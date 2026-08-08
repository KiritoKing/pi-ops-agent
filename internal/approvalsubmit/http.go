package approvalsubmit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type Remote interface {
	Status(context.Context, Request, string, time.Time) (HelperResponse, error)
	Action(context.Context, Request, string, time.Time, protocol.ApprovalGrant) (HelperResponse, error)
}

// PVERecoveryClearanceRemote is intentionally not part of the general Remote
// surface. The submitter type-asserts it only for a pending PVE recovery child,
// keeping clearance outside ordinary client/model/provider APIs.
type PVERecoveryClearanceRemote interface {
	PreparePVERecoveryClearance(context.Context, Request, string, time.Time) (HelperResponse, error)
	ConfirmPVERecoveryClearance(context.Context, Request, string, time.Time, protocol.PVERecoveryClearanceApproval) (HelperResponse, error)
	ActionWithPVERecoveryClearance(context.Context, Request, string, time.Time, protocol.ApprovalGrant, string) (HelperResponse, error)
}

type HTTPSRemote struct {
	baseURL *url.URL
	client  *http.Client
}

func NewHTTPSRemote(server LoadedServer) (Remote, error) {
	if err := validateRegistration(server.Registration); err != nil {
		return nil, err
	}
	if server.TLSConfig == nil || server.TLSConfig.MinVersion != tls.VersionTLS13 || server.TLSConfig.MaxVersion != tls.VersionTLS13 {
		return nil, errors.New("approval HTTPS client requires an exact TLS 1.3 configuration")
	}
	baseURL, err := url.Parse(server.Registration.BaseURL)
	if err != nil {
		return nil, err
	}
	expectedServerName := server.Registration.ServerName
	if expectedServerName == "" {
		expectedServerName = baseURL.Hostname()
	}
	if server.TLSConfig.InsecureSkipVerify || server.TLSConfig.RootCAs == nil || server.TLSConfig.ServerName != expectedServerName ||
		len(server.TLSConfig.Certificates) != 1 || len(server.TLSConfig.Certificates[0].Certificate) != 1 {
		return nil, errors.New("approval HTTPS client has an incomplete or mismatched pinned TLS identity")
	}
	leaf := server.TLSConfig.Certificates[0].Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(server.TLSConfig.Certificates[0].Certificate[0])
		if err != nil {
			return nil, errors.New("approval HTTPS client has an invalid leaf certificate")
		}
	}
	if !hasOnlyApproverRole(leaf) {
		return nil, errors.New("approval HTTPS client certificate is not the approver identity")
	}
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
		MaxIdleConns:      2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second, DisableCompression: true,
		TLSClientConfig: server.TLSConfig.Clone(),
	}
	return &HTTPSRemote{
		baseURL: baseURL,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("approval endpoint redirects are forbidden")
			},
		},
	}, nil
}

func (r *HTTPSRemote) Status(ctx context.Context, reference Request, requestID string, deadline time.Time) (HelperResponse, error) {
	query := url.Values{}
	query.Set("requestId", requestID)
	query.Set("deadline", deadline.UTC().Format(time.RFC3339Nano))
	query.Set("machineId", reference.MachineID)
	query.Set("targetId", reference.TargetID)
	path := "/v1/changes/" + url.PathEscape(reference.ChangeID)
	return r.do(ctx, http.MethodGet, path, query, nil, requestID, time.Until(deadline)+5*time.Second)
}

func (r *HTTPSRemote) Action(ctx context.Context, reference Request, requestID string, deadline time.Time, grant protocol.ApprovalGrant) (HelperResponse, error) {
	return r.action(ctx, reference, requestID, deadline, grant, "")
}

func (r *HTTPSRemote) ActionWithPVERecoveryClearance(ctx context.Context, reference Request, requestID string, deadline time.Time, grant protocol.ApprovalGrant, token string) (HelperResponse, error) {
	if !protocol.ValidPVERecoveryClearanceToken(token) || reference.Action != ActionApprove || !strings.HasPrefix(reference.ChangeID, "pve-change-") {
		return HelperResponse{}, errors.New("invalid PVE recovery clearance action binding")
	}
	return r.action(ctx, reference, requestID, deadline, grant, token)
}

func (r *HTTPSRemote) action(ctx context.Context, reference Request, requestID string, deadline time.Time, grant protocol.ApprovalGrant, token string) (HelperResponse, error) {
	body := struct {
		Version        int                    `json:"version"`
		RequestID      string                 `json:"requestId"`
		Deadline       string                 `json:"deadline"`
		MachineID      string                 `json:"machineId"`
		TargetID       string                 `json:"targetId"`
		Approval       protocol.ApprovalGrant `json:"approval"`
		ClearanceToken string                 `json:"clearanceToken,omitempty"`
	}{
		Version: protocol.Version, RequestID: requestID, Deadline: deadline.UTC().Format(time.RFC3339Nano),
		MachineID: reference.MachineID, TargetID: reference.TargetID, Approval: grant, ClearanceToken: token,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return HelperResponse{}, err
	}
	path := "/v1/changes/" + url.PathEscape(reference.ChangeID) + "/" + string(reference.Action)
	return r.do(ctx, http.MethodPost, path, nil, payload, requestID, time.Until(deadline)+5*time.Second)
}

func (r *HTTPSRemote) PreparePVERecoveryClearance(ctx context.Context, reference Request, requestID string, deadline time.Time) (HelperResponse, error) {
	body := struct {
		Version   int    `json:"version"`
		RequestID string `json:"requestId"`
		Deadline  string `json:"deadline"`
		MachineID string `json:"machineId"`
		TargetID  string `json:"targetId"`
	}{protocol.Version, requestID, deadline.UTC().Format(time.RFC3339Nano), reference.MachineID, reference.TargetID}
	payload, err := json.Marshal(body)
	if err != nil {
		return HelperResponse{}, err
	}
	path := "/v1/changes/" + url.PathEscape(reference.ChangeID) + "/pve-recovery-clearance-prepare"
	return r.do(ctx, http.MethodPost, path, nil, payload, requestID, time.Until(deadline)+5*time.Second)
}

func (r *HTTPSRemote) ConfirmPVERecoveryClearance(ctx context.Context, reference Request, requestID string, deadline time.Time, approval protocol.PVERecoveryClearanceApproval) (HelperResponse, error) {
	body := struct {
		Version           int                                   `json:"version"`
		RequestID         string                                `json:"requestId"`
		Deadline          string                                `json:"deadline"`
		MachineID         string                                `json:"machineId"`
		TargetID          string                                `json:"targetId"`
		ClearanceApproval protocol.PVERecoveryClearanceApproval `json:"clearanceApproval"`
	}{protocol.Version, requestID, deadline.UTC().Format(time.RFC3339Nano), reference.MachineID, reference.TargetID, approval}
	payload, err := json.Marshal(body)
	if err != nil {
		return HelperResponse{}, err
	}
	path := "/v1/changes/" + url.PathEscape(reference.ChangeID) + "/pve-recovery-clearance-confirm"
	return r.do(ctx, http.MethodPost, path, nil, payload, requestID, time.Until(deadline)+5*time.Second)
}

func (r *HTTPSRemote) do(ctx context.Context, method, path string, query url.Values, payload []byte, requestID string, timeout time.Duration) (HelperResponse, error) {
	if r == nil || r.baseURL == nil || r.client == nil || timeout <= 0 || timeout > 10*time.Minute {
		return HelperResponse{}, errors.New("approval HTTPS request has an invalid client or deadline")
	}
	endpoint := *r.baseURL
	endpoint.Path = path
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if payload != nil {
		if len(payload) > protocol.MaxFrameBytes {
			return HelperResponse{}, errors.New("approval request exceeds the protocol bound")
		}
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(requestCtx, method, endpoint.String(), body)
	if err != nil {
		return HelperResponse{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := r.client.Do(request)
	if err != nil {
		return HelperResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return HelperResponse{}, fmt.Errorf("approval endpoint returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return HelperResponse{}, errors.New("approval endpoint response is not application/json")
	}
	bounded, err := io.ReadAll(io.LimitReader(response.Body, protocol.MaxFrameBytes+1))
	if err != nil {
		return HelperResponse{}, err
	}
	if len(bounded) == 0 || len(bounded) > protocol.MaxFrameBytes {
		return HelperResponse{}, errors.New("approval endpoint response is empty or exceeds the protocol bound")
	}
	var result HelperResponse
	if err := strictDecode(bounded, &result); err != nil {
		return HelperResponse{}, fmt.Errorf("decode approval endpoint response: %w", err)
	}
	if err := validateHelperResponse(result, requestID); err != nil {
		return HelperResponse{}, err
	}
	return result, nil
}
