package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const BrokerReceiptVersion = 1

var (
	brokerAuditIDPattern = regexp.MustCompile(`^audit-[a-f0-9]{32}$`)
	jsonIntegerPattern   = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)
)

func ValidBrokerReceiptKeyID(value string) bool {
	return approvalKeyIDPattern.MatchString(value)
}

func ValidBrokerReceiptDomain(value string) bool {
	return value == "core" || value == "pve"
}

// BrokerReceipt is a root-broker attestation over one authoritative change or
// fixed command-inspection response. The non-root HTTPS server may relay this
// value, but cannot alter the response or substitute scope/state/result data
// without invalidating it.
//
// Method and Action are both present deliberately. Method binds the exact RPC
// surface while Action gives clients a small, closed vocabulary to compare
// with the user command they are processing.
type BrokerReceipt struct {
	Version      int    `json:"version"`
	KeyID        string `json:"keyId"`
	Domain       string `json:"domain"`
	RequestID    string `json:"requestId"`
	Method       Method `json:"method"`
	Action       string `json:"action"`
	ServerID     string `json:"serverId"`
	MachineID    string `json:"machineId"`
	TargetID     string `json:"targetId"`
	ChangeID     string `json:"changeId"`
	PlanHash     string `json:"planHash"`
	State        string `json:"state"`
	PluginID     string `json:"pluginId,omitempty"`
	PluginDigest string `json:"pluginDigest,omitempty"`
	ProfileKey   string `json:"profileKey,omitempty"`
	AuditID      string `json:"auditId"`
	ResultDigest string `json:"resultDigest"`
	IssuedAt     string `json:"issuedAt"`
	Signature    string `json:"signature"`
}

// BrokerReceiptClaims are supplied independently by the trusted verifier.
// They must come from its pinned server registration and the request it sent,
// never from the receipt itself.
type BrokerReceiptClaims struct {
	KeyID        string
	Domain       string
	RequestID    string
	Method       Method
	ServerID     string
	MachineID    string
	TargetID     string
	ChangeID     string
	PlanHash     string
	PluginID     string
	PluginDigest string
	ProfileKey   string
}

// IsBrokerReceiptMethod reports whether a broker response must be attested.
// Generic inspections and prepare responses are unsigned; command inspection
// is signed because its output crosses a digest-bound business profile.
func IsBrokerReceiptMethod(method Method) bool {
	_, ok := brokerReceiptAction(method)
	return ok
}

// SignBrokerResponse returns a copy of response with a signed receipt. The
// response must already contain the final root audit ID and durable change
// state. Signing before those values exist is rejected.
func SignBrokerResponse(response Response, claims BrokerReceiptClaims, issuedAt time.Time, privateKey ed25519.PrivateKey) (Response, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Response{}, errors.New("broker receipt signing key must be Ed25519")
	}
	if response.Receipt != nil {
		return Response{}, errors.New("broker response already contains a receipt")
	}
	action, ok := brokerReceiptAction(claims.Method)
	if !ok {
		return Response{}, errors.New("broker receipt method is not approval-relevant")
	}
	issuedAt = issuedAt.UTC()
	receipt := BrokerReceipt{
		Version: BrokerReceiptVersion, KeyID: claims.KeyID, Domain: claims.Domain,
		RequestID: claims.RequestID, Method: claims.Method, Action: action,
		ServerID: claims.ServerID, MachineID: claims.MachineID, TargetID: claims.TargetID,
		ChangeID: claims.ChangeID, PlanHash: claims.PlanHash,
		PluginID: claims.PluginID, PluginDigest: claims.PluginDigest, ProfileKey: claims.ProfileKey,
		State: response.State, AuditID: response.AuditID,
		IssuedAt: issuedAt.Format(time.RFC3339Nano),
	}
	commandInspection := claims.Method == MethodWorkloadCommandInspect
	ready := response.Version == Version && response.RequestID == receipt.RequestID && response.AuditID != ""
	if commandInspection {
		ready = ready && response.ChangeID == "" && response.State == "" && claims.ChangeID == "" && claims.PlanHash == ""
	} else {
		ready = ready && response.ChangeID == receipt.ChangeID && response.State != ""
	}
	if !ready {
		return Response{}, errors.New("broker response is not ready for receipt signing")
	}
	resultDigest, err := CanonicalBrokerResultDigest(response)
	if err != nil {
		return Response{}, err
	}
	receipt.ResultDigest = resultDigest
	if err := receipt.validateUnsigned(); err != nil {
		return Response{}, err
	}
	payload, err := receipt.signingPayload()
	if err != nil {
		return Response{}, err
	}
	receipt.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	response.Receipt = &receipt
	return response, nil
}

// VerifyBrokerResponse verifies both the Ed25519 receipt and the complete
// semantic response digest. expected must be constructed from pinned local
// state and the original request; accepting receipt-provided expectations
// would only prove self-consistency.
func VerifyBrokerResponse(response Response, expected BrokerReceiptClaims, now time.Time, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("broker receipt verification key must be Ed25519")
	}
	if response.Receipt == nil {
		return errors.New("broker response has no signed receipt")
	}
	receipt := *response.Receipt
	if err := receipt.ValidateShape(); err != nil {
		return err
	}
	expectedAction, ok := brokerReceiptAction(expected.Method)
	if !ok {
		return errors.New("expected broker receipt method is not approval-relevant")
	}
	if receipt.KeyID != expected.KeyID || receipt.Domain != expected.Domain ||
		receipt.RequestID != expected.RequestID || receipt.Method != expected.Method || receipt.Action != expectedAction ||
		receipt.ServerID != expected.ServerID || receipt.MachineID != expected.MachineID || receipt.TargetID != expected.TargetID ||
		receipt.ChangeID != expected.ChangeID || receipt.PlanHash != expected.PlanHash ||
		receipt.PluginID != expected.PluginID || receipt.PluginDigest != expected.PluginDigest || receipt.ProfileKey != expected.ProfileKey {
		return errors.New("broker receipt does not match the expected request scope")
	}
	identityMatches := response.Version == Version && response.RequestID == receipt.RequestID && response.AuditID == receipt.AuditID
	if receipt.Method == MethodWorkloadCommandInspect {
		identityMatches = identityMatches && response.ChangeID == "" && response.State == ""
	} else {
		identityMatches = identityMatches && response.ChangeID == receipt.ChangeID && response.State == receipt.State
	}
	if !identityMatches {
		return errors.New("broker receipt does not match the relayed response identity")
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, receipt.IssuedAt)
	if issuedAt.After(now.UTC().Add(30 * time.Second)) {
		return errors.New("broker receipt was issued in the future")
	}
	unsignedResponse := response
	unsignedResponse.Receipt = nil
	resultDigest, err := CanonicalBrokerResultDigest(unsignedResponse)
	if err != nil {
		return err
	}
	if resultDigest != receipt.ResultDigest {
		return errors.New("broker receipt result digest does not match the response")
	}
	payload, err := receipt.signingPayload()
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("broker receipt signature is invalid")
	}
	return nil
}

// ValidateShape rejects ambiguous or cross-domain receipts before signature
// verification. All string identities are intentionally bounded by the same
// protocol grammar as the underlying request.
func (r BrokerReceipt) ValidateShape() error {
	if err := r.validateUnsigned(); err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(r.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != r.Signature {
		return errors.New("broker receipt has an invalid signature encoding")
	}
	return nil
}

func (r BrokerReceipt) validateUnsigned() error {
	action, ok := brokerReceiptAction(r.Method)
	if r.Version != BrokerReceiptVersion || !approvalKeyIDPattern.MatchString(r.KeyID) ||
		(r.Domain != "core" && r.Domain != "pve") || !requestIDPattern.MatchString(r.RequestID) ||
		!ok || r.Action != action {
		return errors.New("broker receipt has an invalid version, key, domain, method, or action")
	}
	if !identityPattern.MatchString(r.ServerID) || !identityPattern.MatchString(r.MachineID) ||
		!identityPattern.MatchString(r.TargetID) || !brokerAuditIDPattern.MatchString(r.AuditID) ||
		!digestPattern.MatchString(r.ResultDigest) {
		return errors.New("broker receipt has an invalid scope, plan, state, audit, or result digest")
	}
	if r.Method == MethodWorkloadCommandInspect {
		if r.Domain != "core" || r.ChangeID != "" || r.PlanHash != "" || r.State != "" ||
			!ValidWorkloadPluginID(r.PluginID) || r.PluginID == BaseWorkloadPluginID ||
			!ValidDigest(r.PluginDigest) || !ValidWorkloadProfileKey(r.ProfileKey) {
			return errors.New("workload command receipt has an invalid digest-bound profile scope")
		}
	} else {
		if !changeIDPattern.MatchString(r.ChangeID) || !digestPattern.MatchString(r.PlanHash) ||
			!brokerReceiptState(r.State) || r.PluginID != "" || r.PluginDigest != "" || r.ProfileKey != "" {
			return errors.New("broker receipt has invalid change or unexpected workload profile fields")
		}
		if (r.Domain == "core" && !strings.HasPrefix(r.ChangeID, "change-")) ||
			(r.Domain == "pve" && !strings.HasPrefix(r.ChangeID, "pve-change-")) {
			return errors.New("broker receipt change ID does not match its domain")
		}
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, r.IssuedAt)
	if err != nil || r.IssuedAt != issuedAt.UTC().Format(time.RFC3339Nano) {
		return errors.New("broker receipt issuedAt is not canonical UTC RFC3339")
	}
	return nil
}

func (r BrokerReceipt) signingPayload() ([]byte, error) {
	if err := r.validateUnsigned(); err != nil {
		return nil, err
	}
	var payload bytes.Buffer
	payload.WriteString("agentd-broker-receipt-v1\x00")
	for _, field := range []string{
		strconv.Itoa(r.Version), r.KeyID, r.Domain, r.RequestID, string(r.Method), r.Action,
		r.ServerID, r.MachineID, r.TargetID, r.ChangeID, r.PlanHash, r.State,
		r.AuditID, r.ResultDigest, r.IssuedAt,
	} {
		writeBrokerFrame(&payload, field)
	}
	if r.Method == MethodWorkloadCommandInspect {
		for _, field := range []string{r.PluginID, r.PluginDigest, r.ProfileKey} {
			writeBrokerFrame(&payload, field)
		}
	}
	return payload.Bytes(), nil
}

func brokerReceiptAction(method Method) (string, bool) {
	switch method {
	case MethodChangeStatus:
		return "status", true
	case MethodChangeApprove:
		return "approve", true
	case MethodChangeReject:
		return "reject", true
	case MethodChangeRollback:
		return "rollback", true
	case MethodPVERecoveryClearancePrepare:
		return "pve-recovery-clearance-prepare", true
	case MethodPVERecoveryClearanceConfirm:
		return "pve-recovery-clearance-confirm", true
	case MethodWorkloadCommandInspect:
		return "inspect", true
	default:
		return "", false
	}
}

func brokerReceiptState(state string) bool {
	switch state {
	case "PENDING_APPROVAL", "REJECTED", "PREPARING", "EXECUTING", "VERIFYING", "COMMITTED",
		"ROLLING_BACK", "ROLLED_BACK", "RECOVERY_REQUIRED", "SUPERSEDED":
		return true
	default:
		return false
	}
}

// CanonicalBrokerResultDigest hashes the entire response except its receipt.
// It uses language-neutral length framing and a deterministic semantic JSON
// encoding for Data, instead of signing JSON text whose escaping and object
// order can change when relayed by the HTTPS server.
func CanonicalBrokerResultDigest(response Response) (string, error) {
	if response.Version != Version || !requestIDPattern.MatchString(response.RequestID) {
		return "", errors.New("broker response has an invalid version or request ID")
	}
	if response.Receipt != nil {
		return "", errors.New("canonical broker result must not include its receipt")
	}
	if !utf8.ValidString(response.AuditID) || !utf8.ValidString(response.ChangeID) ||
		!utf8.ValidString(response.State) || !utf8.ValidString(response.Summary) || !utf8.ValidString(response.Error) {
		return "", errors.New("broker response contains invalid UTF-8")
	}
	if len(response.AuditID) > 160 || len(response.ChangeID) > 160 || len(response.State) > 64 ||
		len(response.Summary) > 16*1024 || len(response.Error) > 8192 {
		return "", errors.New("broker response exceeds a canonical field bound")
	}
	data, err := canonicalBrokerData(response.Data)
	if err != nil {
		return "", fmt.Errorf("canonicalize broker response data: %w", err)
	}
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, "agentd-broker-result-v1\x00")
	for _, field := range []string{
		strconv.Itoa(response.Version), response.RequestID, strconv.FormatBool(response.OK),
		response.AuditID, response.ChangeID, response.State, response.Summary, response.Error,
		string(data),
	} {
		writeBrokerHashFrame(hasher, field)
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func canonicalBrokerData(value interface{}) ([]byte, error) {
	if value == nil {
		return []byte("n"), nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxFrameBytes {
		return nil, errors.New("response data exceeds the protocol frame bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var decoded interface{}
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("response data contains trailing JSON")
	}
	var canonical bytes.Buffer
	if err := appendCanonicalBrokerValue(&canonical, decoded, 0); err != nil {
		return nil, err
	}
	if canonical.Len() > MaxFrameBytes {
		return nil, errors.New("canonical response data exceeds the protocol frame bound")
	}
	return canonical.Bytes(), nil
}

func appendCanonicalBrokerValue(target *bytes.Buffer, value interface{}, depth int) error {
	if depth > 64 {
		return errors.New("response data nesting exceeds the canonical bound")
	}
	switch typed := value.(type) {
	case nil:
		target.WriteByte('n')
	case bool:
		if typed {
			target.WriteByte('t')
		} else {
			target.WriteByte('f')
		}
	case string:
		if !utf8.ValidString(typed) {
			return errors.New("response data string is not valid UTF-8")
		}
		target.WriteByte('s')
		writeBrokerFrame(target, typed)
	case json.Number:
		normalized, err := canonicalBrokerInteger(typed.String())
		if err != nil {
			return err
		}
		target.WriteByte('i')
		writeBrokerFrame(target, normalized)
	case []interface{}:
		target.WriteByte('a')
		writeBrokerFrame(target, strconv.Itoa(len(typed)))
		for _, item := range typed {
			if err := appendCanonicalBrokerValue(target, item, depth+1); err != nil {
				return err
			}
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if !utf8.ValidString(key) {
				return errors.New("response data object key is not valid UTF-8")
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		target.WriteByte('o')
		writeBrokerFrame(target, strconv.Itoa(len(keys)))
		for _, key := range keys {
			writeBrokerFrame(target, key)
			if err := appendCanonicalBrokerValue(target, typed[key], depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported canonical response data type %T", value)
	}
	return nil
}

func canonicalBrokerInteger(value string) (string, error) {
	if !jsonIntegerPattern.MatchString(value) {
		return "", errors.New("broker receipt data only permits canonical integer numbers")
	}
	integer, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return "", errors.New("broker receipt data integer is outside the supported range")
	}
	// Limit signed data to JavaScript's exact integer range so a TypeScript
	// verifier can reproduce the digest without lossy number conversion.
	const maxSafeInteger = int64(1<<53 - 1)
	if integer > maxSafeInteger || integer < -maxSafeInteger {
		return "", errors.New("broker receipt data integer is outside the cross-language safe range")
	}
	return strconv.FormatInt(integer, 10), nil
}

func writeBrokerFrame(target *bytes.Buffer, value string) {
	target.WriteString(strconv.Itoa(len([]byte(value))))
	target.WriteByte(':')
	target.WriteString(value)
}

func writeBrokerHashFrame(target io.Writer, value string) {
	_, _ = io.WriteString(target, strconv.Itoa(len([]byte(value))))
	_, _ = io.WriteString(target, ":")
	_, _ = io.WriteString(target, value)
}
