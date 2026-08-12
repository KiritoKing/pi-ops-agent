package approvalsubmit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const (
	ReviewerSocketPath = "/run/ops-agent/reviewer/reviewer.sock"
	reviewerTimeout    = 30 * time.Second
)

type ReviewRecommendation string

const (
	ReviewManual        ReviewRecommendation = "manual-review"
	ReviewSplitRequired ReviewRecommendation = "split-required"
	ReviewReject        ReviewRecommendation = "reject"
)

type ApprovalReviewRequest struct {
	Version    int                   `json:"version"`
	ReviewID   string                `json:"reviewId"`
	UserIntent string                `json:"userIntent"`
	Plan       protocol.ApprovalPlan `json:"plan"`
}

type ApprovalReviewFinding struct {
	Code        string `json:"code"`
	Risk        string `json:"risk"`
	StepID      string `json:"stepId"`
	Summary     string `json:"summary"`
	SourceStart *int   `json:"sourceStart,omitempty"`
	SourceEnd   *int   `json:"sourceEnd,omitempty"`
}

type ApprovalReview struct {
	Version          int                     `json:"version"`
	ReviewID         string                  `json:"reviewId"`
	PlanHash         string                  `json:"planHash"`
	UserIntentDigest string                  `json:"userIntentDigest"`
	MinimumRisk      string                  `json:"minimumRisk"`
	Risk             string                  `json:"risk"`
	Recommendation   ReviewRecommendation    `json:"recommendation"`
	CanAuthorize     bool                    `json:"canAuthorize"`
	Findings         []ApprovalReviewFinding `json:"findings"`
	Explanation      string                  `json:"explanation"`
	ReviewDigest     string                  `json:"reviewDigest"`
}

type ApprovalReviewer interface {
	Review(context.Context, ApprovalReviewRequest) (ApprovalReview, error)
}

type UnixApprovalReviewer struct {
	SocketPath  string
	Timeout     time.Duration
	DialContext func(context.Context, string, string) (net.Conn, error)
}

type reviewerResponseWire struct {
	OK     *bool           `json:"ok"`
	Review json.RawMessage `json:"review,omitempty"`
	Error  *string         `json:"error,omitempty"`
}

type approvalReviewWire struct {
	Version          int             `json:"version"`
	ReviewID         string          `json:"reviewId"`
	PlanHash         string          `json:"planHash"`
	UserIntentDigest string          `json:"userIntentDigest"`
	MinimumRisk      string          `json:"minimumRisk"`
	Risk             string          `json:"risk"`
	Recommendation   string          `json:"recommendation"`
	CanAuthorize     *bool           `json:"canAuthorize"`
	Findings         json.RawMessage `json:"findings"`
	Explanation      string          `json:"explanation"`
	ReviewDigest     string          `json:"reviewDigest"`
}

type approvalReviewFindingWire struct {
	Code        string `json:"code"`
	Risk        string `json:"risk"`
	StepID      string `json:"stepId"`
	Summary     string `json:"summary"`
	SourceStart *int   `json:"sourceStart,omitempty"`
	SourceEnd   *int   `json:"sourceEnd,omitempty"`
}

var reviewFindingCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)

func (reviewer UnixApprovalReviewer) Review(ctx context.Context, request ApprovalReviewRequest) (ApprovalReview, error) {
	if err := validateReviewRequest(request); err != nil {
		return ApprovalReview{}, err
	}
	socketPath := reviewer.SocketPath
	if socketPath == "" {
		socketPath = ReviewerSocketPath
	}
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || strings.ContainsRune(socketPath, '\x00') {
		return ApprovalReview{}, errors.New("approval reviewer socket path is invalid")
	}
	timeout := reviewer.Timeout
	if timeout <= 0 {
		timeout = reviewerTimeout
	}
	if timeout > reviewerTimeout {
		return ApprovalReview{}, errors.New("approval reviewer timeout exceeds the fixed maximum")
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) == 0 || len(payload) > protocol.MaxFrameBytes {
		return ApprovalReview{}, errors.New("approval reviewer request exceeds its protocol bound")
	}
	dialContext := reviewer.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{}).DialContext
	}
	connection, err := dialContext(ctx, "unix", socketPath)
	if err != nil {
		return ApprovalReview{}, err
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return ApprovalReview{}, err
	}
	if err := protocol.WriteFrame(connection, payload); err != nil {
		return ApprovalReview{}, fmt.Errorf("write approval reviewer request: %w", err)
	}
	if unix, ok := connection.(*net.UnixConn); ok {
		if err := unix.CloseWrite(); err != nil {
			return ApprovalReview{}, fmt.Errorf("finish approval reviewer request: %w", err)
		}
	}
	responsePayload, err := protocol.ReadFrame(connection)
	if err != nil {
		return ApprovalReview{}, fmt.Errorf("read approval reviewer response: %w", err)
	}
	var trailing [1]byte
	if count, trailingErr := connection.Read(trailing[:]); count != 0 || !errors.Is(trailingErr, io.EOF) {
		return ApprovalReview{}, errors.New("approval reviewer returned multiple frames or did not close its response")
	}
	return parseReviewerResponse(responsePayload, request)
}

func parseReviewerResponse(payload []byte, request ApprovalReviewRequest) (ApprovalReview, error) {
	if !utf8.Valid(payload) {
		return ApprovalReview{}, errors.New("approval reviewer response is not valid UTF-8")
	}
	var response reviewerResponseWire
	if err := strictDecode(payload, &response); err != nil {
		return ApprovalReview{}, fmt.Errorf("decode approval reviewer response: %w", err)
	}
	if response.OK == nil {
		return ApprovalReview{}, errors.New("approval reviewer response is missing ok")
	}
	if !*response.OK {
		if response.Error == nil || len(response.Review) != 0 || len(*response.Error) < 1 || len(*response.Error) > 8192 || !utf8.ValidString(*response.Error) {
			return ApprovalReview{}, errors.New("approval reviewer returned an invalid failure response")
		}
		return ApprovalReview{}, fmt.Errorf("approval reviewer rejected its request: %s", *response.Error)
	}
	if response.Error != nil || len(response.Review) == 0 {
		return ApprovalReview{}, errors.New("approval reviewer returned an invalid success response")
	}
	review, err := parseApprovalReview(response.Review, request.Plan)
	if err != nil {
		return ApprovalReview{}, err
	}
	if err := validateApprovalReview(request, review); err != nil {
		return ApprovalReview{}, err
	}
	return review, nil
}

func parseApprovalReview(payload []byte, plan protocol.ApprovalPlan) (ApprovalReview, error) {
	var wire approvalReviewWire
	if err := strictDecode(payload, &wire); err != nil {
		return ApprovalReview{}, fmt.Errorf("decode approval review: %w", err)
	}
	if wire.CanAuthorize == nil || len(wire.Findings) == 0 {
		return ApprovalReview{}, errors.New("approval review is missing an authority or findings field")
	}
	var findingWires []approvalReviewFindingWire
	if err := strictDecode(wire.Findings, &findingWires); err != nil || findingWires == nil {
		return ApprovalReview{}, errors.New("approval review findings are not a strict array")
	}
	if len(findingWires) > 128 {
		return ApprovalReview{}, errors.New("approval review has too many findings")
	}
	stepIDs := make(map[string]struct{}, len(plan.Steps))
	for _, step := range plan.Steps {
		stepIDs[step.ID] = struct{}{}
	}
	findings := make([]ApprovalReviewFinding, 0, len(findingWires))
	for _, finding := range findingWires {
		if !reviewFindingCodePattern.MatchString(finding.Code) || !validRisk(finding.Risk) ||
			len(finding.StepID) < 1 || len(finding.StepID) > 64 || len(finding.Summary) < 1 ||
			len(finding.Summary) > 1024 || !utf8.ValidString(finding.Summary) {
			return ApprovalReview{}, errors.New("approval review contains an invalid finding")
		}
		if _, ok := stepIDs[finding.StepID]; !ok {
			return ApprovalReview{}, errors.New("approval review finding references an unknown plan step")
		}
		if (finding.SourceStart == nil) != (finding.SourceEnd == nil) ||
			(finding.SourceStart != nil && (*finding.SourceStart < 0 || *finding.SourceEnd < *finding.SourceStart || *finding.SourceEnd > 128*1024)) {
			return ApprovalReview{}, errors.New("approval review finding has an invalid source span")
		}
		findings = append(findings, ApprovalReviewFinding{
			Code: finding.Code, Risk: finding.Risk, StepID: finding.StepID, Summary: finding.Summary,
			SourceStart: finding.SourceStart, SourceEnd: finding.SourceEnd,
		})
	}
	review := ApprovalReview{
		Version: wire.Version, ReviewID: wire.ReviewID, PlanHash: wire.PlanHash,
		UserIntentDigest: wire.UserIntentDigest, MinimumRisk: wire.MinimumRisk, Risk: wire.Risk,
		Recommendation: ReviewRecommendation(wire.Recommendation), CanAuthorize: *wire.CanAuthorize,
		Findings: findings, Explanation: wire.Explanation, ReviewDigest: wire.ReviewDigest,
	}
	if err := validateReviewShape(review); err != nil {
		return ApprovalReview{}, err
	}
	return review, nil
}

func validateApprovalReview(request ApprovalReviewRequest, review ApprovalReview) error {
	if err := validateReviewRequest(request); err != nil {
		return err
	}
	if err := validateReviewShape(review); err != nil {
		return err
	}
	if review.ReviewID != request.ReviewID || review.PlanHash != request.Plan.PlanHash {
		return errors.New("approval review does not match the exact request and canonical plan")
	}
	intentDigest, err := canonicalDigest(map[string]any{"userIntent": request.UserIntent})
	if err != nil || review.UserIntentDigest != intentDigest {
		return errors.New("approval review does not match the bounded user intent")
	}
	stepIDs := make(map[string]struct{}, len(request.Plan.Steps))
	for _, step := range request.Plan.Steps {
		stepIDs[step.ID] = struct{}{}
	}
	for _, finding := range review.Findings {
		if _, ok := stepIDs[finding.StepID]; !ok {
			return errors.New("approval review finding does not match the canonical plan")
		}
	}
	return nil
}

func validateReviewRequest(request ApprovalReviewRequest) error {
	if request.Version != protocol.Version || !stableIDPattern.MatchString(request.ReviewID) ||
		len(request.UserIntent) < 1 || len(request.UserIntent) > MaxUserIntentBytes ||
		!utf8.ValidString(request.UserIntent) || strings.TrimSpace(request.UserIntent) == "" {
		return errors.New("approval review request has an invalid version, identity, or user intent")
	}
	canonical, err := protocol.CanonicalApprovalPlanHash(request.Plan)
	if err != nil || canonical != request.Plan.PlanHash {
		return errors.New("approval review request plan is not canonical")
	}
	return nil
}

func validateReviewShape(review ApprovalReview) error {
	if review.Version != protocol.Version || !stableIDPattern.MatchString(review.ReviewID) ||
		!digestPattern.MatchString(review.PlanHash) || !digestPattern.MatchString(review.UserIntentDigest) ||
		!validRisk(review.MinimumRisk) || !validRisk(review.Risk) || review.CanAuthorize || review.Findings == nil ||
		len(review.Findings) > 128 ||
		len(review.Explanation) < 1 || len(review.Explanation) > 16*1024 || !utf8.ValidString(review.Explanation) ||
		!digestPattern.MatchString(review.ReviewDigest) {
		return errors.New("approval review contains an invalid identity, risk, authority, explanation, or digest")
	}
	if riskRank(review.Risk) < riskRank(review.MinimumRisk) {
		return errors.New("approval review risk is below its deterministic minimum")
	}
	if review.Recommendation != ReviewManual && review.Recommendation != ReviewSplitRequired && review.Recommendation != ReviewReject {
		return errors.New("approval review recommendation is unsupported")
	}
	for _, finding := range review.Findings {
		if !reviewFindingCodePattern.MatchString(finding.Code) || !validRisk(finding.Risk) ||
			len(finding.StepID) < 1 || len(finding.StepID) > 64 || len(finding.Summary) < 1 ||
			len(finding.Summary) > 1024 || !utf8.ValidString(finding.Summary) ||
			(finding.SourceStart == nil) != (finding.SourceEnd == nil) ||
			(finding.SourceStart != nil && (*finding.SourceStart < 0 || *finding.SourceEnd < *finding.SourceStart || *finding.SourceEnd > 128*1024)) {
			return errors.New("approval review contains an invalid finding")
		}
	}
	digest, err := approvalReviewDigest(review)
	if err != nil || digest != review.ReviewDigest {
		return errors.New("approval review digest does not match its canonical content")
	}
	return nil
}

func validRisk(value string) bool {
	return value == "low" || value == "medium" || value == "high" || value == "critical"
}

func riskRank(value string) int {
	switch value {
	case "low":
		return 0
	case "medium":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	default:
		return -1
	}
}

func approvalReviewDigest(review ApprovalReview) (string, error) {
	findings := make([]any, 0, len(review.Findings))
	for _, finding := range review.Findings {
		value := map[string]any{
			"code": finding.Code, "risk": finding.Risk, "stepId": finding.StepID, "summary": finding.Summary,
		}
		if finding.SourceStart != nil {
			value["sourceStart"] = *finding.SourceStart
			value["sourceEnd"] = *finding.SourceEnd
		}
		findings = append(findings, value)
	}
	return canonicalDigest(map[string]any{
		"version": review.Version, "reviewId": review.ReviewID, "planHash": review.PlanHash,
		"userIntentDigest": review.UserIntentDigest, "minimumRisk": review.MinimumRisk,
		"risk": review.Risk, "recommendation": string(review.Recommendation),
		"canAuthorize": review.CanAuthorize, "findings": findings, "explanation": review.Explanation,
	})
}

func canonicalDigest(value any) (string, error) {
	var builder strings.Builder
	if err := writeCanonicalJSON(&builder, value); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(builder.String()))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func writeCanonicalJSON(builder *strings.Builder, value any) error {
	switch typed := value.(type) {
	case nil:
		builder.WriteString("null")
	case bool:
		builder.WriteString(strconv.FormatBool(typed))
	case int:
		builder.WriteString(strconv.Itoa(typed))
	case string:
		if !utf8.ValidString(typed) {
			return errors.New("canonical JSON string is not valid UTF-8")
		}
		writeJSONString(builder, typed)
	case []any:
		builder.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				builder.WriteByte(',')
			}
			if err := writeCanonicalJSON(builder, item); err != nil {
				return err
			}
		}
		builder.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		builder.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				builder.WriteByte(',')
			}
			writeJSONString(builder, key)
			builder.WriteByte(':')
			if err := writeCanonicalJSON(builder, typed[key]); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON contains unsupported type %T", value)
	}
	return nil
}

func writeJSONString(builder *strings.Builder, value string) {
	builder.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			builder.WriteByte('\\')
			builder.WriteRune(character)
		case '\b':
			builder.WriteString(`\b`)
		case '\f':
			builder.WriteString(`\f`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		default:
			if character < 0x20 {
				fmt.Fprintf(builder, `\u%04x`, character)
			} else {
				builder.WriteRune(character)
			}
		}
	}
	builder.WriteByte('"')
}
