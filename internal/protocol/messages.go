package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const Version = 1

var (
	requestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{8,160}$`)
	changeIDPattern  = regexp.MustCompile(`^[a-zA-Z0-9._-]{8,160}$`)
	packagePattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._-]{0,127}$`)
	versionPattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+.:~_-]{0,127}$`)
	unitPattern      = regexp.MustCompile(`^[a-zA-Z0-9@_.:-]{1,192}\.service$`)
	modePattern      = regexp.MustCompile(`^0?[0-7]{3,4}$`)
)

type Method string

const (
	MethodChangePrepare  Method = "change.prepare"
	MethodChangeStatus   Method = "change.status"
	MethodChangeApprove  Method = "change.approve"
	MethodChangeReject   Method = "change.reject"
	MethodChangeRollback Method = "change.rollback"
	MethodHostSnapshot   Method = "host.snapshot"
	MethodSystemdUnit    Method = "systemd.unit"
	MethodJournalTail    Method = "journal.tail"
	MethodHeartbeat      Method = "heartbeat"
)

type Request struct {
	Version   int
	RequestID string
	Deadline  time.Time
	Method    Method
	ChangeID  string
	Unit      string
	Lines     int
	Operation Operation
	Raw       json.RawMessage
}

type Response struct {
	Version   int         `json:"version"`
	RequestID string      `json:"requestId"`
	OK        bool        `json:"ok"`
	AuditID   string      `json:"auditId,omitempty"`
	ChangeID  string      `json:"changeId,omitempty"`
	State     string      `json:"state,omitempty"`
	Summary   string      `json:"summary,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
}

type Operation interface {
	Kind() string
	Summary() string
	Validate() error
}

type PackageInstall struct {
	OperationKind string `json:"kind"`
	Package       string `json:"package"`
	Version       string `json:"version,omitempty"`
}

func (o PackageInstall) Kind() string { return "package.install" }
func (o PackageInstall) Summary() string {
	if o.Version == "" {
		return "install package " + o.Package
	}
	return "install package " + o.Package + " version " + o.Version
}
func (o PackageInstall) Validate() error {
	if o.OperationKind != o.Kind() || !packagePattern.MatchString(o.Package) {
		return errors.New("invalid package.install operation")
	}
	if o.Version != "" && !versionPattern.MatchString(o.Version) {
		return errors.New("invalid package version")
	}
	return nil
}

type ServiceAction struct {
	OperationKind string `json:"kind"`
	Unit          string `json:"unit"`
	Action        string `json:"action"`
}

func (o ServiceAction) Kind() string    { return "service.action" }
func (o ServiceAction) Summary() string { return o.Action + " service " + o.Unit }
func (o ServiceAction) Validate() error {
	if o.OperationKind != o.Kind() || !unitPattern.MatchString(o.Unit) {
		return errors.New("invalid service.action operation")
	}
	switch o.Action {
	case "restart", "reload", "start", "stop":
		return nil
	default:
		return errors.New("invalid service action")
	}
}

type FileWrite struct {
	OperationKind string `json:"kind"`
	Path          string `json:"path"`
	Content       string `json:"content"`
	Mode          string `json:"mode,omitempty"`
}

func (o FileWrite) Kind() string { return "file.write" }
func (o FileWrite) Summary() string {
	return fmt.Sprintf("write %d bytes to %s", len(o.Content), o.Path)
}
func (o FileWrite) Validate() error {
	if o.OperationKind != o.Kind() || !filepath.IsAbs(o.Path) || filepath.Clean(o.Path) != o.Path {
		return errors.New("file.write path must be a clean absolute path")
	}
	if len(o.Path) > 4096 || strings.ContainsAny(o.Path, "\x00\n\r") || len(o.Content) > 128*1024 {
		return errors.New("file.write exceeds a protocol limit")
	}
	if o.Mode != "" && !modePattern.MatchString(o.Mode) {
		return errors.New("invalid file mode")
	}
	return nil
}

type BreakglassScript struct {
	OperationKind string   `json:"kind"`
	Script        string   `json:"script"`
	BackupPaths   []string `json:"backupPaths"`
	VerifyScript  string   `json:"verifyScript,omitempty"`
	Network       bool     `json:"network"`
}

func (o BreakglassScript) Kind() string { return "breakglass.script" }
func (o BreakglassScript) Summary() string {
	return fmt.Sprintf("run digest-bound break-glass script (%d bytes, %d backup paths)", len(o.Script), len(o.BackupPaths))
}
func (o BreakglassScript) Validate() error {
	if o.OperationKind != o.Kind() || len(o.Script) == 0 || len(o.Script) > 128*1024 {
		return errors.New("invalid breakglass.script operation")
	}
	if len(o.VerifyScript) > 32*1024 || len(o.BackupPaths) == 0 || len(o.BackupPaths) > 32 {
		return errors.New("break-glass requires a bounded backup and verification plan")
	}
	for _, path := range o.BackupPaths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || path == "/" || strings.ContainsAny(path, "\x00\n\r") {
			return errors.New("break-glass backup paths must be clean absolute paths below root")
		}
	}
	return nil
}

func ParseRequest(payload []byte, now time.Time) (Request, error) {
	var header struct {
		Version   int    `json:"version"`
		RequestID string `json:"requestId"`
		Deadline  string `json:"deadline"`
		Method    Method `json:"method"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return Request{}, fmt.Errorf("decode request header: %w", err)
	}
	if header.Version != Version || !requestIDPattern.MatchString(header.RequestID) {
		return Request{}, errors.New("unsupported version or invalid requestId")
	}
	deadline, err := time.Parse(time.RFC3339Nano, header.Deadline)
	if err != nil || !deadline.After(now) || deadline.After(now.Add(10*time.Minute)) {
		return Request{}, errors.New("deadline must be within the next ten minutes")
	}
	request := Request{Version: Version, RequestID: header.RequestID, Deadline: deadline, Method: header.Method, Raw: append(json.RawMessage(nil), payload...)}

	switch header.Method {
	case MethodChangePrepare:
		var wire struct {
			Version   int             `json:"version"`
			RequestID string          `json:"requestId"`
			Deadline  string          `json:"deadline"`
			Method    Method          `json:"method"`
			Operation json.RawMessage `json:"operation"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		request.Operation, err = parseOperation(wire.Operation)
		if err != nil {
			return Request{}, err
		}
	case MethodChangeStatus, MethodChangeApprove, MethodChangeReject, MethodChangeRollback:
		var wire struct {
			Version   int    `json:"version"`
			RequestID string `json:"requestId"`
			Deadline  string `json:"deadline"`
			Method    Method `json:"method"`
			ChangeID  string `json:"changeId"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		if !changeIDPattern.MatchString(wire.ChangeID) {
			return Request{}, errors.New("invalid changeId")
		}
		request.ChangeID = wire.ChangeID
	case MethodSystemdUnit, MethodJournalTail:
		var wire struct {
			Version   int    `json:"version"`
			RequestID string `json:"requestId"`
			Deadline  string `json:"deadline"`
			Method    Method `json:"method"`
			Unit      string `json:"unit"`
			Lines     int    `json:"lines,omitempty"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		if !unitPattern.MatchString(wire.Unit) {
			return Request{}, errors.New("invalid systemd unit")
		}
		if header.Method == MethodJournalTail {
			if wire.Lines == 0 {
				wire.Lines = 100
			}
			if wire.Lines < 1 || wire.Lines > 200 {
				return Request{}, errors.New("journal lines must be between 1 and 200")
			}
		} else if wire.Lines != 0 {
			return Request{}, errors.New("lines is not valid for systemd.unit")
		}
		request.Unit, request.Lines = wire.Unit, wire.Lines
	case MethodHostSnapshot, MethodHeartbeat:
		var wire struct {
			Version   int    `json:"version"`
			RequestID string `json:"requestId"`
			Deadline  string `json:"deadline"`
			Method    Method `json:"method"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
	default:
		return Request{}, fmt.Errorf("unsupported method %q", header.Method)
	}
	return request, nil
}

func ParseStoredOperation(payload []byte) (Operation, error) {
	return parseOperation(payload)
}

func MarshalOperation(operation Operation) ([]byte, error) {
	if operation == nil {
		return nil, errors.New("operation is required")
	}
	if err := operation.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(operation)
}

func parseOperation(payload []byte) (Operation, error) {
	var header struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return nil, fmt.Errorf("decode operation header: %w", err)
	}
	var operation Operation
	switch header.Kind {
	case "package.install":
		operation = &PackageInstall{}
	case "service.action":
		operation = &ServiceAction{}
	case "file.write":
		operation = &FileWrite{}
	case "breakglass.script":
		operation = &BreakglassScript{}
	default:
		return nil, fmt.Errorf("unsupported operation kind %q", header.Kind)
	}
	if err := strictDecode(payload, operation); err != nil {
		return nil, err
	}
	if err := operation.Validate(); err != nil {
		return nil, err
	}
	return operation, nil
}

func strictDecode(payload []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("strict JSON decode: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("strict JSON decode: trailing value")
		}
		return fmt.Errorf("strict JSON decode: %w", err)
	}
	return nil
}
