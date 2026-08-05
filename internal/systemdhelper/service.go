package systemdhelper

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/audit"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type Runner interface {
	Run(context.Context, string, ...string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	text := string(output)
	if len(text) > 64*1024 {
		text = text[:64*1024] + "\n[TRUNCATED]"
	}
	if err != nil {
		return text, fmt.Errorf("%s failed: %w", name, err)
	}
	return text, nil
}

type Inspector interface {
	HostSnapshot(context.Context) (interface{}, error)
	SystemdUnit(context.Context, string) (interface{}, error)
	JournalTail(context.Context, string, int) (interface{}, error)
}

type OSInspector struct{ Runner Runner }

func (i OSInspector) HostSnapshot(ctx context.Context) (interface{}, error) {
	results := make(map[string]string)
	commands := []struct {
		name string
		args []string
	}{{"uptime", nil}, {"df", []string{"-P"}}, {"free", []string{"-b"}}}
	for _, item := range commands {
		path, err := exec.LookPath(item.name)
		if err != nil {
			results[item.name] = "unavailable"
			continue
		}
		output, err := i.runner().Run(ctx, path, item.args...)
		if err != nil {
			results[item.name] = "error: " + err.Error()
		} else {
			results[item.name] = output
		}
	}
	return results, nil
}
func (i OSInspector) SystemdUnit(ctx context.Context, unit string) (interface{}, error) {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return nil, err
	}
	output, err := i.runner().Run(ctx, path, "show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,UnitFileState", "--", unit)
	if err != nil {
		return nil, err
	}
	return map[string]string{"unit": unit, "properties": output}, nil
}
func (i OSInspector) JournalTail(ctx context.Context, unit string, lines int) (interface{}, error) {
	path, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, err
	}
	output, err := i.runner().Run(ctx, path, "--no-pager", "--output=short-iso", "--unit", unit, "--lines", strconv.Itoa(lines))
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"unit": unit, "lines": lines, "entries": output}, nil
}
func (i OSInspector) runner() Runner {
	if i.Runner == nil {
		return ExecRunner{}
	}
	return i.Runner
}

type SystemdRestarter struct{ Runner Runner }

func (r SystemdRestarter) Restart(ctx context.Context, unit string) error {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	runner := r.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	_, err = runner.Run(ctx, path, "restart", "--", unit)
	return err
}

type Service struct {
	AgentUID  uint32
	Audit     *audit.Log
	Inspector Inspector
	Monitor   *Monitor
	Now       func() time.Time
}

func (s *Service) Handle(ctx context.Context, peer peercred.Credential, request protocol.Request) protocol.Response {
	response := protocol.Response{Version: protocol.Version, RequestID: request.RequestID}
	if peer.UID != s.AgentUID {
		response.Error = "peer is not the configured agent UID"
		if s.Audit != nil {
			response.AuditID, _ = s.Audit.Append(map[string]interface{}{
				"type": "unauthorized_helper_request", "requestId": request.RequestID, "method": request.Method,
				"peer": map[string]interface{}{"pid": peer.PID, "uid": peer.UID, "gid": peer.GID},
			})
		}
		return response
	}
	if s.Audit == nil || s.Inspector == nil || s.Monitor == nil {
		response.Error = "systemd-helper is not initialized"
		return response
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if !request.Deadline.After(now()) {
		response.Error = "request deadline expired"
		return response
	}
	var data interface{}
	var err error
	summary := ""
	switch request.Method {
	case protocol.MethodHeartbeat:
		s.Monitor.Heartbeat(now())
		summary = "heartbeat accepted"
	case protocol.MethodHostSnapshot:
		data, err = s.Inspector.HostSnapshot(ctx)
	case protocol.MethodSystemdUnit:
		data, err = s.Inspector.SystemdUnit(ctx, request.Unit)
	case protocol.MethodJournalTail:
		data, err = s.Inspector.JournalTail(ctx, request.Unit, request.Lines)
	default:
		err = errors.New("method is not served by systemd-helper")
	}
	event := map[string]interface{}{"type": "helper_request", "requestId": request.RequestID, "method": request.Method, "peer": map[string]interface{}{"pid": peer.PID, "uid": peer.UID, "gid": peer.GID}, "ok": err == nil}
	if err != nil {
		event["error"] = err.Error()
	}
	auditID, auditErr := s.Audit.Append(event)
	if auditErr != nil {
		response.Error = "write audit: " + auditErr.Error()
		return response
	}
	response.AuditID = auditID
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.OK = true
	response.Summary = summary
	response.Data = data
	return response
}

func ValidateUnit(unit string) error {
	if !strings.HasSuffix(unit, ".service") || strings.ContainsAny(unit, "/\x00\n\r") || len(unit) > 200 {
		return errors.New("agent unit must be a simple .service name")
	}
	return nil
}
