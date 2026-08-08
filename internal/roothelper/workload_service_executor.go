package roothelper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const maxWorkloadServiceStateBytes = 8 * 1024

type workloadServiceState struct {
	LoadState   string
	ActiveState string
	SubState    string
	UnitUser    string
}

type workloadServiceMutationError struct{ err error }

func (e workloadServiceMutationError) Error() string                  { return e.err.Error() }
func (e workloadServiceMutationError) Unwrap() error                  { return e.err }
func (e workloadServiceMutationError) MutationOutcomeUncertain() bool { return true }

func requiresAuthoritativePrecondition(operation protocol.Operation) bool {
	if isPVEOperation(operation) {
		return true
	}
	switch operation.(type) {
	case *protocol.WorkloadServiceAction, *protocol.WorkloadJSONConfigEdit:
		return true
	default:
		return false
	}
}

func operationResourceKey(operation protocol.Operation) string {
	if value, ok := operation.(*protocol.WorkloadServiceAction); ok {
		return strings.Join([]string{"workload-service", value.Manager, value.Account, value.Unit}, "/")
	}
	if value, ok := operation.(*protocol.WorkloadJSONConfigEdit); ok {
		// Target policy validation forbids exposing the same physical document
		// through multiple semantic profiles, so this locks the whole document,
		// not merely one selector or field.
		return strings.Join([]string{"workload-json-config", value.PluginID, value.ProfileKey}, "/")
	}
	return pveResourceKey(operation)
}

func (e *OSExecutor) planWorkloadService(ctx context.Context, scope ExecutionScope, operation *protocol.WorkloadServiceAction) (OperationPrecondition, error) {
	if err := e.ValidateOperation(scope, operation); err != nil {
		return OperationPrecondition{}, err
	}
	state, uid, err := e.readWorkloadServiceState(ctx, operation)
	if err != nil {
		return OperationPrecondition{}, err
	}
	if err := requireWorkloadServiceStartingState(operation.Action, state); err != nil {
		return OperationPrecondition{}, err
	}
	unitUser := state.UnitUser
	if operation.Manager == "user" {
		unitUser = "implicit-user-manager"
	}
	fields := []protocol.ApprovalPlanField{
		{Name: "accountUid", Value: strconv.Itoa(uid)},
		{Name: "loadState", Value: state.LoadState},
		{Name: "activeState", Value: state.ActiveState},
		{Name: "subState", Value: state.SubState},
		{Name: "unitUser", Value: unitUser},
	}
	digest, err := protocol.ApprovalPreconditionDigest(fields)
	if err != nil {
		return OperationPrecondition{}, err
	}
	return OperationPrecondition{Digest: digest, Fields: fields}, nil
}

func (e *OSExecutor) prepareWorkloadService(ctx context.Context, scope ExecutionScope, operation *protocol.WorkloadServiceAction) (ExecutionResult, error) {
	if scope.PreconditionDigest == "" {
		return ExecutionResult{}, errors.New("workload service action is missing its approved precondition digest")
	}
	planned, err := e.planWorkloadService(ctx, scope, operation)
	if err != nil {
		return ExecutionResult{}, err
	}
	if planned.Digest != scope.PreconditionDigest {
		return ExecutionResult{}, errors.New("workload service state changed after approval")
	}
	// Starting, stopping, or restarting a daemon may discard or create external
	// work. Restoring only ActiveState is not a complete rollback, so v1 never
	// advertises an automatic inverse.
	return ExecutionResult{RollbackAvailable: false}, nil
}

func (e *OSExecutor) executeWorkloadService(ctx context.Context, scope ExecutionScope, operation *protocol.WorkloadServiceAction) error {
	if scope.PreconditionDigest == "" {
		return errors.New("workload service action is missing its approved precondition digest")
	}
	// Prepare validates immediately before the durable mutation barrier. Re-read
	// after that barrier as well: policy, plugin digest, account identity, unit
	// ownership, and service state may all drift while the record is fsynced.
	planned, err := e.planWorkloadService(ctx, scope, operation)
	if err != nil {
		return fmt.Errorf("workload service preconditions changed after preparation: %w", err)
	}
	if planned.Digest != scope.PreconditionDigest {
		return errors.New("workload service state changed after preparation")
	}
	if _, err := e.runWorkloadSystemctl(ctx, operation, operation.Action); err != nil {
		return workloadServiceMutationError{err: fmt.Errorf("workload service action outcome is uncertain: %w", err)}
	}
	return nil
}

func (e *OSExecutor) verifyWorkloadService(ctx context.Context, operation *protocol.WorkloadServiceAction) (string, error) {
	state, _, err := e.readWorkloadServiceState(ctx, operation)
	if err != nil {
		return "", err
	}
	if operation.Action == "stop" {
		if state.ActiveState != "inactive" {
			return "", fmt.Errorf("workload service is %s/%s after stop", state.ActiveState, state.SubState)
		}
		return "service is inactive/dead", nil
	}
	if operation.Action == "reset-failed" {
		if state.ActiveState == "failed" {
			return "", fmt.Errorf("workload service remains %s/%s after reset-failed", state.ActiveState, state.SubState)
		}
		return "service failure state cleared: " + state.ActiveState + "/" + state.SubState, nil
	}
	if state.ActiveState != "active" {
		return "", fmt.Errorf("workload service is %s/%s after %s", state.ActiveState, state.SubState, operation.Action)
	}
	return "service is active/" + state.SubState, nil
}

func requireWorkloadServiceStartingState(action string, state workloadServiceState) error {
	if state.LoadState != "loaded" {
		return fmt.Errorf("workload service unit load state is %q", state.LoadState)
	}
	switch action {
	case "start":
		if state.ActiveState != "inactive" && state.ActiveState != "failed" {
			return fmt.Errorf("workload service must be inactive or failed before start, got %q", state.ActiveState)
		}
	case "stop", "restart", "reload":
		if state.ActiveState != "active" {
			return fmt.Errorf("workload service must be active before %s, got %q", action, state.ActiveState)
		}
	case "reset-failed":
		if state.ActiveState != "failed" {
			return fmt.Errorf("workload service must be failed before reset-failed, got %q", state.ActiveState)
		}
	default:
		return errors.New("unsupported workload service action")
	}
	return nil
}

func (e *OSExecutor) readWorkloadServiceState(ctx context.Context, operation *protocol.WorkloadServiceAction) (workloadServiceState, int, error) {
	uid, _, err := e.lookupWorkloadAccount(operation.Account)
	if err != nil {
		return workloadServiceState{}, 0, err
	}
	output, err := e.runWorkloadSystemctl(ctx, operation,
		"show", "--no-pager", "--property=LoadState", "--property=ActiveState",
		"--property=SubState", "--property=User")
	if err != nil {
		return workloadServiceState{}, 0, fmt.Errorf("inspect workload service: %w", err)
	}
	state, err := parseWorkloadServiceState(output)
	if err != nil {
		return workloadServiceState{}, 0, err
	}
	if operation.Manager == "system" && state.UnitUser != operation.Account {
		return workloadServiceState{}, 0, fmt.Errorf("system service User=%q does not match approved account", state.UnitUser)
	}
	return state, uid, nil
}

func parseWorkloadServiceState(output string) (workloadServiceState, error) {
	if len(output) == 0 || len(output) > maxWorkloadServiceStateBytes {
		return workloadServiceState{}, errors.New("workload service state is empty or exceeds its output limit")
	}
	wanted := map[string]*string{}
	state := workloadServiceState{}
	wanted["LoadState"] = &state.LoadState
	wanted["ActiveState"] = &state.ActiveState
	wanted["SubState"] = &state.SubState
	wanted["User"] = &state.UnitUser
	seen := make(map[string]struct{}, len(wanted))
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 1024), maxWorkloadServiceStateBytes)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		destination, expected := wanted[key]
		if !ok || !expected || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return workloadServiceState{}, errors.New("workload service state contains an unexpected field")
		}
		if _, duplicate := seen[key]; duplicate {
			return workloadServiceState{}, errors.New("workload service state contains a duplicate field")
		}
		seen[key] = struct{}{}
		*destination = value
	}
	if err := scanner.Err(); err != nil {
		return workloadServiceState{}, err
	}
	if len(seen) != len(wanted) || state.LoadState == "" || state.ActiveState == "" || state.SubState == "" {
		return workloadServiceState{}, errors.New("workload service state is missing an authoritative property")
	}
	return state, nil
}

func (e *OSExecutor) runWorkloadSystemctl(ctx context.Context, operation *protocol.WorkloadServiceAction, arguments ...string) (string, error) {
	systemctlPath := e.SystemctlPath
	if systemctlPath == "" {
		systemctlPath = "/usr/bin/systemctl"
	}
	if !filepath.IsAbs(systemctlPath) || filepath.Clean(systemctlPath) != systemctlPath {
		return "", errors.New("systemctl path must be a clean absolute path")
	}
	commandArguments := append(append([]string(nil), arguments...), "--", operation.Unit)
	if operation.Manager == "system" {
		return e.Runner.Run(ctx, systemctlPath, commandArguments...)
	}
	uid, home, err := e.lookupWorkloadAccount(operation.Account)
	if err != nil {
		return "", err
	}
	runuserPath := e.RunuserPath
	if runuserPath == "" {
		runuserPath = "/usr/sbin/runuser"
	}
	envPath := e.EnvPath
	if envPath == "" {
		envPath = "/usr/bin/env"
	}
	for label, path := range map[string]string{"runuser": runuserPath, "env": envPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return "", fmt.Errorf("%s path must be a clean absolute path", label)
		}
	}
	userArguments := []string{
		"--user", operation.Account, "--", envPath, "-i",
		"HOME=" + home, "USER=" + operation.Account, "LOGNAME=" + operation.Account,
		"XDG_RUNTIME_DIR=/run/user/" + strconv.Itoa(uid),
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C",
		systemctlPath, "--user",
	}
	userArguments = append(userArguments, commandArguments...)
	return e.Runner.Run(ctx, runuserPath, userArguments...)
}

func (e *OSExecutor) lookupWorkloadAccount(account string) (int, string, error) {
	if !protocol.ValidWorkloadAccount(account) {
		return 0, "", errors.New("invalid workload service account")
	}
	if e.LookupWorkloadAccount != nil {
		uid, home, err := e.LookupWorkloadAccount(account)
		return validateWorkloadAccount(uid, home, err)
	}
	entry, err := user.Lookup(account)
	if err != nil {
		return 0, "", fmt.Errorf("lookup workload service account: %w", err)
	}
	uid, err := strconv.Atoi(entry.Uid)
	if err != nil {
		return 0, "", errors.New("workload service account has an invalid UID")
	}
	return validateWorkloadAccount(uid, entry.HomeDir, nil)
}

func validateWorkloadAccount(uid int, home string, lookupErr error) (int, string, error) {
	if lookupErr != nil {
		return 0, "", lookupErr
	}
	if uid <= 0 {
		return 0, "", errors.New("workload service account must be a non-root local account")
	}
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || home == "/" || len(home) > 4096 || strings.ContainsAny(home, "\x00\r\n") {
		return 0, "", errors.New("workload service account has an unsafe home directory")
	}
	return uid, home, nil
}
