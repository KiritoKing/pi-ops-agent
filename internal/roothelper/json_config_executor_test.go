package roothelper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const (
	jsonExecutorDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var (
	jsonExecutorBeforePayload = []byte("[{\"name\":\"primary\",\"model\":\"old/model\",\"unknown\":{\"kept\":true}}]\n")
	jsonExecutorAfterPayload  = []byte("[{\"model\":\"openai/gpt-5\",\"name\":\"primary\",\"unknown\":{\"kept\":true}}]\n")
	jsonExecutorBeforeDigest  = jsonConfigPayloadDigest(jsonExecutorBeforePayload)
	jsonExecutorAfterDigest   = jsonConfigPayloadDigest(jsonExecutorAfterPayload)
	jsonExecutorRacedDigest   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type jsonConfigFakeRunner struct {
	t               *testing.T
	calls           [][]string
	current         string
	selector        jsonConfigSafeValue
	failCommit      bool
	tamperEphemeral bool
	restoredDigest  string
	restoredValue   jsonConfigSafeValue
}

func (r *jsonConfigFakeRunner) RunJSONConfig(_ context.Context, name string, arguments ...string) ([]byte, error) {
	r.t.Helper()
	if name != "/test/systemd-run" {
		r.t.Fatalf("unexpected runner: %s", name)
	}
	r.calls = append(r.calls, append([]string{}, arguments...))
	helperIndex := slices.Index(arguments, jsonConfigHelperPath)
	if helperIndex < 1 || arguments[helperIndex-1] != "--" || helperIndex+1 >= len(arguments) {
		r.t.Fatalf("fixed helper was not invoked after --: %#v", arguments)
	}
	command := arguments[helperIndex+1]
	metadata := func(digest string, inode uint64) jsonConfigFileMetadata {
		size := len(jsonExecutorBeforePayload)
		if digest == jsonExecutorAfterDigest {
			size = len(jsonExecutorAfterPayload)
		}
		return jsonConfigFileMetadata{SHA256: digest, Size: int64(size), Dev: 7, Ino: inode, Mode: 0o600}
	}
	encode := func(value interface{}) []byte {
		payload, err := json.Marshal(value)
		if err != nil {
			r.t.Fatal(err)
		}
		return append(payload, '\n')
	}
	switch command {
	case "inspect":
		inode := uint64(11)
		if r.current == jsonExecutorAfterDigest {
			inode = 12
		}
		return encode(jsonConfigInspectProof{
			Version: 1, Operation: "inspect", Source: metadata(r.current, inode), Selected: r.selector,
		}), nil
	case "inspect-directory":
		return encode(jsonConfigDirectoryProof{
			Version:   1,
			Operation: "inspect-directory",
			Root: jsonConfigDirectoryMetadata{
				Dev: 9, Ino: 31, Mode: 0o755, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()),
			},
			Directory: jsonConfigDirectoryMetadata{
				Dev: 9, Ino: 32, Mode: 0o750, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()),
			},
			ResidualRisk: "pathname_may_be_replaced_after_verification",
		}), nil
	case "snapshot":
		stage := jsonConfigBoundHostStage(arguments)
		if err := os.WriteFile(stage+"/before.json", jsonExecutorBeforePayload, 0o600); err != nil {
			r.t.Fatal(err)
		}
		return encode(jsonConfigSnapshotProof{
			Version: 1, Operation: "snapshot", Source: metadata(jsonExecutorBeforeDigest, 11),
			Snapshot: metadata(jsonExecutorBeforeDigest, 21), Selected: jsonStringSafeValue("old/model"),
		}), nil
	case "mutate":
		stage := jsonConfigBoundHostStage(arguments)
		if err := os.WriteFile(stage+"/after.json", jsonExecutorAfterPayload, 0o600); err != nil {
			r.t.Fatal(err)
		}
		return encode(jsonConfigMutateProof{
			Version: 1, Operation: "mutate", Source: metadata(jsonExecutorBeforeDigest, 11),
			Output: metadata(jsonExecutorAfterDigest, 22), Before: jsonStringSafeValue("old/model"),
			After: jsonStringSafeValue("openai/gpt-5"), BeforeDigest: jsonExecutorBeforeDigest,
			AfterDigest: jsonExecutorAfterDigest, WholeDocumentRewrite: true,
		}), nil
	case "commit", "rollback":
		expectedAfter := optionValue(arguments[helperIndex+2:], "expected-after")
		proof := jsonConfigCommitProof{
			Version: 1, Operation: command, Outcome: "committed", MutationAttempted: true,
			ResidualState: "same_uid_writers_may_race_after_verification", CASMethod: "rename_exchange_then_validate",
			Current: pointerJSONConfigMetadata(metadata(expectedAfter, 12)),
		}
		if r.failCommit {
			proof.Outcome = "outcome_uncertain"
			proof.ResidualState = "unknown"
			proof.Current = nil
			return encode(proof), errors.New("unit failed")
		}
		if r.tamperEphemeral {
			stage := jsonConfigBoundHostStage(arguments)
			if err := os.WriteFile(stage+"/staged.json", []byte("[]\n"), 0o600); err != nil {
				r.t.Fatal(err)
			}
			proof.Outcome = "refused_before_exchange"
			proof.MutationAttempted = false
			proof.ResidualState = "no_mutation_observed"
			proof.Current = nil
			return encode(proof), errors.New("helper rejected tampered staged digest")
		}
		if r.restoredDigest != "" {
			proof.Outcome = "refused_restored"
			proof.ExchangeRestored = true
			proof.ResidualState = "exchange_restored_at_verification"
			proof.Current = pointerJSONConfigMetadata(metadata(r.restoredDigest, 13))
			r.current = r.restoredDigest
			r.selector = r.restoredValue
			return encode(proof), errors.New("helper rejected and restored exchange")
		}
		r.current = expectedAfter
		if expectedAfter == jsonExecutorAfterDigest {
			r.selector = jsonStringSafeValue("openai/gpt-5")
		} else {
			r.selector = jsonStringSafeValue("old/model")
		}
		return encode(proof), nil
	default:
		r.t.Fatalf("unexpected helper command %q", command)
		return nil, nil
	}
}

func jsonConfigBoundHostStage(arguments []string) string {
	for _, argument := range arguments {
		for _, prefix := range []string{"--property=BindPaths=", "--property=BindReadOnlyPaths="} {
			if strings.HasPrefix(argument, prefix) && strings.HasSuffix(argument, ":"+jsonConfigStageMount) {
				return strings.TrimSuffix(strings.TrimPrefix(argument, prefix), ":"+jsonConfigStageMount)
			}
		}
	}
	return ""
}

func optionValue(arguments []string, name string) string {
	for index := range arguments {
		if arguments[index] == "--"+name && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func pointerJSONConfigMetadata(value jsonConfigFileMetadata) *jsonConfigFileMetadata { return &value }

func jsonStringSafeValue(value string) jsonConfigSafeValue {
	return jsonConfigSafeValue{Kind: "string", StringValue: &value}
}

func jsonConfigExecutorFixture(t *testing.T) (*OSExecutor, *jsonConfigFakeRunner, ExecutionScope, *protocol.WorkloadJSONConfigEdit) {
	t.Helper()
	uid := os.Getuid()
	if uid <= 0 {
		t.Skip("JSON config executor fixture requires a non-root test UID")
	}
	policyJSON := `{"version":1,"revision":"policy-json-executor-v1","targets":[{"id":"target-alice-json","account":"alice","displayName":"Alice","inspect":{"hostSnapshot":false,"processList":false,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"authorization":{"standingScopes":[]},"jsonConfigWorkloads":[{"pluginId":"workload.botmux-ops","pluginDigest":"` + jsonExecutorDigest + `","targetAccount":"alice","profileKey":"botmux.bots","runAsUid":` + strconv.Itoa(uid) + `,"runAsHome":"/home/alice","relativeConfig":".botmux/bots.json","selectorKey":"name","allowedSelectors":["primary"],"fields":[{"fieldKey":"model","jsonField":"model","valueType":"string","allowClear":true,"stringConstraint":"model-id/v1"},{"fieldKey":"defaultWorkingDir","jsonField":"defaultWorkingDir","valueType":"string","allowClear":true,"stringConstraint":"absolute-path/v1","pathRoots":["/home/alice"]}]}]}]}`
	policy, err := targetpolicy.Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	runner := &jsonConfigFakeRunner{t: t, current: jsonExecutorBeforeDigest, selector: jsonStringSafeValue("old/model")}
	executor := &OSExecutor{
		StateDir: t.TempDir(), Policy: policy, SystemdRunPath: "/test/systemd-run", JSONConfigRunner: runner,
		LookupWorkloadAccount: func(account string) (int, string, error) {
			if account != "alice" {
				return 0, "", errors.New("unexpected account")
			}
			return uid, "/home/alice", nil
		},
	}
	model := "openai/gpt-5"
	operation := &protocol.WorkloadJSONConfigEdit{
		OperationKind: "workload.json-config.edit", PluginID: "workload.botmux-ops",
		SourceDigest: jsonExecutorDigest, ProfileKey: "botmux.bots", SelectorValue: "primary",
		FieldKey: "model", Value: protocol.WorkloadJSONConfigValue{Kind: "string", StringValue: &model},
	}
	scope := ExecutionScope{
		ChangeID: "change-json-config-0001", TargetID: "target-alice-json",
		PolicyRevision: policy.Revision, CapabilityRevision: protocol.CapabilityRevision,
	}
	return executor, runner, scope, operation
}

func TestWorkloadJSONConfigExecutorEndToEndAndHardening(t *testing.T) {
	executor, runner, scope, operation := jsonConfigExecutorFixture(t)
	planned, err := executor.PlanOperation(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"before", "after", "configDigest", "configIdentity", "documentRewrite", "sameUidRaceBoundary"} {
		if approvalPreconditionValue(planned.Fields, field) == "" {
			t.Fatalf("plan omitted %s: %#v", field, planned.Fields)
		}
	}
	scope.PreconditionDigest = planned.Digest
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.RollbackAvailable || len(prepared.BackupRefs) != 2 || strings.Contains(string(prepared.RollbackData), "old/model") == false {
		// RollbackData is root-only and must bind safe before/after scalars; the
		// externally exposed evidence remains digest-only.
		t.Fatalf("unexpected prepared result: %#v", prepared)
	}
	var sealed jsonConfigRollback
	if err := json.Unmarshal(prepared.RollbackData, &sealed); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(sealed.SealedRoot); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("sealed root is not broker-private: %#v %v", info, err)
	}
	for _, name := range []string{"before.json", "after.json"} {
		if info, err := os.Stat(sealed.SealedRoot + "/" + name); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("sealed %s is not mode 0600: %#v %v", name, info, err)
		}
	}
	if err := executor.Execute(context.Background(), scope, operation, prepared); err != nil {
		t.Fatal(err)
	}
	verification, err := executor.Verify(context.Background(), scope, operation, prepared)
	if err != nil || verification != "json-config-after:"+jsonExecutorAfterDigest {
		t.Fatalf("verification failed: %q %v", verification, err)
	}
	if err := executor.Rollback(context.Background(), scope, operation, prepared); err != nil {
		t.Fatal(err)
	}
	if runner.current != jsonExecutorBeforeDigest {
		t.Fatalf("rollback left digest %s", runner.current)
	}

	for _, call := range runner.calls {
		joined := strings.Join(call, "\n")
		for _, required := range []string{
			"--property=NoNewPrivileges=yes", "--property=PrivateNetwork=yes",
			"--property=ProtectSystem=strict", "--property=ProtectHome=tmpfs",
			"--property=CapabilityBoundingSet=", "--property=RestrictNamespaces=yes",
			"--property=RuntimeMaxSec=30s", "--property=KillMode=control-group",
			"--property=SendSIGKILL=yes", "--property=TimeoutStopSec=5s",
		} {
			if !strings.Contains(joined, required) {
				t.Fatalf("transient unit omitted %s: %#v", required, call)
			}
		}
		if strings.Contains(joined, "/bin/sh") || strings.Contains(joined, "sudo") {
			t.Fatalf("transient unit exposed a shell or sudo: %#v", call)
		}
		if strings.Contains(joined, sealed.SealedRoot) {
			t.Fatalf("root-sealed rollback material was exposed to the target UID: %#v", call)
		}
	}
}

func TestWorkloadJSONConfigPlanBindsDirectoryIdentityProof(t *testing.T) {
	executor, runner, scope, operation := jsonConfigExecutorFixture(t)
	workingDirectory := "/home/alice/workspace"
	operation.FieldKey = "defaultWorkingDir"
	operation.Value = protocol.WorkloadJSONConfigValue{Kind: "string", StringValue: &workingDirectory}
	planned, err := executor.PlanOperation(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []struct{ name, value string }{
		{"workingDirectoryRoot", "/home/alice"},
		{"workingDirectoryPath", workingDirectory},
		{"workingDirectoryRootIdentity", "dev=9;ino=31;mode=0755;uid=" + strconv.Itoa(os.Getuid()) + ";gid=" + strconv.Itoa(os.Getgid())},
		{"workingDirectoryIdentity", "dev=9;ino=32;mode=0750;uid=" + strconv.Itoa(os.Getuid()) + ";gid=" + strconv.Itoa(os.Getgid())},
		{"workingDirectoryResidualRisk", "pathname_may_be_replaced_after_verification"},
	} {
		if actual := approvalPreconditionValue(planned.Fields, expected.name); actual != expected.value {
			t.Fatalf("directory precondition %s=%q, want %q", expected.name, actual, expected.value)
		}
	}
	found := false
	for _, call := range runner.calls {
		joined := strings.Join(call, "\n")
		if strings.Contains(joined, "inspect-directory") {
			found = true
			if !strings.Contains(joined, "--property=BindReadOnlyPaths=/home/alice") ||
				!strings.Contains(joined, "--root\n/home/alice\n--path\n"+workingDirectory) {
				t.Fatalf("directory inspection did not bind the exact policy root and path: %#v", call)
			}
		}
	}
	if !found {
		t.Fatal("absolute-path edit did not invoke the fixed directory-proof helper")
	}
}

func TestWorkloadJSONConfigTamperedEphemeralNeverCommitsOrDamagesSealedCopy(t *testing.T) {
	executor, runner, scope, operation := jsonConfigExecutorFixture(t)
	planned, err := executor.PlanOperation(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	scope.PreconditionDigest = planned.Digest
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	var rollback jsonConfigRollback
	if err := json.Unmarshal(prepared.RollbackData, &rollback); err != nil {
		t.Fatal(err)
	}
	runner.tamperEphemeral = true
	err = executor.Execute(context.Background(), scope, operation, prepared)
	if err == nil || !noMutationStarted(err) || mutationOutcomeUncertain(err) {
		t.Fatalf("tampered ephemeral copy was not a known CAS refusal: %v", err)
	}
	if runner.current != jsonExecutorBeforeDigest {
		t.Fatalf("tampered ephemeral changed current config to %s", runner.current)
	}
	sealedAfter, err := readStableJSONConfigFile(
		rollback.SealedRoot+"/after.json", uint32(os.Geteuid()), jsonExecutorAfterDigest,
	)
	if err != nil || jsonConfigPayloadDigest(sealedAfter) != jsonExecutorAfterDigest {
		t.Fatalf("tampered ephemeral damaged root-sealed after copy: %v", err)
	}
}

func TestWorkloadJSONConfigRestoredExchangeRequiresFreshExactObservation(t *testing.T) {
	tests := []struct {
		name       string
		digest     string
		value      jsonConfigSafeValue
		uncertain  bool
		noMutation bool
		wantError  bool
	}{
		{
			name: "approved before", digest: jsonExecutorBeforeDigest,
			value: jsonStringSafeValue("old/model"), noMutation: true, wantError: true,
		},
		{
			name: "approved after", digest: jsonExecutorAfterDigest,
			value: jsonStringSafeValue("openai/gpt-5"), wantError: false,
		},
		{
			name: "concurrent third state", digest: jsonExecutorRacedDigest,
			value: jsonStringSafeValue("raced/model"), uncertain: true, wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor, runner, scope, operation := jsonConfigExecutorFixture(t)
			planned, err := executor.PlanOperation(context.Background(), scope, operation)
			if err != nil {
				t.Fatal(err)
			}
			scope.PreconditionDigest = planned.Digest
			prepared, err := executor.Prepare(context.Background(), scope, operation)
			if err != nil {
				t.Fatal(err)
			}
			runner.restoredDigest, runner.restoredValue = test.digest, test.value
			err = executor.Execute(context.Background(), scope, operation, prepared)
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected restored-exchange result: %v", err)
			}
			if err == nil {
				if runner.current != jsonExecutorAfterDigest {
					t.Fatalf("successful restored exchange left %s", runner.current)
				}
				return
			}
			if mutationOutcomeUncertain(err) != test.uncertain || noMutationStarted(err) != test.noMutation {
				t.Fatalf("restored-exchange classification mismatch: %v uncertain=%t noMutation=%t", err, mutationOutcomeUncertain(err), noMutationStarted(err))
			}
			attempted, restored := mutationAttemptEvidence(err)
			if !attempted || !restored {
				t.Fatalf("restored-exchange evidence was lost: attempted=%t restored=%t", attempted, restored)
			}
		})
	}
}

func TestClassifyJSONConfigCommitProof(t *testing.T) {
	metadata := &jsonConfigFileMetadata{SHA256: jsonExecutorAfterDigest, Size: 1, Dev: 1, Ino: 1, Mode: 0o600}
	tests := []struct {
		name      string
		proof     jsonConfigCommitProof
		runErr    error
		uncertain bool
		noMutate  bool
	}{
		{"committed", jsonConfigCommitProof{Version: 1, Operation: "commit", Outcome: "committed", MutationAttempted: true, ResidualState: "same_uid_writers_may_race_after_verification", CASMethod: "rename_exchange_then_validate", Current: metadata}, nil, false, false},
		{"before", jsonConfigCommitProof{Version: 1, Operation: "commit", Outcome: "refused_before_exchange", ResidualState: "no_mutation_observed", CASMethod: "rename_exchange_then_validate"}, errors.New("exit"), false, true},
		{"restored", jsonConfigCommitProof{Version: 1, Operation: "commit", Outcome: "refused_restored", MutationAttempted: true, ExchangeRestored: true, ResidualState: "exchange_restored_at_verification", CASMethod: "rename_exchange_then_validate", Current: metadata}, errors.New("exit"), false, false},
		{"unknown", jsonConfigCommitProof{Version: 1, Operation: "commit", Outcome: "outcome_uncertain", MutationAttempted: true, ResidualState: "unknown", CASMethod: "rename_exchange_then_validate"}, errors.New("exit"), true, false},
		{"conflicting success", jsonConfigCommitProof{Version: 1, Operation: "commit", Outcome: "committed", MutationAttempted: true, ResidualState: "same_uid_writers_may_race_after_verification", CASMethod: "rename_exchange_then_validate", Current: metadata}, errors.New("exit"), true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := classifyJSONConfigCommitProof(test.proof, test.runErr, jsonExecutorAfterDigest)
			if test.name == "committed" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || mutationOutcomeUncertain(err) != test.uncertain || noMutationStarted(err) != test.noMutate {
				t.Fatalf("classification mismatch: %v uncertain=%t noMutation=%t", err, mutationOutcomeUncertain(err), noMutationStarted(err))
			}
		})
	}
}

func TestWorkloadJSONConfigInterruptedReconciliation(t *testing.T) {
	executor, runner, scope, operation := jsonConfigExecutorFixture(t)
	planned, err := executor.PlanOperation(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	scope.PreconditionDigest = planned.Digest
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	runner.current, runner.selector = jsonExecutorAfterDigest, jsonStringSafeValue("openai/gpt-5")
	reconciled, err := executor.ReconcileInterruptedChange(context.Background(), scope, operation, prepared)
	if err != nil || reconciled.State != StateCommitted || reconciled.Verification == "" {
		t.Fatalf("after state did not reconcile committed: %#v %v", reconciled, err)
	}
	runner.current, runner.selector = jsonExecutorBeforeDigest, jsonStringSafeValue("old/model")
	reconciled, err = executor.ReconcileInterruptedChange(context.Background(), scope, operation, prepared)
	if err != nil || reconciled.State != StateRolledBack {
		t.Fatalf("before state did not reconcile rolled back: %#v %v", reconciled, err)
	}
	runner.current = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if _, err := executor.ReconcileInterruptedChange(context.Background(), scope, operation, prepared); err == nil {
		t.Fatal("unknown interrupted content was reconciled as terminal")
	}
}
