package roothelper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

func useLegacyRecoveryFixtureOwner(t *testing.T) (int, int) {
	t.Helper()
	uid, gid := os.Geteuid(), os.Getegid()
	previousParent := secureFileRequiredParentUID
	previousLegacyUID, previousLegacyGID := secureLegacyFileRequiredUID, secureLegacyFileRequiredGID
	secureFileRequiredParentUID = uint32(uid)
	secureLegacyFileRequiredUID, secureLegacyFileRequiredGID = uint32(uid), uint32(gid)
	t.Cleanup(func() {
		secureFileRequiredParentUID = previousParent
		secureLegacyFileRequiredUID, secureLegacyFileRequiredGID = previousLegacyUID, previousLegacyGID
	})
	return uid, gid
}

func legacyFileOperation(t *testing.T, path, content, mode string) *protocol.FileWrite {
	t.Helper()
	payload, err := json.Marshal(map[string]interface{}{
		"kind": "file.write", "path": path, "content": content, "mode": mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := protocol.ParseStoredOperation(payload)
	if err != nil {
		t.Fatal(err)
	}
	file, ok := operation.(*protocol.FileWrite)
	if !ok || !protocol.IsStoredOnlyOperation(file) {
		t.Fatalf("operation is not stored legacy file.write: %#v", operation)
	}
	return file
}

func TestLegacyFileRollbackRestoresOnlyExactCommittedTargetAndBrokerBackup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file ownership fixture is Unix-only")
	}
	uid, gid := useLegacyRecoveryFixtureOwner(t)
	directory := t.TempDir()
	allowedRoot := filepath.Join(directory, "allowed")
	stateDir := filepath.Join(directory, "state")
	changeID := "change-legacy-file-restore"
	changeDir := filepath.Join(stateDir, "changes", changeID)
	if err := os.MkdirAll(allowedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(changeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(allowedRoot, "demo.conf")
	backup := filepath.Join(changeDir, "file.backup")
	if err := os.WriteFile(target, []byte("approved replacement\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(backup, 0o600); err != nil {
		t.Fatal(err)
	}
	rollback, err := json.Marshal(legacyFileRollback{
		Existed: true, BackupPath: backup, Mode: 0o600, UID: uid, GID: gid,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := ExecutionResult{
		BackupRefs: []string{backup}, RollbackData: rollback, RollbackAvailable: true,
	}
	executor := &OSExecutor{StateDir: stateDir, AllowedRoots: []string{allowedRoot}}
	operation := legacyFileOperation(t, target, "approved replacement\n", "0640")
	objects, err := executor.InspectLegacyFileRecovery(ExecutionScope{ChangeID: changeID}, operation, result)
	if err != nil || len(objects) != 1 || objects[0].Reference != backup || objects[0].Digest != secureFilePayloadDigest([]byte("original\n")) {
		t.Fatalf("legacy recovery proof is incomplete: objects=%#v err=%v", objects, err)
	}
	if err := executor.Rollback(context.Background(), ExecutionScope{ChangeID: changeID}, operation, result); err != nil {
		t.Fatalf("restore exact legacy target: %v", err)
	}
	payload, err := os.ReadFile(target)
	if err != nil || string(payload) != "original\n" {
		t.Fatalf("legacy target was not restored: payload=%q err=%v", payload, err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("legacy target mode was not restored: info=%#v err=%v", info, err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf("legacy target owner was not restored: %#v", info.Sys())
	}
}

func TestLegacyFileRollbackRemovesOnlyExactRootOwnedNewFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file ownership fixture is Unix-only")
	}
	useLegacyRecoveryFixtureOwner(t)
	directory := t.TempDir()
	allowedRoot := filepath.Join(directory, "allowed")
	stateDir := filepath.Join(directory, "state")
	changeID := "change-legacy-file-remove"
	if err := os.MkdirAll(filepath.Join(stateDir, "changes", changeID), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(allowedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(allowedRoot, "new.conf")
	if err := os.WriteFile(target, []byte("approved new file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	result := ExecutionResult{RollbackData: json.RawMessage(`{"existed":false}`), RollbackAvailable: true}
	executor := &OSExecutor{StateDir: stateDir, AllowedRoots: []string{allowedRoot}}
	operation := legacyFileOperation(t, target, "approved new file\n", "")
	if err := executor.Rollback(context.Background(), ExecutionScope{ChangeID: changeID}, operation, result); err != nil {
		t.Fatalf("remove exact legacy-created target: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("legacy-created target remains after rollback: %v", err)
	}
}

func TestLegacyFileRollbackRejectsContentOrBackupEvidenceDrift(t *testing.T) {
	useLegacyRecoveryFixtureOwner(t)
	directory := t.TempDir()
	allowedRoot := filepath.Join(directory, "allowed")
	stateDir := filepath.Join(directory, "state")
	changeID := "change-legacy-file-drift"
	changeDir := filepath.Join(stateDir, "changes", changeID)
	if err := os.MkdirAll(allowedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(changeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(allowedRoot, "demo.conf")
	backup := filepath.Join(changeDir, "file.backup")
	if err := os.WriteFile(target, []byte("drifted after commit\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(backup, 0o644); err != nil {
		t.Fatal(err)
	}
	rollback, _ := json.Marshal(legacyFileRollback{
		Existed: true, BackupPath: backup, Mode: 0o600, UID: os.Geteuid(), GID: os.Getegid(),
	})
	result := ExecutionResult{BackupRefs: []string{backup}, RollbackData: rollback, RollbackAvailable: true}
	executor := &OSExecutor{StateDir: stateDir, AllowedRoots: []string{allowedRoot}}
	operation := legacyFileOperation(t, target, "approved replacement\n", "0640")
	if _, err := executor.InspectLegacyFileRecovery(ExecutionScope{ChangeID: changeID}, operation, result); err == nil {
		t.Fatal("legacy recovery proof accepted drifted content and an unsafe backup mode")
	}
	if err := executor.Rollback(context.Background(), ExecutionScope{ChangeID: changeID}, operation, result); err == nil {
		t.Fatal("legacy rollback mutated a target without exact commit evidence")
	}
	payload, _ := os.ReadFile(target)
	if string(payload) != "drifted after commit\n" {
		t.Fatalf("failed legacy recovery changed the target: %q", payload)
	}
}
