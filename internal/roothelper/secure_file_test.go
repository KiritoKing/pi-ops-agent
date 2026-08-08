package roothelper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

func testFileExecutor(t *testing.T) (*OSExecutor, string) {
	t.Helper()
	previousUID := secureFileRequiredParentUID
	secureFileRequiredParentUID = uint32(os.Geteuid())
	t.Cleanup(func() { secureFileRequiredParentUID = previousUID })
	root := filepath.Join(t.TempDir(), "allowed")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return &OSExecutor{StateDir: t.TempDir(), AllowedRoots: []string{root}}, root
}

func preparedFileWrite(t *testing.T, executor *OSExecutor, path, content, mode, changeID string) (*protocol.FileWrite, ExecutionScope, ExecutionResult) {
	t.Helper()
	operation := &protocol.FileWrite{OperationKind: "file.write", Path: path, Content: content, Mode: mode}
	scope := ExecutionScope{ChangeID: changeID}
	result, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	return operation, scope, result
}

func TestFileWriteRejectsExecutableTargetAndMode(t *testing.T) {
	executor, root := testFileExecutor(t)
	path := filepath.Join(root, "script")
	if err := os.WriteFile(path, []byte("old\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	operation := &protocol.FileWrite{OperationKind: "file.write", Path: path, Content: "new\n", Mode: "0644"}
	if _, err := executor.Prepare(context.Background(), ExecutionScope{ChangeID: "change-executable-target"}, operation); err == nil {
		t.Fatal("file.write prepared an executable target")
	}
	operation.Mode = "0755"
	if err := operation.Validate(); err == nil {
		t.Fatal("file.write accepted an executable requested mode")
	}
}

func TestFileWriteBindsParentAndTargetIdentityAcrossApproval(t *testing.T) {
	executor, root := testFileExecutor(t)
	parent := filepath.Join(root, "config")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "value.conf")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	operation := &protocol.FileWrite{OperationKind: "file.write", Path: path, Content: "new\n", Mode: "0644"}
	result, err := executor.Prepare(context.Background(), ExecutionScope{ChangeID: "change-parent-drift"}, operation)
	if err != nil {
		t.Fatal(err)
	}
	moved := parent + ".moved"
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("decoy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), ExecutionScope{ChangeID: "change-parent-drift"}, operation, result); err == nil {
		t.Fatal("file.write followed a replaced parent directory after approval")
	}
	if payload, _ := os.ReadFile(path); string(payload) != "decoy\n" {
		t.Fatalf("replacement parent was mutated: %q", payload)
	}
	if payload, _ := os.ReadFile(filepath.Join(moved, "value.conf")); string(payload) != "old\n" {
		t.Fatalf("prepared parent was mutated despite identity mismatch: %q", payload)
	}
}

func TestFileWriteSecureCommitVerifyAndRollback(t *testing.T) {
	executor, root := testFileExecutor(t)
	path := filepath.Join(root, "value.conf")
	if err := os.WriteFile(path, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	operation := &protocol.FileWrite{OperationKind: "file.write", Path: path, Content: "new\n", Mode: "0644"}
	scope := ExecutionScope{ChangeID: "change-secure-roundtrip"}
	result, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	var rollback fileRollback
	if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
		t.Fatal(err)
	}
	commit, err := readAllowedFileCommit(rollback.CommitPath)
	if err != nil {
		t.Fatal(err)
	}
	if commit.UID != os.Geteuid() || commit.GID != os.Getegid() || commit.Mode != 0o644 ||
		commit.ContentDigest != secureFilePayloadDigest([]byte("new\n")) {
		t.Fatalf("committed identity did not bind actual inode metadata: %#v", commit)
	}
	if _, err := executor.Verify(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if err := executor.Rollback(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil || string(payload) != "old\n" {
		t.Fatalf("rollback did not restore the exact backup: %q %v", payload, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("rollback did not restore the original mode: %v %v", info, err)
	}
}

func TestFileWriteRejectsInPlaceContentAndMetadataDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{name: "content", mutate: func(path string) error { return os.WriteFile(path, []byte("raced\n"), 0o640) }},
		{name: "mode", mutate: func(path string) error { return os.Chmod(path, 0o600) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor, root := testFileExecutor(t)
			path := filepath.Join(root, "value.conf")
			if err := os.WriteFile(path, []byte("old\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			operation, scope, result := preparedFileWrite(t, executor, path, "new\n", "0644", "change-in-place-"+test.name)
			if err := test.mutate(path); err != nil {
				t.Fatal(err)
			}
			if err := executor.Execute(context.Background(), scope, operation, result); err == nil {
				t.Fatal("file.write accepted an in-place target drift")
			}
		})
	}
}

func TestFileWriteNewTargetCommitAndRollbackRemovesExactInode(t *testing.T) {
	executor, root := testFileExecutor(t)
	path := filepath.Join(root, "new.conf")
	operation, scope, result := preparedFileWrite(t, executor, path, "new\n", "0640", "change-new-roundtrip")
	if err := executor.Execute(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Verify(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if err := executor.Rollback(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("rollback did not remove the exact newly-created inode: %v", err)
	}
}

func TestFileWriteVerifyAndRollbackRejectCommittedDrift(t *testing.T) {
	executor, root := testFileExecutor(t)
	path := filepath.Join(root, "value.conf")
	if err := os.WriteFile(path, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	operation, scope, result := preparedFileWrite(t, executor, path, "new\n", "0644", "change-committed-drift")
	if err := executor.Execute(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("external\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Verify(context.Background(), scope, operation, result); err == nil {
		t.Fatal("verification accepted content changed after commit")
	}
	if err := executor.Rollback(context.Background(), scope, operation, result); err == nil {
		t.Fatal("rollback overwrote content changed after commit")
	}
	payload, err := os.ReadFile(path)
	if err != nil || string(payload) != "external\n" {
		t.Fatalf("failed rollback changed external content: %q %v", payload, err)
	}
}

func TestFileWriteRejectsWritableParentSymlinkAndOversizedBackup(t *testing.T) {
	t.Run("writable-parent", func(t *testing.T) {
		executor, root := testFileExecutor(t)
		if err := os.Chmod(root, 0o777); err != nil {
			t.Fatal(err)
		}
		operation := &protocol.FileWrite{OperationKind: "file.write", Path: filepath.Join(root, "value.conf"), Content: "new\n"}
		if _, err := executor.Prepare(context.Background(), ExecutionScope{ChangeID: "change-writable-parent"}, operation); err == nil {
			t.Fatal("file.write accepted a group/world-writable parent")
		}
	})
	t.Run("symlink-target", func(t *testing.T) {
		executor, root := testFileExecutor(t)
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "value.conf")
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
		operation := &protocol.FileWrite{OperationKind: "file.write", Path: path, Content: "new\n"}
		if _, err := executor.Prepare(context.Background(), ExecutionScope{ChangeID: "change-symlink-target"}, operation); err == nil {
			t.Fatal("file.write accepted a symlink target")
		}
	})
	t.Run("oversized-backup", func(t *testing.T) {
		executor, root := testFileExecutor(t)
		path := filepath.Join(root, "value.conf")
		if err := os.WriteFile(path, []byte(strings.Repeat("x", maxSecureFileBytes+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		operation := &protocol.FileWrite{OperationKind: "file.write", Path: path, Content: "new\n"}
		if _, err := executor.Prepare(context.Background(), ExecutionScope{ChangeID: "change-large-backup"}, operation); err == nil {
			t.Fatal("file.write accepted an unbounded backup target")
		}
	})
}
