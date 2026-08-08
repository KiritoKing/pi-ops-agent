//go:build linux

package roothelper

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestLinuxFileWriteResolvePolicyRejectsMountCrossings(t *testing.T) {
	if fileWriteResolveFlags&unix.RESOLVE_NO_XDEV == 0 ||
		fileWriteResolveFlags&unix.RESOLVE_NO_SYMLINKS == 0 ||
		fileWriteResolveFlags&unix.RESOLVE_BENEATH == 0 {
		t.Fatalf("file.write openat2 flags do not close mount/symlink escapes: %#x", fileWriteResolveFlags)
	}
}

func TestLinuxFileWriteFIFOTypeCheckDoesNotBlock(t *testing.T) {
	executor, root := testFileExecutor(t)
	path := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	operation := &protocol.FileWrite{OperationKind: "file.write", Path: path, Content: "new\n"}
	started := time.Now()
	if _, err := executor.Prepare(context.Background(), ExecutionScope{ChangeID: "change-linux-fifo"}, operation); err == nil {
		t.Fatal("file.write accepted a FIFO target")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("file.write FIFO rejection blocked for %s", elapsed)
	}
}

func TestLinuxExchangeCASRestoresUnexpectedDisplacedInode(t *testing.T) {
	_, root := testFileExecutor(t)
	path := filepath.Join(root, "value.conf")
	if err := os.WriteFile(path, []byte("approved-old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup")
	expected, err := captureAllowedFile(path, []string{root}, backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unexpected-current\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	parentFD, base, _, err := openAllowedFileParent(path, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(parentFD) }()
	staged, err := createStagedAllowedFile(parentFD, []byte("approved-new\n"), 0o640, os.Geteuid(), os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	defer staged.cleanup(parentFD)
	err = exchangeStagedFile(parentFD, staged.name, base, func() error {
		return validateSnapshotAt(parentFD, staged.name, expected)
	})
	if err == nil || mutationOutcomeUncertain(err) {
		t.Fatalf("exchange CAS did not cleanly reject and restore the unexpected inode: %v", err)
	}
	payload, readErr := os.ReadFile(path)
	if readErr != nil || string(payload) != "unexpected-current\n" {
		t.Fatalf("exchange CAS did not restore the unexpected target: %q %v", payload, readErr)
	}
	stagedPayload, readErr := os.ReadFile(filepath.Join(root, staged.name))
	if readErr != nil || string(stagedPayload) != "approved-new\n" {
		t.Fatalf("exchange CAS lost its staging inode after restoration: %q %v", stagedPayload, readErr)
	}
}

func TestLinuxRenameNoReplacePreservesAppearedTarget(t *testing.T) {
	executor, root := testFileExecutor(t)
	path := filepath.Join(root, "new.conf")
	operation, scope, result := preparedFileWrite(t, executor, path, "approved\n", "0640", "change-linux-noreplace")
	if err := os.WriteFile(path, []byte("appeared\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), scope, operation, result); err == nil {
		t.Fatal("file.write replaced a target that appeared after preparation")
	}
	payload, err := os.ReadFile(path)
	if err != nil || string(payload) != "appeared\n" {
		t.Fatalf("RENAME_NOREPLACE changed the appeared target: %q %v", payload, err)
	}
}
