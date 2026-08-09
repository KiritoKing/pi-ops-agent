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
	if fileWriteRootResolveFlags&unix.RESOLVE_NO_XDEV != 0 ||
		fileWriteRootResolveFlags&unix.RESOLVE_NO_MAGICLINKS == 0 ||
		fileWriteRootResolveFlags&unix.RESOLVE_NO_SYMLINKS == 0 ||
		fileWriteRootResolveFlags&unix.RESOLVE_BENEATH == 0 {
		t.Fatalf("file.write policy-root flags do not safely anchor a mount-point root: %#x", fileWriteRootResolveFlags)
	}
	if fileWriteResolveFlags&unix.RESOLVE_NO_XDEV == 0 ||
		fileWriteResolveFlags&unix.RESOLVE_NO_SYMLINKS == 0 ||
		fileWriteResolveFlags&unix.RESOLVE_BENEATH == 0 {
		t.Fatalf("file.write descendant flags do not close mount/symlink escapes: %#x", fileWriteResolveFlags)
	}
}

func TestLinuxFileWriteAllowsFilesystemRoot(t *testing.T) {
	parentFD, base, _, err := openAllowedFileParent("/ops-agent-root-value", []string{"/"})
	if err != nil {
		t.Fatalf("configured filesystem root was rejected: %v", err)
	}
	defer func() { _ = unix.Close(parentFD) }()
	if base != "ops-agent-root-value" {
		t.Fatalf("unexpected basename below filesystem root: %q", base)
	}
}

func TestLinuxSecureFileFixtureUsesNarrowestUsableMountAnchor(t *testing.T) {
	executor, root := testFileExecutor(t)
	if len(executor.AllowedRoots) != 1 {
		t.Fatalf("unexpected fixture roots: %#v", executor.AllowedRoots)
	}
	anchor := executor.AllowedRoots[0]
	parentFD, base, _, err := openAllowedFileParent(filepath.Join(root, "value.conf"), []string{anchor})
	if err != nil {
		t.Fatalf("fixture anchor does not admit its unique target: anchor=%q err=%v", anchor, err)
	}
	_ = unix.Close(parentFD)
	if base != "value.conf" {
		t.Fatalf("unexpected fixture target basename: %q", base)
	}
	if anchor != root {
		if rejectedFD, _, _, rootErr := openAllowedFileParent(filepath.Join(root, "value.conf"), []string{root}); rootErr == nil {
			_ = unix.Close(rejectedFD)
			t.Fatalf("fixture climbed away from an already-usable narrow root: root=%q anchor=%q", root, anchor)
		}
	}
}

func TestLinuxFileWriteRejectsNestedMountBelowConfiguredRoot(t *testing.T) {
	var deviceRoot unix.Stat_t
	var pseudoterminalRoot unix.Stat_t
	if err := unix.Stat("/dev", &deviceRoot); err != nil {
		t.Skipf("/dev identity is unavailable: %v", err)
	}
	if err := unix.Stat("/dev/pts", &pseudoterminalRoot); err != nil {
		t.Skipf("/dev/pts is unavailable: %v", err)
	}
	if deviceRoot.Dev == pseudoterminalRoot.Dev {
		t.Skip("/dev/pts is not a nested mount")
	}
	if parentFD, _, _, err := openAllowedFileParent("/dev/pts/ops-agent-value", []string{"/dev"}); err == nil {
		_ = unix.Close(parentFD)
		t.Fatal("file.write accepted a nested mount below its configured root")
	}
}

func TestLinuxFileWriteAllowsConfiguredRootAtMountPoint(t *testing.T) {
	var filesystemRoot unix.Stat_t
	var deviceRoot unix.Stat_t
	if err := unix.Stat("/", &filesystemRoot); err != nil {
		t.Skipf("filesystem root identity is unavailable: %v", err)
	}
	if err := unix.Stat("/dev", &deviceRoot); err != nil {
		t.Skipf("/dev is unavailable: %v", err)
	}
	if filesystemRoot.Dev == deviceRoot.Dev {
		t.Skip("/dev is not a separate mount")
	}

	parentFD, base, parentStat, err := openAllowedFileParent("/dev/ops-agent-value", []string{"/dev"})
	if err != nil {
		t.Fatalf("configured policy root at a mount boundary was rejected: %v", err)
	}
	defer func() { _ = unix.Close(parentFD) }()
	if base != "ops-agent-value" || parentStat.Dev != deviceRoot.Dev {
		t.Fatalf("unexpected cross-filesystem parent binding: base=%q dev=%d want-dev=%d", base, parentStat.Dev, deviceRoot.Dev)
	}
}

func TestLinuxFileWriteRejectsConfiguredRootBelowMountedAncestor(t *testing.T) {
	var filesystemRoot unix.Stat_t
	var sharedMemoryRoot unix.Stat_t
	if err := unix.Stat("/", &filesystemRoot); err != nil {
		t.Skipf("filesystem root identity is unavailable: %v", err)
	}
	if err := unix.Stat("/dev/shm", &sharedMemoryRoot); err != nil {
		t.Skipf("/dev/shm is unavailable: %v", err)
	}
	if filesystemRoot.Dev == sharedMemoryRoot.Dev {
		t.Skip("/dev/shm is not on a mounted ancestor")
	}

	root, err := os.MkdirTemp("/dev/shm", "ops-agent-file-root-")
	if err != nil {
		t.Skipf("cannot create a policy root below the mounted ancestor: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if parentFD, _, _, err := openAllowedFileParent(filepath.Join(root, "value.conf"), []string{root}); err == nil {
		_ = unix.Close(parentFD)
		t.Fatal("file.write accepted a configured root below a mounted ancestor")
	}
}

func TestLinuxFileWriteRejectsSymlinkConfiguredRoot(t *testing.T) {
	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real-root")
	linkRoot := filepath.Join(parent, "link-root")
	if err := os.Mkdir(realRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	if parentFD, _, _, err := openAllowedFileParent(filepath.Join(linkRoot, "value.conf"), []string{linkRoot}); err == nil {
		_ = unix.Close(parentFD)
		t.Fatal("file.write accepted a symlink as its configured root")
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
	executor, root := testFileExecutor(t)
	path := filepath.Join(root, "value.conf")
	if err := os.WriteFile(path, []byte("approved-old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup")
	expected, err := captureAllowedFile(path, executor.AllowedRoots, backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unexpected-current\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	parentFD, base, _, err := openAllowedFileParent(path, executor.AllowedRoots)
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
