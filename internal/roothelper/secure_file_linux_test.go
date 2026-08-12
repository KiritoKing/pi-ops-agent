//go:build linux

package roothelper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"golang.org/x/sys/unix"
)

func forceFileWriteOpenat2ENOSYS(t *testing.T) {
	t.Helper()
	previous := secureFileOpenat2
	secureFileOpenat2 = func(int, string, *unix.OpenHow) (int, error) {
		return -1, unix.ENOSYS
	}
	t.Cleanup(func() { secureFileOpenat2 = previous })
}

func TestLinuxFileWriteOpenat2ENOSYSFallbackHandlesExistingAndNewTargets(t *testing.T) {
	executor, root := testFileExecutor(t)
	forceFileWriteOpenat2ENOSYS(t)

	existing := filepath.Join(root, "existing.conf")
	if err := os.WriteFile(existing, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	existingOperation, existingScope, existingResult := preparedFileWrite(
		t, executor, existing, "new\n", "0640", "change-openat2-enosys-existing",
	)
	if err := executor.Execute(context.Background(), existingScope, existingOperation, existingResult); err != nil {
		t.Fatalf("execute existing target through fallback: %v", err)
	}
	if _, err := executor.Verify(context.Background(), existingScope, existingOperation, existingResult); err != nil {
		t.Fatalf("verify existing target through fallback: %v", err)
	}
	if err := executor.Rollback(context.Background(), existingScope, existingOperation, existingResult); err != nil {
		t.Fatalf("rollback existing target through fallback: %v", err)
	}

	created := filepath.Join(root, "created.conf")
	createdOperation, createdScope, createdResult := preparedFileWrite(
		t, executor, created, "created\n", "0640", "change-openat2-enosys-created",
	)
	if err := executor.Execute(context.Background(), createdScope, createdOperation, createdResult); err != nil {
		t.Fatalf("execute new target through fallback: %v", err)
	}
	if _, err := executor.Verify(context.Background(), createdScope, createdOperation, createdResult); err != nil {
		t.Fatalf("verify new target through fallback: %v", err)
	}
	if err := executor.Rollback(context.Background(), createdScope, createdOperation, createdResult); err != nil {
		t.Fatalf("rollback new target through fallback: %v", err)
	}
	if _, err := os.Lstat(created); !os.IsNotExist(err) {
		t.Fatalf("fallback rollback left the newly-created target behind: %v", err)
	}
}

func TestLinuxFileWriteOpenat2ENOSYSFallbackRejectsUnsafeComponents(t *testing.T) {
	forceFileWriteOpenat2ENOSYS(t)
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rootFD) }()

	previousOpenat := secureFileOpenat
	previousStatx := secureFileStatx
	openatCalls := 0
	statxCalls := 0
	secureFileOpenat = func(dirfd int, path string, flags int, mode uint32) (int, error) {
		openatCalls++
		return previousOpenat(dirfd, path, flags, mode)
	}
	secureFileStatx = func(dirfd int, path string, flags int, mask int, stat *unix.Statx_t) error {
		statxCalls++
		return previousStatx(dirfd, path, flags, mask, stat)
	}
	t.Cleanup(func() {
		secureFileOpenat = previousOpenat
		secureFileStatx = previousStatx
	})

	for _, relative := range []string{"", "/dev", ".", "..", "dev/.", "dev/..", "dev//pts", "dev/"} {
		if fd, err := openFileWriteDirectoryAt(rootFD, relative, fileWriteResolveFlags); err == nil {
			_ = unix.Close(fd)
			t.Fatalf("fallback accepted unsafe relative path %q", relative)
		}
	}
	if openatCalls != 0 || statxCalls != 0 {
		t.Fatalf("unsafe paths reached fallback syscalls: openat=%d statx=%d", openatCalls, statxCalls)
	}
}

func TestLinuxFileWriteOpenat2ENOSYSFallbackUsesExactSyscallPolicy(t *testing.T) {
	forceFileWriteOpenat2ENOSYS(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rootFD) }()

	previousOpenat := secureFileOpenat
	previousStatx := secureFileStatx
	openatCalls := 0
	statxCalls := 0
	secureFileOpenat = func(dirfd int, path string, flags int, mode uint32) (int, error) {
		openatCalls++
		wantFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if flags != wantFlags || mode != 0 {
			t.Fatalf("unsafe fallback openat policy: flags=%#x mode=%#o", flags, mode)
		}
		return previousOpenat(dirfd, path, flags, mode)
	}
	secureFileStatx = func(dirfd int, path string, flags int, mask int, stat *unix.Statx_t) error {
		statxCalls++
		if path != "" || flags != unix.AT_EMPTY_PATH || mask != unix.STATX_MNT_ID {
			t.Fatalf("unsafe fallback statx policy: path=%q flags=%#x mask=%#x", path, flags, mask)
		}
		return previousStatx(dirfd, path, flags, mask, stat)
	}
	t.Cleanup(func() {
		secureFileOpenat = previousOpenat
		secureFileStatx = previousStatx
	})
	fd, err := openFileWriteDirectoryAt(rootFD, "child", fileWriteResolveFlags)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	if openatCalls != 1 || statxCalls != 2 {
		t.Fatalf("unexpected syscall count: openat=%d statx=%d", openatCalls, statxCalls)
	}
}

func TestLinuxFileWriteOpenat2NonENOSYSDoesNotFallback(t *testing.T) {
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rootFD) }()

	previousOpenat2 := secureFileOpenat2
	previousOpenat := secureFileOpenat
	previousStatx := secureFileStatx
	openatCalls := 0
	statxCalls := 0
	secureFileOpenat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.EPERM }
	secureFileOpenat = func(int, string, int, uint32) (int, error) {
		openatCalls++
		return -1, unix.EIO
	}
	secureFileStatx = func(int, string, int, int, *unix.Statx_t) error {
		statxCalls++
		return unix.EIO
	}
	t.Cleanup(func() {
		secureFileOpenat2 = previousOpenat2
		secureFileOpenat = previousOpenat
		secureFileStatx = previousStatx
	})

	if fd, err := openFileWriteDirectoryAt(rootFD, "dev", fileWriteResolveFlags); !errors.Is(err, unix.EPERM) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatalf("non-ENOSYS result was not preserved: %v", err)
	}
	if openatCalls != 0 || statxCalls != 0 {
		t.Fatalf("non-ENOSYS openat2 error entered fallback: openat=%d statx=%d", openatCalls, statxCalls)
	}
}

func TestLinuxFileWriteOpenat2ENOSYSFallbackRequiresMountIdentity(t *testing.T) {
	forceFileWriteOpenat2ENOSYS(t)
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rootFD) }()

	previousStatx := secureFileStatx
	t.Cleanup(func() { secureFileStatx = previousStatx })
	tests := []struct {
		name  string
		statx func(int, string, int, int, *unix.Statx_t) error
	}{
		{name: "syscall-failure", statx: func(int, string, int, int, *unix.Statx_t) error { return unix.EIO }},
		{name: "missing-mask", statx: func(_ int, _ string, _ int, _ int, stat *unix.Statx_t) error {
			stat.Mask = unix.STATX_TYPE
			stat.Mnt_id = 7
			return nil
		}},
		{name: "zero-mount-id", statx: func(_ int, _ string, _ int, _ int, stat *unix.Statx_t) error {
			stat.Mask = unix.STATX_MNT_ID
			return nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secureFileStatx = test.statx
			if fd, err := openFileWriteDirectoryAt(rootFD, "dev", fileWriteRootResolveFlags); err == nil {
				_ = unix.Close(fd)
				t.Fatal("configured-root fallback accepted unavailable mount identity")
			}
		})
	}
}

func TestLinuxFileWriteOpenat2ENOSYSFallbackRejectsSymlink(t *testing.T) {
	allowed := t.TempDir()
	if err := os.Mkdir(filepath.Join(allowed, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(allowed, "link")); err != nil {
		t.Fatal(err)
	}
	allowedFD, err := unix.Open(allowed, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(allowedFD) }()
	forceFileWriteOpenat2ENOSYS(t)
	if fd, err := openFileWriteDirectoryAt(allowedFD, "link", fileWriteResolveFlags); err == nil {
		_ = unix.Close(fd)
		t.Fatal("fallback followed a symlink directory")
	}
}

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

func TestLinuxFileWriteOpenat2ENOSYSFallbackRejectsNestedMount(t *testing.T) {
	var deviceRoot unix.Statx_t
	var pseudoterminalRoot unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, "/dev", 0, unix.STATX_MNT_ID, &deviceRoot); err != nil ||
		deviceRoot.Mask&unix.STATX_MNT_ID == 0 || deviceRoot.Mnt_id == 0 {
		t.Skipf("/dev mount identity is unavailable: %v", err)
	}
	if err := unix.Statx(unix.AT_FDCWD, "/dev/pts", 0, unix.STATX_MNT_ID, &pseudoterminalRoot); err != nil ||
		pseudoterminalRoot.Mask&unix.STATX_MNT_ID == 0 || pseudoterminalRoot.Mnt_id == 0 {
		t.Skipf("/dev/pts mount identity is unavailable: %v", err)
	}
	if deviceRoot.Mnt_id == pseudoterminalRoot.Mnt_id {
		t.Skip("/dev/pts is not a nested mount")
	}
	forceFileWriteOpenat2ENOSYS(t)
	if parentFD, _, _, err := openAllowedFileParent("/dev/pts/ops-agent-value", []string{"/dev"}); err == nil {
		_ = unix.Close(parentFD)
		t.Fatal("openat2 ENOSYS fallback accepted a nested mount below its configured root")
	}
}

func TestLinuxFileWriteOpenat2ENOSYSFallbackMountAnchorPolicy(t *testing.T) {
	forceFileWriteOpenat2ENOSYS(t)
	parentFD, base, parentStat, err := openAllowedFileParent("/dev/ops-agent-value", []string{"/dev"})
	if err != nil {
		t.Fatalf("fallback rejected a configured root at its mount point: %v", err)
	}
	_ = unix.Close(parentFD)
	if base != "ops-agent-value" {
		t.Fatalf("unexpected direct target below configured mount root: %q", base)
	}
	var deviceRoot unix.Stat_t
	if err := unix.Stat("/dev", &deviceRoot); err != nil {
		t.Fatal(err)
	}
	if parentStat.Dev != deviceRoot.Dev || parentStat.Ino != deviceRoot.Ino {
		t.Fatal("fallback did not bind the configured mount-root directory identity")
	}

	root, err := os.MkdirTemp("/dev/shm", "ops-agent-openat2-fallback-")
	if err != nil {
		t.Skipf("cannot create a root below the mounted ancestor: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	previousUID := secureFileRequiredParentUID
	secureFileRequiredParentUID = uint32(os.Geteuid())
	t.Cleanup(func() { secureFileRequiredParentUID = previousUID })
	if fd, _, _, err := openAllowedFileParent(filepath.Join(root, "value.conf"), []string{root}); err == nil {
		_ = unix.Close(fd)
		t.Fatal("fallback accepted a configured root below a mounted ancestor")
	}
}

func TestLinuxFileWriteOpenat2ENOSYSFallbackBindMountBoundaries(t *testing.T) {
	previousUID := secureFileRequiredParentUID
	secureFileRequiredParentUID = uint32(os.Geteuid())
	t.Cleanup(func() { secureFileRequiredParentUID = previousUID })
	base := t.TempDir()
	if os.Geteuid() == 0 {
		rootBase, err := os.MkdirTemp("/", ".ops-agent-openat2-bind-")
		if err == nil {
			base = rootBase
			t.Cleanup(func() { _ = os.RemoveAll(rootBase) })
		}
	}
	sourceRoot := filepath.Join(base, "source-root")
	targetRoot := filepath.Join(base, "target-root")
	nestedSource := filepath.Join(base, "nested-source")
	for _, path := range []string{sourceRoot, targetRoot, nestedSource, filepath.Join(sourceRoot, "nested")} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	forceFileWriteOpenat2ENOSYS(t)
	if fd, _, _, err := openAllowedFileParent(filepath.Join(targetRoot, "value.conf"), []string{targetRoot}); err != nil {
		t.Skipf("temporary directory parent already crosses a mount: %v", err)
	} else {
		_ = unix.Close(fd)
	}

	if err := unix.Mount(sourceRoot, targetRoot, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOSYS) {
			t.Skipf("bind mounts are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(targetRoot, 0); err != nil {
			t.Errorf("unmount configured-root fixture: %v", err)
		}
	})
	if fd, base, _, err := openAllowedFileParent(filepath.Join(targetRoot, "value.conf"), []string{targetRoot}); err != nil {
		t.Fatalf("fallback rejected configured root at a bind mount: %v", err)
	} else {
		_ = unix.Close(fd)
		if base != "value.conf" {
			t.Fatalf("unexpected target below bind-mounted root: %q", base)
		}
	}

	nestedTarget := filepath.Join(targetRoot, "nested")
	if err := unix.Mount(nestedSource, nestedTarget, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(nestedTarget, 0); err != nil {
			t.Errorf("unmount nested fixture: %v", err)
		}
	})
	if fd, _, _, err := openAllowedFileParent(filepath.Join(nestedTarget, "value.conf"), []string{targetRoot}); err == nil {
		_ = unix.Close(fd)
		t.Fatal("fallback accepted a bind mount nested below its configured root")
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
