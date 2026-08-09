//go:build linux

package roothelper

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const fileWriteRootResolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS |
	unix.RESOLVE_NO_SYMLINKS

const fileWriteResolveFlags = fileWriteRootResolveFlags | unix.RESOLVE_NO_XDEV

func validateAllowedParent(stat unix.Stat_t) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != secureFileRequiredParentUID || stat.Mode&0o022 != 0 {
		return errors.New("file.write parent must be a root-owned directory that is not group/world writable")
	}
	return nil
}

func openAllowedFileParent(path string, roots []string) (int, string, unix.Stat_t, error) {
	root, relative, err := selectAllowedFileRoot(path, roots)
	if err != nil {
		return -1, "", unix.Stat_t{}, err
	}
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", unix.Stat_t{}, errors.New("open filesystem root for file.write")
	}
	defer func() { _ = unix.Close(rootFD) }()

	allowedFD := -1
	if root == "/" {
		allowedFD, err = unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	} else {
		rootParentRelative := strings.TrimPrefix(filepath.Dir(root), "/")
		if rootParentRelative == "" {
			rootParentRelative = "."
		}
		rootParentFD, parentErr := unix.Openat2(rootFD, rootParentRelative, &unix.OpenHow{
			Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: fileWriteResolveFlags,
		})
		if parentErr != nil {
			return -1, "", unix.Stat_t{}, errors.New("configured file.write root parent crosses a mount or is not a symlink-free directory")
		}
		allowedFD, err = unix.Openat2(rootParentFD, filepath.Base(root), &unix.OpenHow{
			Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: fileWriteRootResolveFlags,
		})
		_ = unix.Close(rootParentFD)
	}
	if err != nil {
		return -1, "", unix.Stat_t{}, errors.New("configured file.write root is not a symlink-free directory")
	}
	defer func() { _ = unix.Close(allowedFD) }()

	parentRelative := filepath.Dir(relative)
	parentFD := -1
	if parentRelative == "." {
		parentFD, err = unix.FcntlInt(uintptr(allowedFD), unix.F_DUPFD_CLOEXEC, 0)
	} else {
		parentFD, err = unix.Openat2(allowedFD, parentRelative, &unix.OpenHow{
			Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: fileWriteResolveFlags,
		})
	}
	if err != nil {
		return -1, "", unix.Stat_t{}, errors.New("file.write parent is not a symlink-free directory beneath the allowed root")
	}
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		_ = unix.Close(parentFD)
		return -1, "", unix.Stat_t{}, errors.New("file.write parent directory identity is unavailable")
	}
	if err := validateAllowedParent(parentStat); err != nil {
		_ = unix.Close(parentFD)
		return -1, "", unix.Stat_t{}, err
	}
	return parentFD, filepath.Base(relative), parentStat, nil
}

func openRegularAt(parentFD int, base string) (*os.File, unix.Stat_t, error) {
	probeFD, err := unix.Openat(parentFD, base, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	var probe unix.Stat_t
	if err := unix.Fstat(probeFD, &probe); err != nil {
		_ = unix.Close(probeFD)
		return nil, unix.Stat_t{}, err
	}
	if probe.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(probeFD)
		return nil, unix.Stat_t{}, errors.New("file.write target must be a regular file")
	}
	// O_NONBLOCK prevents a concurrently substituted FIFO from hanging the
	// root broker before fstat can reject its type.
	fd, err := unix.Openat(parentFD, base, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = unix.Close(probeFD)
		return nil, unix.Stat_t{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(probeFD)
		_ = unix.Close(fd)
		return nil, unix.Stat_t{}, err
	}
	_ = unix.Close(probeFD)
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Dev != probe.Dev || stat.Ino != probe.Ino {
		_ = unix.Close(fd)
		return nil, unix.Stat_t{}, errors.New("file.write target changed during its type-safe open")
	}
	file := os.NewFile(uintptr(fd), base)
	if file == nil {
		_ = unix.Close(fd)
		return nil, unix.Stat_t{}, errors.New("open file.write target")
	}
	// os.File exclusively owns fd after this point.
	return file, stat, nil
}

func snapshotMatchesOpenFile(file *os.File, stat unix.Stat_t, expected allowedFileSnapshot) error {
	if !expected.Existed || uint64(stat.Dev) != expected.TargetDev || stat.Ino != expected.TargetIno ||
		uint32(stat.Mode&0o777) != expected.Mode || int(stat.Uid) != expected.UID || int(stat.Gid) != expected.GID ||
		stat.Mode&0o7111 != 0 {
		return errors.New("file.write target identity, owner, or mode changed")
	}
	digest, err := digestOpenFile(file)
	if err != nil {
		return err
	}
	if digest != expected.ContentDigest {
		return errors.New("file.write target content changed")
	}
	return nil
}

func commitMatchesOpenFile(file *os.File, stat unix.Stat_t, expected allowedFileCommit) error {
	if err := expected.validate(); err != nil {
		return err
	}
	if uint64(stat.Dev) != expected.TargetDev || stat.Ino != expected.TargetIno ||
		uint32(stat.Mode&0o777) != expected.Mode || int(stat.Uid) != expected.UID || int(stat.Gid) != expected.GID ||
		stat.Mode&0o7111 != 0 {
		return errors.New("file.write committed inode, owner, or mode changed")
	}
	digest, err := digestOpenFile(file)
	if err != nil {
		return err
	}
	if digest != expected.ContentDigest {
		return errors.New("file.write committed content changed")
	}
	return nil
}

func captureAllowedFile(path string, roots []string, backupPath string) (allowedFileSnapshot, error) {
	parentFD, base, parentStat, err := openAllowedFileParent(path, roots)
	if err != nil {
		return allowedFileSnapshot{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	snapshot := allowedFileSnapshot{ParentDev: uint64(parentStat.Dev), ParentIno: parentStat.Ino, UID: -1, GID: -1}
	target, stat, err := openRegularAt(parentFD, base)
	if errors.Is(err, unix.ENOENT) {
		return snapshot, nil
	}
	if err != nil {
		return allowedFileSnapshot{}, fmt.Errorf("open prepared file.write target: %w", err)
	}
	defer func() { _ = target.Close() }()
	if stat.Mode&0o7111 != 0 {
		return allowedFileSnapshot{}, errors.New("file.write cannot replace an executable payload")
	}
	digest, err := copyOpenFile(target, backupPath)
	if err != nil {
		return allowedFileSnapshot{}, fmt.Errorf("backup prepared file.write target: %w", err)
	}
	// Re-read the still-open inode. A writer racing the backup cannot leave an
	// inconsistent rollback image under the snapshot digest.
	stableDigest, err := digestOpenFile(target)
	if err != nil || stableDigest != digest {
		return allowedFileSnapshot{}, errors.New("file.write target changed while its backup was captured")
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(target.Fd()), &after); err != nil || after.Dev != stat.Dev || after.Ino != stat.Ino ||
		after.Mode != stat.Mode || after.Uid != stat.Uid || after.Gid != stat.Gid {
		return allowedFileSnapshot{}, errors.New("file.write target metadata changed while its backup was captured")
	}
	snapshot.Existed = true
	snapshot.Mode = stat.Mode & 0o777
	snapshot.UID, snapshot.GID = int(stat.Uid), int(stat.Gid)
	snapshot.TargetDev, snapshot.TargetIno = uint64(stat.Dev), stat.Ino
	snapshot.ContentDigest = digest
	return snapshot, nil
}

func preparedTargetStillMatches(parentFD int, base string, expected allowedFileSnapshot) error {
	target, stat, err := openRegularAt(parentFD, base)
	if !expected.Existed {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err == nil {
			_ = target.Close()
		}
		return errors.New("file.write target appeared after preparation")
	}
	if err != nil {
		return errors.New("file.write target disappeared or changed type after preparation")
	}
	defer func() { _ = target.Close() }()
	if err := snapshotMatchesOpenFile(target, stat, expected); err != nil {
		return fmt.Errorf("file.write target changed after preparation: %w", err)
	}
	return nil
}

func randomTemporaryName() (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf(".ops-agent-%x.tmp", raw[:]), nil
}

type stagedAllowedFile struct {
	file   *os.File
	name   string
	stat   unix.Stat_t
	digest string
}

func (s *stagedAllowedFile) close() error {
	if s == nil || s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *stagedAllowedFile) cleanup(parentFD int) {
	_ = s.close()
	if s == nil || s.name == "" || s.stat.Ino == 0 {
		return
	}
	// After RENAME_EXCHANGE the temporary name may refer to the displaced
	// approved object, not the staging inode. Never unlink by name unless its
	// identity still belongs to this staging object.
	var current unix.Stat_t
	if err := unix.Fstatat(parentFD, s.name, &current, unix.AT_SYMLINK_NOFOLLOW); err == nil &&
		current.Dev == s.stat.Dev && current.Ino == s.stat.Ino {
		_ = unix.Unlinkat(parentFD, s.name, 0)
	}
}

func createStagedAllowedFile(parentFD int, payload []byte, mode os.FileMode, uid, gid int) (*stagedAllowedFile, error) {
	if len(payload) > maxSecureFileBytes || mode.Perm()&0o111 != 0 {
		return nil, errors.New("file.write cannot create an oversized or executable payload")
	}
	name, err := randomTemporaryName()
	if err != nil {
		return nil, errors.New("create file.write temporary name")
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parentFD, name, 0)
		return nil, errors.New("open file.write temporary file")
	}
	staged := &stagedAllowedFile{file: file, name: name, digest: secureFilePayloadDigest(payload)}
	if err := unix.Fstat(int(file.Fd()), &staged.stat); err != nil {
		_ = staged.close()
		_ = unix.Unlinkat(parentFD, name, 0)
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			staged.cleanup(parentFD)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if uid >= 0 || gid >= 0 {
		if err := unix.Fchown(int(file.Fd()), uid, gid); err != nil {
			return nil, err
		}
	}
	if err := unix.Fchmod(int(file.Fd()), uint32(mode.Perm())); err != nil {
		return nil, err
	}
	if err := unix.Fsync(int(file.Fd())); err != nil {
		return nil, err
	}
	if err := unix.Fstat(int(file.Fd()), &staged.stat); err != nil {
		return nil, err
	}
	if staged.stat.Mode&unix.S_IFMT != unix.S_IFREG || staged.stat.Mode&0o111 != 0 {
		return nil, errors.New("file.write staging inode is not a non-executable regular file")
	}
	actualDigest, err := digestOpenFile(file)
	if err != nil || actualDigest != staged.digest {
		return nil, errors.New("file.write staging content does not match the approved payload")
	}
	ok = true
	return staged, nil
}

func parentMatches(stat unix.Stat_t, expected allowedFileSnapshot) bool {
	return uint64(stat.Dev) == expected.ParentDev && stat.Ino == expected.ParentIno
}

func validateSnapshotAt(parentFD int, base string, expected allowedFileSnapshot) error {
	file, stat, err := openRegularAt(parentFD, base)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return snapshotMatchesOpenFile(file, stat, expected)
}

func validateCommitAt(parentFD int, base string, expected allowedFileCommit) error {
	file, stat, err := openRegularAt(parentFD, base)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return commitMatchesOpenFile(file, stat, expected)
}

func restoreFailedExchange(parentFD int, stagedName, base string, cause error) error {
	if err := unix.Renameat2(parentFD, stagedName, parentFD, base, unix.RENAME_EXCHANGE); err != nil {
		return uncertainFileMutation("file.write CAS observed another object and could not restore it", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return uncertainFileMutation("file.write CAS restoration is not durable", err)
	}
	return fmt.Errorf("file.write CAS refused a changed target: %w", cause)
}

func exchangeStagedFile(parentFD int, stagedName, base string, validateDisplaced func() error) error {
	if err := unix.Renameat2(parentFD, stagedName, parentFD, base, unix.RENAME_EXCHANGE); err != nil {
		return err
	}
	if err := validateDisplaced(); err != nil {
		return restoreFailedExchange(parentFD, stagedName, base, err)
	}
	return nil
}

func stagedCommit(staged *stagedAllowedFile) allowedFileCommit {
	return allowedFileCommit{
		Version: 1, TargetDev: uint64(staged.stat.Dev), TargetIno: staged.stat.Ino,
		Mode: staged.stat.Mode & 0o777, UID: int(staged.stat.Uid), GID: int(staged.stat.Gid),
		ContentDigest: staged.digest,
	}
}

func replacePreparedAllowedFile(path string, roots []string, expected allowedFileSnapshot, payload []byte, mode os.FileMode, uid, gid int) (allowedFileCommit, error) {
	parentFD, base, parentStat, err := openAllowedFileParent(path, roots)
	if err != nil {
		return allowedFileCommit{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	if !parentMatches(parentStat, expected) {
		return allowedFileCommit{}, errors.New("file.write parent directory changed after preparation")
	}
	if err := preparedTargetStillMatches(parentFD, base, expected); err != nil {
		return allowedFileCommit{}, err
	}
	staged, err := createStagedAllowedFile(parentFD, payload, mode, uid, gid)
	if err != nil {
		return allowedFileCommit{}, err
	}
	defer staged.cleanup(parentFD)

	if expected.Existed {
		err = exchangeStagedFile(parentFD, staged.name, base, func() error {
			return validateSnapshotAt(parentFD, staged.name, expected)
		})
	} else {
		err = unix.Renameat2(parentFD, staged.name, parentFD, base, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		return allowedFileCommit{}, err
	}
	commit := stagedCommit(staged)
	if err := validateCommitAt(parentFD, base, commit); err != nil {
		return allowedFileCommit{}, uncertainFileMutation("file.write installed target failed identity verification", err)
	}
	if expected.Existed {
		if err := unix.Unlinkat(parentFD, staged.name, 0); err != nil {
			return allowedFileCommit{}, uncertainFileMutation("file.write could not remove the displaced target", err)
		}
	}
	if err := unix.Fsync(parentFD); err != nil {
		return allowedFileCommit{}, uncertainFileMutation("file.write directory commit is not durable", err)
	}
	if err := staged.close(); err != nil {
		return allowedFileCommit{}, uncertainFileMutation("file.write installed inode close failed", err)
	}
	return commit, nil
}

func readCommittedAllowedFile(path string, roots []string, expected allowedFileSnapshot, commit allowedFileCommit) ([]byte, os.FileMode, error) {
	parentFD, base, parentStat, err := openAllowedFileParent(path, roots)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	if !parentMatches(parentStat, expected) {
		return nil, 0, errors.New("file.write parent directory changed")
	}
	target, stat, err := openRegularAt(parentFD, base)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = target.Close() }()
	if err := commitMatchesOpenFile(target, stat, commit); err != nil {
		return nil, 0, err
	}
	if _, err := target.Seek(0, 0); err != nil {
		return nil, 0, err
	}
	payload, err := io.ReadAll(io.LimitReader(target, maxSecureFileBytes+1))
	if err != nil || len(payload) > maxSecureFileBytes {
		return nil, 0, errors.New("read bounded file.write result")
	}
	return payload, os.FileMode(stat.Mode & 0o777), nil
}

func inspectLegacyAllowedFile(
	path string,
	roots []string,
	expectedContentDigest string,
	expectedMode uint32,
	rollback legacyFileRollback,
	backupPath string,
) (legacyFileRecoveryProof, error) {
	parentFD, base, parentStat, err := openAllowedFileParent(path, roots)
	if err != nil {
		return legacyFileRecoveryProof{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	target, stat, err := openRegularAt(parentFD, base)
	if err != nil {
		return legacyFileRecoveryProof{}, errors.New("legacy file.write result is missing or not a regular file")
	}
	defer func() { _ = target.Close() }()
	if stat.Mode&0o7111 != 0 || uint32(stat.Mode&0o777) != expectedMode {
		return legacyFileRecoveryProof{}, errors.New("legacy file.write result mode is not the exact expected non-executable mode")
	}
	if rollback.Existed {
		if int(stat.Uid) != rollback.UID || int(stat.Gid) != rollback.GID {
			return legacyFileRecoveryProof{}, errors.New("legacy file.write result owner differs from its persisted restore owner")
		}
	} else if stat.Uid != secureLegacyFileRequiredUID || stat.Gid != secureLegacyFileRequiredGID {
		return legacyFileRecoveryProof{}, errors.New("legacy newly-created file.write result is not root:root-owned")
	}
	contentDigest, err := digestOpenFile(target)
	if err != nil || contentDigest != expectedContentDigest {
		return legacyFileRecoveryProof{}, errors.New("legacy file.write result does not exactly match the originally approved content")
	}
	commit := allowedFileCommit{
		Version: 1, TargetDev: uint64(stat.Dev), TargetIno: stat.Ino,
		Mode: uint32(stat.Mode & 0o777), UID: int(stat.Uid), GID: int(stat.Gid),
		ContentDigest: contentDigest,
	}
	proof := legacyFileRecoveryProof{
		Rollback: rollback,
		Snapshot: allowedFileSnapshot{
			Existed: rollback.Existed, Mode: rollback.Mode, UID: rollback.UID, GID: rollback.GID,
			ParentDev: uint64(parentStat.Dev), ParentIno: parentStat.Ino,
		},
		Commit: commit,
	}
	if !rollback.Existed {
		return proof, nil
	}
	backupFD, err := unix.Open(backupPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return legacyFileRecoveryProof{}, errors.New("open exact legacy file backup object")
	}
	backup := os.NewFile(uintptr(backupFD), filepath.Base(backupPath))
	if backup == nil {
		_ = unix.Close(backupFD)
		return legacyFileRecoveryProof{}, errors.New("open legacy file backup object")
	}
	defer func() { _ = backup.Close() }()
	var backupStat unix.Stat_t
	if err := unix.Fstat(int(backup.Fd()), &backupStat); err != nil || backupStat.Mode&unix.S_IFMT != unix.S_IFREG ||
		backupStat.Uid != secureLegacyFileRequiredUID || backupStat.Gid != secureLegacyFileRequiredGID || backupStat.Mode&0o7777 != 0o600 ||
		backupStat.Size < 0 || backupStat.Size > maxSecureFileBytes {
		return legacyFileRecoveryProof{}, errors.New("legacy file backup object has an unsafe type, owner, mode, or size")
	}
	payload, err := io.ReadAll(io.LimitReader(backup, maxSecureFileBytes+1))
	if err != nil || len(payload) > maxSecureFileBytes {
		return legacyFileRecoveryProof{}, errors.New("read bounded legacy file backup object")
	}
	proof.BackupPath = backupPath
	proof.Backup = payload
	proof.BackupDigest = secureFilePayloadDigest(payload)
	proof.Snapshot.ContentDigest = proof.BackupDigest
	return proof, nil
}

func restoreAllowedFile(path string, roots []string, expected allowedFileSnapshot, commit allowedFileCommit, backup []byte) error {
	parentFD, base, parentStat, err := openAllowedFileParent(path, roots)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	if !parentMatches(parentStat, expected) {
		return errors.New("file.write parent directory changed before rollback")
	}
	if err := validateCommitAt(parentFD, base, commit); err != nil {
		return errors.New("file.write result changed after commit; refusing rollback")
	}
	if secureFilePayloadDigest(backup) != expected.ContentDigest {
		return errors.New("file.write rollback backup does not match its prepared digest")
	}
	staged, err := createStagedAllowedFile(parentFD, backup, os.FileMode(expected.Mode), expected.UID, expected.GID)
	if err != nil {
		return err
	}
	defer staged.cleanup(parentFD)
	if err := exchangeStagedFile(parentFD, staged.name, base, func() error {
		return validateCommitAt(parentFD, staged.name, commit)
	}); err != nil {
		return err
	}
	restoredCommit := stagedCommit(staged)
	if err := validateCommitAt(parentFD, base, restoredCommit); err != nil {
		return uncertainFileMutation("file.write restored target failed identity verification", err)
	}
	if err := unix.Unlinkat(parentFD, staged.name, 0); err != nil {
		return uncertainFileMutation("file.write could not remove the rolled-back inode", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return uncertainFileMutation("file.write rollback directory commit is not durable", err)
	}
	if err := staged.close(); err != nil {
		return uncertainFileMutation("file.write restored inode close failed", err)
	}
	return nil
}

func restoreMovedRollbackTarget(parentFD int, temporary, base string, cause error) error {
	if err := unix.Renameat2(parentFD, temporary, parentFD, base, unix.RENAME_NOREPLACE); err != nil {
		return uncertainFileMutation("file.write rollback moved another inode and could not restore it", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return uncertainFileMutation("file.write rollback CAS restoration is not durable", err)
	}
	return fmt.Errorf("file.write rollback CAS refused a changed target: %w", cause)
}

func removeAllowedFile(path string, roots []string, expected allowedFileSnapshot, commit allowedFileCommit) error {
	parentFD, base, parentStat, err := openAllowedFileParent(path, roots)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	if !parentMatches(parentStat, expected) {
		return errors.New("file.write parent directory changed before rollback")
	}
	if err := validateCommitAt(parentFD, base, commit); err != nil {
		return errors.New("file.write result changed after commit; refusing rollback")
	}
	temporary, err := randomTemporaryName()
	if err != nil {
		return err
	}
	if err := unix.Renameat2(parentFD, base, parentFD, temporary, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err := validateCommitAt(parentFD, temporary, commit); err != nil {
		return restoreMovedRollbackTarget(parentFD, temporary, base, err)
	}
	if err := unix.Unlinkat(parentFD, temporary, 0); err != nil {
		return uncertainFileMutation("file.write could not remove the committed inode during rollback", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return uncertainFileMutation("file.write removal rollback is not durable", err)
	}
	return nil
}
