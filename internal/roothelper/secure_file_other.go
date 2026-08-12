//go:build !linux

package roothelper

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Non-Linux support exists only so protocol/unit tests can run on developer
// workstations. Production is Linux/systemd and uses openat2 plus renameat2 CAS
// in secure_file_linux.go.
func portableIdentity(info os.FileInfo) (uint64, uint64, int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, -1, -1, errors.New("filesystem identity is unavailable")
	}
	return uint64(stat.Dev), uint64(stat.Ino), int(stat.Uid), int(stat.Gid), nil
}

func portableResolvedParent(path string, roots []string) (string, os.FileInfo, error) {
	root, _, err := selectAllowedFileRoot(path, roots)
	if err != nil {
		return "", nil, err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", nil, err
	}
	relative, err := filepath.Rel(resolvedRoot, parent)
	if err != nil || relative == ".." || (len(relative) > 3 && relative[:3] == ".."+string(filepath.Separator)) {
		return "", nil, errors.New("file.write parent escapes the allowed root")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return "", nil, errors.New("file.write parent is not a directory")
	}
	_, _, uid, _, identityErr := portableIdentity(info)
	if identityErr != nil || uint32(uid) != secureFileRequiredParentUID || info.Mode().Perm()&0o022 != 0 {
		return "", nil, errors.New("file.write parent must be a root-owned directory that is not group/world writable")
	}
	return parent, info, nil
}

func captureAllowedFile(path string, roots []string, backupPath string) (allowedFileSnapshot, error) {
	_, parentInfo, err := portableResolvedParent(path, roots)
	if err != nil {
		return allowedFileSnapshot{}, err
	}
	parentDev, parentIno, _, _, err := portableIdentity(parentInfo)
	if err != nil {
		return allowedFileSnapshot{}, err
	}
	snapshot := allowedFileSnapshot{ParentDev: parentDev, ParentIno: parentIno, UID: -1, GID: -1}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return allowedFileSnapshot{}, errors.New("file.write target must be a regular file")
	}
	if info.Mode().Perm()&0o111 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return allowedFileSnapshot{}, errors.New("file.write cannot replace an executable payload")
	}
	dev, ino, uid, gid, err := portableIdentity(info)
	if err != nil {
		return allowedFileSnapshot{}, err
	}
	target, err := os.Open(path)
	if err != nil {
		return allowedFileSnapshot{}, err
	}
	defer func() { _ = target.Close() }()
	openedInfo, err := target.Stat()
	if err != nil {
		return allowedFileSnapshot{}, err
	}
	openedDev, openedIno, openedUID, openedGID, err := portableIdentity(openedInfo)
	if err != nil || openedDev != dev || openedIno != ino || openedUID != uid || openedGID != gid || openedInfo.Mode().Perm() != info.Mode().Perm() {
		return allowedFileSnapshot{}, errors.New("file.write target changed while it was opened")
	}
	digest, err := copyOpenFile(target, backupPath)
	if err != nil {
		return allowedFileSnapshot{}, err
	}
	stableDigest, err := digestOpenFile(target)
	if err != nil || stableDigest != digest {
		return allowedFileSnapshot{}, errors.New("file.write target changed while its backup was captured")
	}
	snapshot.Existed, snapshot.Mode, snapshot.UID, snapshot.GID = true, uint32(info.Mode().Perm()), uid, gid
	snapshot.TargetDev, snapshot.TargetIno, snapshot.ContentDigest = dev, ino, digest
	return snapshot, nil
}

func portableParentMatches(path string, roots []string, expected allowedFileSnapshot) error {
	_, info, err := portableResolvedParent(path, roots)
	if err != nil {
		return err
	}
	dev, ino, _, _, err := portableIdentity(info)
	if err != nil || dev != expected.ParentDev || ino != expected.ParentIno {
		return errors.New("file.write parent directory changed after preparation")
	}
	return nil
}

func portableSnapshotMatches(path string, expected allowedFileSnapshot) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("file.write target disappeared or changed type")
	}
	dev, ino, uid, gid, err := portableIdentity(info)
	if err != nil || dev != expected.TargetDev || ino != expected.TargetIno || uid != expected.UID || gid != expected.GID ||
		uint32(info.Mode().Perm()) != expected.Mode {
		return errors.New("file.write target identity, owner, or mode changed")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	digest, err := digestOpenFile(file)
	if err != nil || digest != expected.ContentDigest {
		return errors.New("file.write target content changed")
	}
	return nil
}

func portableCommit(path string) (allowedFileCommit, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return allowedFileCommit{}, errors.New("file.write result is unavailable or executable")
	}
	dev, ino, uid, gid, err := portableIdentity(info)
	if err != nil {
		return allowedFileCommit{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return allowedFileCommit{}, err
	}
	defer func() { _ = file.Close() }()
	digest, err := digestOpenFile(file)
	if err != nil {
		return allowedFileCommit{}, err
	}
	return allowedFileCommit{
		Version: 1, TargetDev: dev, TargetIno: ino, Mode: uint32(info.Mode().Perm()),
		UID: uid, GID: gid, ContentDigest: digest,
	}, nil
}

func replacePreparedAllowedFile(path string, roots []string, expected allowedFileSnapshot, payload []byte, mode os.FileMode, uid, gid int) (allowedFileCommit, error) {
	if len(payload) > maxSecureFileBytes || mode.Perm()&0o111 != 0 {
		return allowedFileCommit{}, errors.New("file.write cannot create an oversized or executable payload")
	}
	if err := portableParentMatches(path, roots, expected); err != nil {
		return allowedFileCommit{}, err
	}
	if expected.Existed {
		if err := portableSnapshotMatches(path, expected); err != nil {
			return allowedFileCommit{}, err
		}
	} else if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return allowedFileCommit{}, errors.New("file.write target appeared after preparation")
	}
	if err := atomicReplace(path, payload, mode, uid, gid); err != nil {
		return allowedFileCommit{}, err
	}
	commit, err := portableCommit(path)
	if err != nil {
		return allowedFileCommit{}, uncertainFileMutation("file.write installed target failed identity verification", err)
	}
	return commit, nil
}

func portableCommitMatches(path string, expected allowedFileCommit) error {
	current, err := portableCommit(path)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("file.write committed inode, owner, mode, or content changed")
	}
	return nil
}

func readCommittedAllowedFile(path string, roots []string, expected allowedFileSnapshot, commit allowedFileCommit) ([]byte, os.FileMode, error) {
	if err := portableParentMatches(path, roots, expected); err != nil {
		return nil, 0, err
	}
	if err := portableCommitMatches(path, commit); err != nil {
		return nil, 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	target, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = target.Close() }()
	payload, err := io.ReadAll(io.LimitReader(target, maxSecureFileBytes+1))
	if err != nil || len(payload) > maxSecureFileBytes {
		return nil, 0, errors.New("read bounded file.write result")
	}
	return payload, info.Mode().Perm(), nil
}

func inspectLegacyAllowedFile(
	path string,
	roots []string,
	expectedContentDigest string,
	expectedMode uint32,
	rollback legacyFileRollback,
	backupPath string,
) (legacyFileRecoveryProof, error) {
	_, parentInfo, err := portableResolvedParent(path, roots)
	if err != nil {
		return legacyFileRecoveryProof{}, err
	}
	parentDev, parentIno, _, _, err := portableIdentity(parentInfo)
	if err != nil {
		return legacyFileRecoveryProof{}, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || uint32(info.Mode().Perm()) != expectedMode {
		return legacyFileRecoveryProof{}, errors.New("legacy file.write result has an unsafe type or unexpected mode")
	}
	dev, ino, uid, gid, err := portableIdentity(info)
	if err != nil {
		return legacyFileRecoveryProof{}, err
	}
	if rollback.Existed {
		if uid != rollback.UID || gid != rollback.GID {
			return legacyFileRecoveryProof{}, errors.New("legacy file.write result owner differs from its persisted restore owner")
		}
	} else if uint32(uid) != secureLegacyFileRequiredUID || uint32(gid) != secureLegacyFileRequiredGID {
		return legacyFileRecoveryProof{}, errors.New("legacy newly-created file.write result is not root:root-owned")
	}
	target, err := os.Open(path)
	if err != nil {
		return legacyFileRecoveryProof{}, err
	}
	defer func() { _ = target.Close() }()
	openedInfo, err := target.Stat()
	if err != nil {
		return legacyFileRecoveryProof{}, err
	}
	openedDev, openedIno, openedUID, openedGID, err := portableIdentity(openedInfo)
	if err != nil || openedDev != dev || openedIno != ino || openedUID != uid || openedGID != gid || openedInfo.Mode() != info.Mode() {
		return legacyFileRecoveryProof{}, errors.New("legacy file.write result changed during its type-safe open")
	}
	contentDigest, err := digestOpenFile(target)
	if err != nil || contentDigest != expectedContentDigest {
		return legacyFileRecoveryProof{}, errors.New("legacy file.write result does not exactly match the originally approved content")
	}
	commit := allowedFileCommit{
		Version: 1, TargetDev: dev, TargetIno: ino, Mode: uint32(info.Mode().Perm()),
		UID: uid, GID: gid, ContentDigest: contentDigest,
	}
	proof := legacyFileRecoveryProof{
		Rollback: rollback,
		Snapshot: allowedFileSnapshot{
			Existed: rollback.Existed, Mode: rollback.Mode, UID: rollback.UID, GID: rollback.GID,
			ParentDev: parentDev, ParentIno: parentIno,
		},
		Commit: commit,
	}
	if !rollback.Existed {
		return proof, nil
	}
	backupInfo, err := os.Lstat(backupPath)
	if err != nil || !backupInfo.Mode().IsRegular() || backupInfo.Mode().Perm() != 0o600 ||
		backupInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || backupInfo.Size() < 0 || backupInfo.Size() > maxSecureFileBytes {
		return legacyFileRecoveryProof{}, errors.New("legacy file backup object has an unsafe type, mode, or size")
	}
	_, _, backupUID, backupGID, err := portableIdentity(backupInfo)
	if err != nil || uint32(backupUID) != secureLegacyFileRequiredUID || uint32(backupGID) != secureLegacyFileRequiredGID {
		return legacyFileRecoveryProof{}, errors.New("legacy file backup object has an unsafe owner")
	}
	backup, err := os.Open(backupPath)
	if err != nil {
		return legacyFileRecoveryProof{}, err
	}
	defer func() { _ = backup.Close() }()
	openedBackupInfo, err := backup.Stat()
	if err != nil || !os.SameFile(backupInfo, openedBackupInfo) {
		return legacyFileRecoveryProof{}, errors.New("legacy file backup object changed during its type-safe open")
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
	if err := portableParentMatches(path, roots, expected); err != nil {
		return err
	}
	if err := portableCommitMatches(path, commit); err != nil {
		return errors.New("file.write result changed after commit; refusing rollback")
	}
	if secureFilePayloadDigest(backup) != expected.ContentDigest {
		return errors.New("file.write rollback backup does not match its prepared digest")
	}
	if err := atomicReplace(path, backup, os.FileMode(expected.Mode), expected.UID, expected.GID); err != nil {
		return err
	}
	return nil
}

func removeAllowedFile(path string, roots []string, expected allowedFileSnapshot, commit allowedFileCommit) error {
	if err := portableParentMatches(path, roots, expected); err != nil {
		return err
	}
	if err := portableCommitMatches(path, commit); err != nil {
		return errors.New("file.write result changed after commit; refusing rollback")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncSecureDirectory(filepath.Dir(path))
}
