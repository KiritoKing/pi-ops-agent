//go:build linux

package jsonconfighelper

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const secureResolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS

type linuxHooks struct {
	fsync          func(int) error
	renameExchange func(int, string, int, string) error
	beforeExchange func()
	afterExchange  func()
}

func productionLinuxHooks() linuxHooks {
	return linuxHooks{
		fsync: unix.Fsync,
		renameExchange: func(oldDirectory int, oldName string, newDirectory int, newName string) error {
			return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, unix.RENAME_EXCHANGE)
		},
		beforeExchange: func() {},
		afterExchange:  func() {},
	}
}

type openedDocument struct {
	file     *os.File
	stat     unix.Stat_t
	payload  []byte
	document parsedDocument
	metadata fileMetadata
}

func (document *openedDocument) close() {
	if document != nil && document.file != nil {
		_ = document.file.Close()
		document.file = nil
	}
}

func inspectPlatform(options inspectOptions) (inspectProof, error) {
	uid, err := nonRootUID()
	if err != nil {
		return inspectProof{}, err
	}
	parentFD, base, err := openConfigParent(options.Home, options.Relative, uid)
	if err != nil {
		return inspectProof{}, err
	}
	defer unix.Close(parentFD)
	document, err := openDocumentAt(parentFD, base, uid)
	if err != nil {
		return inspectProof{}, err
	}
	defer document.close()
	selected, err := document.document.selectValue(options.SelectorKey, options.SelectorValue, options.Field)
	if err != nil {
		return inspectProof{}, err
	}
	return inspectProof{Version: 1, Operation: "inspect", Source: document.metadata, Selected: selected}, nil
}

type inspectDirectoryHooks struct {
	afterInitialOpen func()
}

func productionInspectDirectoryHooks() inspectDirectoryHooks {
	return inspectDirectoryHooks{afterInitialOpen: func() {}}
}

func inspectDirectoryPlatform(options inspectDirectoryOptions) (inspectDirectoryProof, error) {
	return inspectDirectoryWithHooks(options, productionInspectDirectoryHooks())
}

func inspectDirectoryWithHooks(options inspectDirectoryOptions, hooks inspectDirectoryHooks) (inspectDirectoryProof, error) {
	if _, err := nonRootUID(); err != nil {
		return inspectDirectoryProof{}, err
	}
	if err := options.validate(); err != nil {
		return inspectDirectoryProof{}, err
	}
	if hooks.afterInitialOpen == nil {
		return inspectDirectoryProof{}, errors.New("inspect-directory race hook is unavailable")
	}

	rootFD, rootBefore, err := openInspectableAbsoluteDirectory(options.Root)
	if err != nil {
		return inspectDirectoryProof{}, err
	}
	defer unix.Close(rootFD)
	directoryFD, directoryBefore, err := openInspectableDirectoryBeneath(rootFD, options.Root, options.Path)
	if err != nil {
		return inspectDirectoryProof{}, err
	}
	defer unix.Close(directoryFD)

	// Re-resolve both policy pathnames after the first observation. This makes
	// root, final-component, and intermediate rename swaps detectable. A writer
	// with this UID can still race after the final observation, which is stated
	// explicitly in the proof.
	hooks.afterInitialOpen()
	var rootAfter, directoryAfter unix.Stat_t
	if err := unix.Fstat(rootFD, &rootAfter); err != nil || !sameInspectableDirectory(rootBefore, rootAfter) {
		return inspectDirectoryProof{}, errors.New("directory root identity changed during inspection")
	}
	if err := unix.Fstat(directoryFD, &directoryAfter); err != nil ||
		!sameInspectableDirectory(directoryBefore, directoryAfter) {
		return inspectDirectoryProof{}, errors.New("selected directory identity changed during inspection")
	}

	reopenedRootFD, reopenedRoot, err := openInspectableAbsoluteDirectory(options.Root)
	if err != nil {
		return inspectDirectoryProof{}, errors.New("reopen directory root after inspection")
	}
	defer unix.Close(reopenedRootFD)
	reopenedDirectoryFD, reopenedDirectory, err := openInspectableDirectoryBeneath(
		reopenedRootFD,
		options.Root,
		options.Path,
	)
	if err != nil {
		return inspectDirectoryProof{}, errors.New("reopen selected directory after inspection")
	}
	defer unix.Close(reopenedDirectoryFD)
	if !sameInspectableDirectory(rootAfter, reopenedRoot) {
		return inspectDirectoryProof{}, errors.New("directory root pathname changed during inspection")
	}
	if !sameInspectableDirectory(directoryAfter, reopenedDirectory) {
		return inspectDirectoryProof{}, errors.New("selected directory pathname changed during inspection")
	}

	return inspectDirectoryProof{
		Version:   1,
		Operation: "inspect-directory",
		Root:      inspectDirectoryMetadata(reopenedRoot),
		Directory: inspectDirectoryMetadata(reopenedDirectory),
		// The proof binds the pathnames to exact directory identities at this
		// observation, but it cannot prove the write permissions of every parent
		// namespace remain unchanged afterwards. Do not narrow this residual risk
		// to the target UID: another locally-authorized pathname writer may exist.
		ResidualRisk: "pathname_may_be_replaced_after_verification",
	}, nil
}

func openInspectableAbsoluteDirectory(path string) (int, unix.Stat_t, error) {
	filesystemRootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, errors.New("open filesystem root for directory inspection")
	}
	defer unix.Close(filesystemRootFD)

	var fd int
	if path == string(filepath.Separator) {
		fd, err = unix.FcntlInt(uintptr(filesystemRootFD), unix.F_DUPFD_CLOEXEC, 0)
	} else {
		fd, err = unix.Openat2(filesystemRootFD, strings.TrimPrefix(path, string(filepath.Separator)), &unix.OpenHow{
			Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
			Resolve: secureResolveFlags,
		})
	}
	if err != nil {
		return -1, unix.Stat_t{}, errors.New("open symlink-free absolute directory for inspection")
	}
	stat, err := inspectOpenedDirectory(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	return fd, stat, nil
}

func openInspectableDirectoryBeneath(rootFD int, root, path string) (int, unix.Stat_t, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return -1, unix.Stat_t{}, errors.New("selected directory escapes its root")
	}
	var fd int
	if relative == "." {
		fd, err = unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	} else {
		fd, err = unix.Openat2(rootFD, relative, &unix.OpenHow{
			Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
			Resolve: secureResolveFlags,
		})
	}
	if err != nil {
		return -1, unix.Stat_t{}, errors.New("open symlink-free selected directory beneath root")
	}
	stat, err := inspectOpenedDirectory(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, err
	}
	return fd, stat, nil
}

func inspectOpenedDirectory(fd int) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unix.Stat_t{}, errors.New("inspect opened directory identity")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Stat_t{}, errors.New("opened path is not a directory")
	}
	return stat, nil
}

func sameInspectableDirectory(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Uid == right.Uid && left.Gid == right.Gid
}

func inspectDirectoryMetadata(stat unix.Stat_t) directoryMetadata {
	return directoryMetadata{
		Dev: uint64(stat.Dev), Ino: stat.Ino, Mode: stat.Mode & 0o7777, UID: stat.Uid, GID: stat.Gid,
	}
}

func snapshotPlatform(options snapshotOptions) (snapshotProof, error) {
	return snapshotWithHooks(options, productionLinuxHooks())
}

func snapshotWithHooks(options snapshotOptions, hooks linuxHooks) (snapshotProof, error) {
	uid, err := nonRootUID()
	if err != nil {
		return snapshotProof{}, err
	}
	if hooks.fsync == nil {
		return snapshotProof{}, errors.New("snapshot durability hook is unavailable")
	}
	configParentFD, base, err := openConfigParent(options.Home, options.Relative, uid)
	if err != nil {
		return snapshotProof{}, err
	}
	defer unix.Close(configParentFD)
	source, err := openDocumentAt(configParentFD, base, uid)
	if err != nil {
		return snapshotProof{}, err
	}
	defer source.close()
	selected, err := source.document.selectValue(options.SelectorKey, options.SelectorValue, options.Field)
	if err != nil {
		return snapshotProof{}, err
	}

	stageParentFD, outputBase, err := openStageParent(options.StageRoot, options.Output, uid)
	if err != nil {
		return snapshotProof{}, err
	}
	defer unix.Close(stageParentFD)
	snapshot, err := createExclusiveDocument(stageParentFD, outputBase, source.payload, 0o600, uid, hooks)
	if err != nil {
		return snapshotProof{}, err
	}
	snapshot.close()
	return snapshotProof{
		Version: 1, Operation: "snapshot", Source: source.metadata, Snapshot: snapshot.metadata, Selected: selected,
	}, nil
}

func mutatePlatform(options mutateOptions) (mutateProof, error) {
	return mutateWithHooks(options, productionLinuxHooks())
}

func mutateWithHooks(options mutateOptions, hooks linuxHooks) (mutateProof, error) {
	uid, err := nonRootUID()
	if err != nil {
		return mutateProof{}, err
	}
	if hooks.fsync == nil {
		return mutateProof{}, errors.New("mutate durability hook is unavailable")
	}
	configParentFD, base, err := openConfigParent(options.Home, options.Relative, uid)
	if err != nil {
		return mutateProof{}, err
	}
	defer unix.Close(configParentFD)
	source, err := openDocumentAt(configParentFD, base, uid)
	if err != nil {
		return mutateProof{}, err
	}
	defer source.close()
	payload, before, after, err := source.document.rewriteOneField(
		options.SelectorKey,
		options.SelectorValue,
		options.Field,
		options.Value,
	)
	if err != nil {
		return mutateProof{}, err
	}

	stageParentFD, outputBase, err := openStageParent(options.StageRoot, options.Output, uid)
	if err != nil {
		return mutateProof{}, err
	}
	defer unix.Close(stageParentFD)
	output, err := createExclusiveDocument(stageParentFD, outputBase, payload, 0o600, uid, hooks)
	if err != nil {
		return mutateProof{}, err
	}
	keepOutput := false
	defer func() {
		output.close()
		if !keepOutput {
			unlinkIfIdentity(stageParentFD, outputBase, output.stat)
		}
	}()

	// A same-UID writer can race any observation. Reopen both pathnames after
	// the durable output is created so a race during generation is rejected;
	// the returned digests remain the CAS inputs for the caller.
	currentSource, err := openDocumentAt(configParentFD, base, uid)
	if err != nil {
		return mutateProof{}, errors.New("reopen source after staged mutation")
	}
	defer currentSource.close()
	if !sameFileIdentity(currentSource.stat, source.stat) || currentSource.metadata.SHA256 != source.metadata.SHA256 {
		return mutateProof{}, errors.New("source changed while generating staged mutation")
	}
	currentOutput, err := openDocumentAt(stageParentFD, outputBase, uid)
	if err != nil {
		return mutateProof{}, errors.New("reopen staged mutation output")
	}
	defer currentOutput.close()
	selectedOutput, err := currentOutput.document.selectValue(options.SelectorKey, options.SelectorValue, options.Field)
	if err != nil || !sameFileIdentity(currentOutput.stat, output.stat) ||
		!sameSafeValue(selectedOutput, after) || currentOutput.metadata.SHA256 != output.metadata.SHA256 ||
		currentOutput.metadata.SHA256 == source.metadata.SHA256 {
		return mutateProof{}, errors.New("staged mutation failed exact typed verification")
	}
	keepOutput = true
	return mutateProof{
		Version: 1, Operation: "mutate", WholeDocumentRewrite: true,
		Source: source.metadata, Output: output.metadata,
		BeforeDigest: source.metadata.SHA256, AfterDigest: output.metadata.SHA256,
		Before: before, After: after,
	}, nil
}

func commitPlatform(options commitOptions) (CommitProof, error) {
	return commitWithHooks(options, productionLinuxHooks())
}

func commitWithHooks(options commitOptions, hooks linuxHooks) (CommitProof, error) {
	uid, err := nonRootUID()
	if err != nil {
		return CommitProof{}, err
	}
	if hooks.fsync == nil || hooks.renameExchange == nil || hooks.beforeExchange == nil || hooks.afterExchange == nil {
		return CommitProof{}, errors.New("commit system-call hooks are unavailable")
	}
	baseProof := CommitProof{
		Version: 1, Operation: options.Operation, Outcome: "refused_before_exchange",
		ResidualState: "no_mutation_observed", CASMethod: "rename_exchange_then_validate",
	}

	stageParentFD, stagedBase, err := openStageParent(options.StageRoot, options.Staged, uid)
	if err != nil {
		return CommitProof{}, err
	}
	staged, err := openDocumentAt(stageParentFD, stagedBase, uid)
	_ = unix.Close(stageParentFD)
	if err != nil {
		return CommitProof{}, err
	}
	defer staged.close()
	if staged.metadata.SHA256 != options.ExpectedAfter {
		return baseProof, errors.New("staged document does not match expected-after digest")
	}

	configParentFD, configBase, err := openConfigParent(options.Home, options.Relative, uid)
	if err != nil {
		return CommitProof{}, err
	}
	defer unix.Close(configParentFD)
	current, err := openDocumentAt(configParentFD, configBase, uid)
	if err != nil {
		return CommitProof{}, err
	}
	defer current.close()
	if current.metadata.SHA256 == options.ExpectedAfter {
		proof := baseProof
		proof.Outcome = "already_after"
		proof.ResidualState = "same_uid_writers_may_race_after_verification"
		proof.Current = metadataPointer(current.metadata)
		return proof, nil
	}
	if current.metadata.SHA256 != options.ExpectedBefore {
		return baseProof, errors.New("current document does not match expected-before digest")
	}

	temporaryName, err := randomTemporaryName()
	if err != nil {
		return baseProof, err
	}
	installed, err := createTemporaryDocument(configParentFD, temporaryName, staged.payload, current.metadata.Mode, uid, hooks)
	if err != nil {
		return baseProof, err
	}
	defer installed.close()
	temporaryExists := true
	mutationAttempted := false
	defer func() {
		if !mutationAttempted && temporaryExists {
			unlinkIfIdentity(configParentFD, temporaryName, installed.stat)
		}
	}()

	// Persist the fully-written temporary inode before it participates in the
	// exchange. The post-exchange directory fsync below is still authoritative.
	if err := hooks.fsync(configParentFD); err != nil {
		return baseProof, errors.New("persist pre-exchange directory entry")
	}
	hooks.beforeExchange()
	if err := hooks.renameExchange(configParentFD, temporaryName, configParentFD, configBase); err != nil {
		baseStat, baseErr := lstatAt(configParentFD, configBase)
		temporaryStat, temporaryErr := lstatAt(configParentFD, temporaryName)
		if baseErr != nil || temporaryErr != nil || !sameObject(baseStat, current.stat) ||
			!sameObject(temporaryStat, installed.stat) {
			proof := baseProof
			proof.MutationAttempted = true
			proof.Outcome = "outcome_uncertain"
			proof.ResidualState = "unknown"
			mutationAttempted = true
			return proof, errors.New("exchange returned an error with changed path identities")
		}
		return baseProof, errors.New("atomically exchange staged and current documents")
	}
	mutationAttempted = true
	hooks.afterExchange()

	proof := baseProof
	proof.MutationAttempted = true
	proof.Outcome = "outcome_uncertain"
	proof.ResidualState = "unknown"
	baseStat, baseErr := lstatAt(configParentFD, configBase)
	displacedStat, displacedStatErr := lstatAt(configParentFD, temporaryName)
	if baseErr != nil || displacedStatErr != nil || !sameObject(baseStat, installed.stat) {
		return proof, errors.New("exchange path identities changed before validation")
	}
	installedAfter, installedErr := refreshOpenDocument(installed.file, uid)
	displacedAfter, displacedErr := openDocumentAt(configParentFD, temporaryName, uid)
	displacedMatches := displacedErr == nil && sameObject(displacedAfter.stat, displacedStat) &&
		displacedAfter.metadata.SHA256 == options.ExpectedBefore
	if displacedAfter != nil {
		displacedAfter.close()
	}
	if installedErr != nil || !displacedMatches || installedAfter.metadata.SHA256 != options.ExpectedAfter ||
		!sameFileIdentity(installedAfter.stat, installed.stat) {
		restoredProof, restoreErr := restoreExchange(
			options.Operation, configParentFD, configBase, temporaryName, installed.stat, displacedStat,
			uid, hooks,
		)
		temporaryExists = restoredProof.ResidualState != "exchange_restored_at_verification"
		if restoreErr != nil {
			return restoredProof, restoreErr
		}
		return restoredProof, errors.New("CAS rejected a changed current document and restored the exchange")
	}

	// First make the exchange itself durable while the displaced object remains
	// available under the temporary name for recovery.
	if err := hooks.fsync(configParentFD); err != nil {
		return proof, errors.New("exchange durability is uncertain")
	}
	if err := unlinkExactIdentity(configParentFD, temporaryName, displacedStat); err != nil {
		return proof, errors.New("committed exchange retained an unexpected displaced entry")
	}
	temporaryExists = false
	if err := hooks.fsync(configParentFD); err != nil {
		return proof, errors.New("displaced-entry cleanup durability is uncertain")
	}
	finalDocument, err := openDocumentAt(configParentFD, configBase, uid)
	if err != nil || finalDocument.metadata.SHA256 != options.ExpectedAfter ||
		!sameFileIdentity(finalDocument.stat, installed.stat) {
		if finalDocument != nil {
			finalDocument.close()
		}
		return proof, errors.New("committed document failed final verification")
	}
	proof.Outcome = "committed"
	proof.ResidualState = "same_uid_writers_may_race_after_verification"
	proof.Current = metadataPointer(finalDocument.metadata)
	finalDocument.close()
	return proof, nil
}

func restoreExchange(
	operation string,
	parentFD int,
	base, temporaryName string,
	installedIdentity, displacedIdentity unix.Stat_t,
	uid uint32,
	hooks linuxHooks,
) (CommitProof, error) {
	proof := CommitProof{
		Version: 1, Operation: operation, Outcome: "outcome_uncertain", MutationAttempted: true,
		ResidualState: "unknown", CASMethod: "rename_exchange_then_validate",
	}
	if err := verifyExchangePaths(parentFD, base, temporaryName, installedIdentity, displacedIdentity); err != nil {
		return proof, errors.New("cannot safely restore changed exchange path identities")
	}
	if err := hooks.renameExchange(parentFD, temporaryName, parentFD, base); err != nil {
		return proof, errors.New("failed to restore rejected exchange")
	}
	proof.ExchangeRestored = true
	if err := hooks.fsync(parentFD); err != nil {
		return proof, errors.New("restored exchange durability is uncertain")
	}
	restoredStat, restoredErr := lstatAt(parentFD, base)
	if restoredErr != nil || !sameObject(restoredStat, displacedIdentity) {
		return proof, errors.New("restored document failed verification")
	}
	rejectedStat, rejectedErr := lstatAt(parentFD, temporaryName)
	if rejectedErr != nil || !sameObject(rejectedStat, installedIdentity) {
		return proof, errors.New("rejected staging entry changed during restoration")
	}
	if err := unlinkExactIdentity(parentFD, temporaryName, installedIdentity); err != nil {
		return proof, errors.New("restored exchange retained an unexpected staging entry")
	}
	if err := hooks.fsync(parentFD); err != nil {
		return proof, errors.New("restored staging cleanup durability is uncertain")
	}
	restoredDocument, err := openDocumentAt(parentFD, base, uid)
	if err != nil || !sameFileIdentity(restoredDocument.stat, displacedIdentity) {
		if restoredDocument != nil {
			restoredDocument.close()
		}
		return proof, errors.New("restored document content could not be observed authoritatively")
	}
	proof.Current = metadataPointer(restoredDocument.metadata)
	restoredDocument.close()
	proof.Outcome = "refused_restored"
	proof.ResidualState = "exchange_restored_at_verification"
	return proof, nil
}

func nonRootUID() (uint32, error) {
	uid, effective := os.Getuid(), os.Geteuid()
	if uid <= 0 || effective <= 0 || uid != effective {
		return 0, errors.New("helper requires a matching non-root real and effective UID")
	}
	return uint32(effective), nil
}

func openConfigParent(home, relative string, uid uint32) (int, string, error) {
	homeFD, err := openAbsoluteDirectory(home, uid, false)
	if err != nil {
		return -1, "", err
	}
	defer unix.Close(homeFD)
	return openRelativeParent(homeFD, relative, uid, false)
}

func openStageParent(stageRoot, path string, uid uint32) (int, string, error) {
	stageFD, err := openAbsoluteDirectory(stageRoot, uid, true)
	if err != nil {
		return -1, "", err
	}
	defer unix.Close(stageFD)
	relative, err := filepath.Rel(stageRoot, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return -1, "", errors.New("stage path escapes the stage root")
	}
	return openRelativeParent(stageFD, relative, uid, true)
}

func openAbsoluteDirectory(path string, uid uint32, exactPrivateMode bool) (int, error) {
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("open filesystem root")
	}
	defer unix.Close(rootFD)
	relative := strings.TrimPrefix(path, string(filepath.Separator))
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: secureResolveFlags,
	})
	if err != nil {
		return -1, errors.New("open symlink-free bounded directory")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, errors.New("inspect directory identity")
	}
	if err := validateDirectory(stat, uid, exactPrivateMode); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openRelativeParent(rootFD int, relative string, uid uint32, private bool) (int, string, error) {
	components := strings.Split(relative, string(filepath.Separator))
	if len(components) == 0 {
		return -1, "", errors.New("relative path is empty")
	}
	currentFD, err := unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, "", errors.New("duplicate bounded directory descriptor")
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat2(currentFD, component, &unix.OpenHow{
			Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: secureResolveFlags,
		})
		_ = unix.Close(currentFD)
		if openErr != nil {
			return -1, "", errors.New("open symlink-free relative directory")
		}
		var stat unix.Stat_t
		if statErr := unix.Fstat(nextFD, &stat); statErr != nil || validateDirectory(stat, uid, private) != nil {
			_ = unix.Close(nextFD)
			return -1, "", errors.New("relative directory owner or mode is unsafe")
		}
		currentFD = nextFD
	}
	return currentFD, components[len(components)-1], nil
}

func validateDirectory(stat unix.Stat_t, uid uint32, exactPrivateMode bool) error {
	mode := stat.Mode & 0o7777
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || mode&0o100 == 0 || mode&0o022 != 0 ||
		mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
		return errors.New("directory owner or mode is unsafe")
	}
	if exactPrivateMode && mode != 0o700 {
		return errors.New("stage directory must be owned by the current UID with mode 0700")
	}
	return nil
}

func openDocumentAt(parentFD int, base string, uid uint32) (*openedDocument, error) {
	fd, err := unix.Openat2(parentFD, base, &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: secureResolveFlags,
	})
	if err != nil {
		return nil, errors.New("open bounded regular JSON document")
	}
	file := os.NewFile(uintptr(fd), base)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap JSON document descriptor")
	}
	document, err := refreshOpenDocument(file, uid)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	document.file = file
	return document, nil
}

func refreshOpenDocument(file *os.File, uid uint32) (*openedDocument, error) {
	if file == nil {
		return nil, errors.New("JSON document descriptor is unavailable")
	}
	var before unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &before); err != nil {
		return nil, errors.New("inspect JSON document identity")
	}
	if err := validateRegularFile(before, uid); err != nil {
		return nil, err
	}
	first, err := readBounded(file)
	if err != nil {
		return nil, err
	}
	var middle unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &middle); err != nil || !sameStableObservation(before, middle) {
		return nil, errors.New("JSON document changed during secure read")
	}
	second, err := readBounded(file)
	if err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil || !sameStableObservation(middle, after) || !bytes.Equal(first, second) {
		return nil, errors.New("JSON document changed during stable read")
	}
	parsed, err := parseStrictDocument(first)
	if err != nil {
		return nil, err
	}
	return &openedDocument{
		stat: after, payload: first, document: parsed,
		metadata: fileMetadata{
			SHA256: digestPayload(first), Size: int64(len(first)), Dev: uint64(after.Dev), Ino: after.Ino,
			Mode: after.Mode & 0o7777,
		},
	}, nil
}

func validateRegularFile(stat unix.Stat_t, uid uint32) error {
	mode := stat.Mode & 0o7777
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uid || stat.Nlink != 1 ||
		(mode != 0o400 && mode != 0o600) {
		return errors.New("JSON document must be a single-link current-UID regular file with mode 0400 or 0600")
	}
	if stat.Size < 1 || stat.Size > maxJSONBytes {
		return errors.New("JSON document exceeds the bounded file size")
	}
	return nil
}

func readBounded(file *os.File) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("seek bounded JSON document")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxJSONBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maxJSONBytes {
		return nil, errors.New("read bounded JSON document")
	}
	return payload, nil
}

func sameStableObservation(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode && left.Uid == right.Uid &&
		left.Gid == right.Gid && left.Nlink == right.Nlink && left.Size == right.Size &&
		left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func sameFileIdentity(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Nlink == right.Nlink
}

func createExclusiveDocument(
	parentFD int, base string, payload []byte, mode uint32, uid uint32, hooks linuxHooks,
) (*openedDocument, error) {
	created, err := createTemporaryDocument(parentFD, base, payload, mode, uid, hooks)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			created.close()
			unlinkIfIdentity(parentFD, base, created.stat)
		}
	}()
	if err := hooks.fsync(parentFD); err != nil {
		return nil, errors.New("persist snapshot directory entry")
	}
	ok = true
	return created, nil
}

func createTemporaryDocument(
	parentFD int, base string, payload []byte, mode uint32, uid uint32, hooks linuxHooks,
) (*openedDocument, error) {
	fd, err := unix.Openat(parentFD, base, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("create exclusive staged JSON document")
	}
	file := os.NewFile(uintptr(fd), base)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parentFD, base, 0)
		return nil, errors.New("wrap staged JSON document descriptor")
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
			_ = unix.Unlinkat(parentFD, base, 0)
		}
	}()
	if err := writeAll(file, payload); err != nil {
		return nil, err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return nil, errors.New("set staged JSON document mode")
	}
	if err := hooks.fsync(fd); err != nil {
		return nil, errors.New("persist staged JSON document")
	}
	document, err := refreshOpenDocument(file, uid)
	if err != nil {
		return nil, err
	}
	document.file = file
	if document.metadata.SHA256 != digestPayload(payload) {
		return nil, errors.New("staged JSON document digest changed")
	}
	ok = true
	return document, nil
}

func writeAll(file *os.File, payload []byte) error {
	written := 0
	for written < len(payload) {
		count, err := file.Write(payload[written:])
		if err != nil || count <= 0 {
			return errors.New("write staged JSON document")
		}
		written += count
	}
	return nil
}

func randomTemporaryName() (string, error) {
	var bytes [16]byte
	if _, err := io.ReadFull(rand.Reader, bytes[:]); err != nil {
		return "", errors.New("generate temporary JSON document name")
	}
	return fmt.Sprintf(".agentd-json-config-%x.tmp", bytes[:]), nil
}

func verifyExchangePaths(parentFD int, base, temporaryName string, installed, displaced unix.Stat_t) error {
	baseStat, err := lstatAt(parentFD, base)
	if err != nil || !sameObject(baseStat, installed) {
		return errors.New("installed path does not name the staged inode")
	}
	temporaryStat, err := lstatAt(parentFD, temporaryName)
	if err != nil || !sameObject(temporaryStat, displaced) {
		return errors.New("temporary path does not name the displaced inode")
	}
	return nil
}

func lstatAt(parentFD int, base string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unix.Stat_t{}, err
	}
	return stat, nil
}

func sameObject(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT
}

func unlinkExactIdentity(parentFD int, base string, expected unix.Stat_t) error {
	stat, err := lstatAt(parentFD, base)
	if err != nil || !sameObject(stat, expected) {
		return errors.New("refusing to unlink a changed temporary path")
	}
	if err := unix.Unlinkat(parentFD, base, 0); err != nil {
		return errors.New("unlink exact temporary inode")
	}
	return nil
}

func unlinkIfIdentity(parentFD int, base string, expected unix.Stat_t) {
	stat, err := lstatAt(parentFD, base)
	if err == nil && sameObject(stat, expected) {
		_ = unix.Unlinkat(parentFD, base, 0)
	}
}

func metadataPointer(metadata fileMetadata) *fileMetadata {
	copy := metadata
	return &copy
}
