//go:build !linux

package jsonconfighelper

import "errors"

var errUnsupportedPlatform = errors.New("json config helper requires Linux openat2 and renameat2")

func inspectPlatform(inspectOptions) (inspectProof, error) {
	return inspectProof{}, errUnsupportedPlatform
}

func inspectDirectoryPlatform(inspectDirectoryOptions) (inspectDirectoryProof, error) {
	return inspectDirectoryProof{}, errUnsupportedPlatform
}

func snapshotPlatform(snapshotOptions) (snapshotProof, error) {
	return snapshotProof{}, errUnsupportedPlatform
}

func mutatePlatform(mutateOptions) (mutateProof, error) {
	return mutateProof{}, errUnsupportedPlatform
}

func commitPlatform(commitOptions) (CommitProof, error) {
	return CommitProof{}, errUnsupportedPlatform
}
