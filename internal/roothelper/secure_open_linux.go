//go:build linux

package roothelper

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const inspectionResolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS

func openInspectionPath(path string, readPaths []string, forRead bool) (*os.File, error) {
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot open the filesystem root for secure inspection")
	}
	defer unix.Close(rootFD)

	for _, allowed := range readPaths {
		relative, relativeErr := filepath.Rel(allowed, path)
		if relativeErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		allowedRelative := strings.TrimPrefix(allowed, string(filepath.Separator))
		allowedFlags := unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if relative == "." && forRead {
			allowedFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		}
		allowedFD, openErr := unix.Openat2(rootFD, allowedRelative, &unix.OpenHow{
			Flags: uint64(allowedFlags), Resolve: inspectionResolveFlags,
		})
		if openErr != nil {
			continue
		}
		if relative == "." {
			file := os.NewFile(uintptr(allowedFD), path)
			if file == nil {
				unix.Close(allowedFD)
				continue
			}
			return file, nil
		}

		var allowedStat unix.Stat_t
		if statErr := unix.Fstat(allowedFD, &allowedStat); statErr != nil || allowedStat.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(allowedFD)
			continue
		}
		targetFlags := unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if forRead {
			targetFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		}
		targetFD, targetErr := unix.Openat2(allowedFD, relative, &unix.OpenHow{
			Flags: uint64(targetFlags), Resolve: inspectionResolveFlags,
		})
		unix.Close(allowedFD)
		if targetErr != nil {
			continue
		}
		file := os.NewFile(uintptr(targetFD), path)
		if file == nil {
			unix.Close(targetFD)
			continue
		}
		return file, nil
	}
	return nil, errors.New("inspection path is not securely reachable beneath an allowed root")
}
