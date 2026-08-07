//go:build !linux

package roothelper

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func openInspectionPath(path string, readPaths []string, _ bool) (*os.File, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, errors.New("cannot resolve inspection path")
	}
	for _, allowed := range readPaths {
		resolvedRoot, rootErr := filepath.EvalSymlinks(allowed)
		if rootErr != nil {
			continue
		}
		relative, relativeErr := filepath.Rel(resolvedRoot, resolved)
		if relativeErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return os.Open(resolved)
		}
	}
	return nil, errors.New("inspection path is not reachable beneath an allowed root")
}
