package agentserver

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginpkg"
)

type publicPlugin struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Digest      string `json:"digest"`
	CatalogPath string `json:"catalogPath"`
	Description string `json:"description"`
}

func (s *Server) handlePlugins(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleAdmin); !ok {
		return
	}
	catalog := s.CatalogDir
	if catalog == "" {
		catalog = "/opt/pi-ops-agent/current/catalog"
	}
	entries, err := os.ReadDir(catalog)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(writer, http.StatusOK, []publicPlugin{})
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "read trusted plugin catalog")
		return
	}
	plugins := make([]publicPlugin, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".opspkg") {
			continue
		}
		packagePath := filepath.Join(catalog, entry.Name())
		packageInfo, inspectErr := pluginpkg.Inspect(packagePath, catalog)
		if inspectErr != nil {
			writeError(writer, http.StatusInternalServerError, "trusted plugin catalog contains an invalid package")
			return
		}
		plugins = append(plugins, publicPlugin{
			ID: packageInfo.Manifest.ID, Version: packageInfo.Manifest.Version,
			Digest: packageInfo.Digest, CatalogPath: packagePath,
			Description: packageInfo.Manifest.Description,
		})
	}
	sort.Slice(plugins, func(left, right int) bool {
		if plugins[left].ID == plugins[right].ID {
			return plugins[left].Version < plugins[right].Version
		}
		return plugins[left].ID < plugins[right].ID
	})
	writeJSON(writer, http.StatusOK, plugins)
}
