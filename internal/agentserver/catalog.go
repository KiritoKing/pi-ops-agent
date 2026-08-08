package agentserver

import (
	"net/http"
	"sort"

	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

type publicArtifact struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	Digest      string `json:"digest"`
	ArtifactRef string `json:"artifactRef"`
}

func (s *Server) handleArtifacts(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleObserver, RoleAdmin); !ok {
		return
	}
	query := request.URL.Query()
	targetIDs, ok := query["targetId"]
	if !ok || len(query) != 1 || len(targetIDs) != 1 || targetIDs[0] == "" {
		writeError(writer, http.StatusBadRequest, "targetId is required and must be the only query parameter")
		return
	}
	target, ok := s.Policy.Target(targetIDs[0])
	if !ok {
		writeError(writer, http.StatusNotFound, "unknown targetId")
		return
	}
	writeJSON(writer, http.StatusOK, publicArtifacts(target.Changes.Plugins))
}

func publicArtifacts(artifacts []targetpolicy.ArtifactPolicy) []publicArtifact {
	public := make([]publicArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		public = append(public, publicArtifact{
			ID: artifact.ID, Kind: artifact.Kind, Version: artifact.Version,
			Publisher: artifact.Publisher, Digest: artifact.Digest, ArtifactRef: "builtin:" + artifact.Digest,
		})
	}
	sort.Slice(public, func(left, right int) bool {
		if public[left].Kind != public[right].Kind {
			return public[left].Kind < public[right].Kind
		}
		if public[left].ID != public[right].ID {
			return public[left].ID < public[right].ID
		}
		if public[left].Version != public[right].Version {
			return public[left].Version < public[right].Version
		}
		return public[left].Publisher < public[right].Publisher
	})
	return public
}
