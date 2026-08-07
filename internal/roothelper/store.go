package roothelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type Change struct {
	ID                 string          `json:"id"`
	ServerID           string          `json:"serverId,omitempty"`
	MachineID          string          `json:"machineId,omitempty"`
	TargetID           string          `json:"targetId,omitempty"`
	PolicyRevision     string          `json:"policyRevision,omitempty"`
	CapabilityRevision string          `json:"capabilityRevision,omitempty"`
	PlanHash           string          `json:"planHash"`
	Kind               string          `json:"kind"`
	Summary            string          `json:"summary"`
	Operation          json.RawMessage `json:"operation"`
	State              string          `json:"state"`
	PreparedAt         string          `json:"preparedAt"`
	UpdatedAt          string          `json:"updatedAt"`
	ApprovedByUID      *uint32         `json:"approvedByUid,omitempty"`
	BackupRefs         []string        `json:"backupRefs,omitempty"`
	RollbackData       json.RawMessage `json:"rollbackData,omitempty"`
	RollbackAvailable  bool            `json:"rollbackAvailable"`
	Verification       string          `json:"verification,omitempty"`
	LastError          string          `json:"lastError,omitempty"`
}

type requestRecord struct {
	UID         uint32            `json:"uid"`
	Fingerprint string            `json:"fingerprint"`
	Response    protocol.Response `json:"response"`
}

type persistedState struct {
	Changes        map[string]*Change       `json:"changes"`
	Requests       map[string]requestRecord `json:"requests"`
	ApprovalNonces map[string]string        `json:"approvalNonces,omitempty"`
}

type Store struct {
	mu    sync.Mutex
	dir   string
	path  string
	state persistedState
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	store := &Store{
		dir: dir, path: filepath.Join(dir, "state.json"),
		state: persistedState{Changes: make(map[string]*Change), Requests: make(map[string]requestRecord), ApprovalNonces: make(map[string]string)},
	}
	payload, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, &store.state); err != nil {
		return nil, fmt.Errorf("decode root-helper state: %w", err)
	}
	if store.state.Changes == nil {
		store.state.Changes = make(map[string]*Change)
	}
	if store.state.Requests == nil {
		store.state.Requests = make(map[string]requestRecord)
	}
	if store.state.ApprovalNonces == nil {
		store.state.ApprovalNonces = make(map[string]string)
	}
	for id, change := range store.state.Changes {
		if change == nil || change.ID != id {
			return nil, fmt.Errorf("invalid persisted change %q", id)
		}
		operation, err := protocol.ParseStoredOperation(change.Operation)
		if err != nil {
			return nil, fmt.Errorf("invalid persisted operation for %q: %w", id, err)
		}
		if operation.Kind() != change.Kind {
			return nil, fmt.Errorf("persisted operation kind for %q does not match change kind", id)
		}
	}
	return store, nil
}

func (s *Store) Directory() string { return s.dir }

func (s *Store) Change(id string) (*Change, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	change, ok := s.state.Changes[id]
	if !ok {
		return nil, false
	}
	clone := *change
	clone.Operation = append(json.RawMessage(nil), change.Operation...)
	clone.RollbackData = append(json.RawMessage(nil), change.RollbackData...)
	clone.BackupRefs = append([]string(nil), change.BackupRefs...)
	return &clone, true
}

func (s *Store) PutChange(change *Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *change
	clone.Operation = append(json.RawMessage(nil), change.Operation...)
	clone.RollbackData = append(json.RawMessage(nil), change.RollbackData...)
	clone.BackupRefs = append([]string(nil), change.BackupRefs...)
	s.state.Changes[change.ID] = &clone
	return s.persistLocked()
}

func (s *Store) Cached(requestID string, uid uint32, fingerprint string) (protocol.Response, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.state.Requests[requestID]
	if !ok {
		return protocol.Response{}, false, nil
	}
	if record.UID != uid || record.Fingerprint != fingerprint {
		return protocol.Response{}, false, errors.New("requestId replayed by another peer or with different content")
	}
	return record.Response, true, nil
}

func (s *Store) Cache(requestID string, uid uint32, fingerprint string, response protocol.Response) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Requests[requestID] = requestRecord{UID: uid, Fingerprint: fingerprint, Response: response}
	return s.persistLocked()
}

func (s *Store) UseApprovalNonce(nonce, changeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, exists := s.state.ApprovalNonces[nonce]; exists {
		return fmt.Errorf("approval nonce was already used for %s", previous)
	}
	s.state.ApprovalNonces[nonce] = changeID
	return s.persistLocked()
}

func (s *Store) recoverInterrupted(now time.Time) ([]Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var recovered []Change
	for _, change := range s.state.Changes {
		switch change.State {
		case StatePreparing, StateExecuting, StateVerifying, StateRollingBack:
			previous := change.State
			change.State = StateRecoveryRequired
			change.UpdatedAt = timestamp(now)
			change.LastError = "helper restarted while change was " + previous + "; operator review or explicit rollback is required"
			recovered = append(recovered, *change)
		}
	}
	if len(recovered) == 0 {
		return nil, nil
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return recovered, nil
}

func (s *Store) persistLocked() error {
	payload, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	directory, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func timestamp(now time.Time) string { return now.UTC().Format(time.RFC3339Nano) }
