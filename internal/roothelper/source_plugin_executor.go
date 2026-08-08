package roothelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const (
	defaultSourcePluginRoot     = "/var/lib/ops-agent/plugin-sources"
	defaultSourcePluginRegistry = "/var/lib/ops-agent/plugins"
)

type pluginRegistrationRollback struct {
	Previous *pluginRegistrationPrevious `json:"previous,omitempty"`
}

type pluginRegistrationPrevious struct {
	PluginID        string              `json:"pluginId"`
	Kind            pluginregistry.Kind `json:"kind"`
	Digest          string              `json:"digest"`
	RequestedScopes []string            `json:"requestedScopes"`
	ApprovedBy      string              `json:"approvedBy"`
	ApprovedAt      time.Time           `json:"approvedAt"`
}

func (e *OSExecutor) sourcePluginDirectory(pluginID string) string {
	root := e.SourcePluginRoot
	if root == "" {
		root = defaultSourcePluginRoot
	}
	return filepath.Join(root, pluginID)
}

func (e *OSExecutor) sourcePluginRegistry() (*pluginregistry.Registry, error) {
	root := e.SourcePluginRegistry
	if root == "" {
		root = defaultSourcePluginRegistry
	}
	return pluginregistry.Open(root)
}

func pluginKind(value string) (pluginregistry.Kind, error) {
	switch value {
	case string(pluginregistry.KindAdapter):
		return pluginregistry.KindAdapter, nil
	case string(pluginregistry.KindWorkload):
		return pluginregistry.KindWorkload, nil
	default:
		return "", errors.New("source plugin kind must be adapter or workload")
	}
}

func (e *OSExecutor) inspectPluginRegistration(operation *protocol.PluginRegister) (pluginregistry.Inspection, error) {
	if err := operation.Validate(); err != nil {
		return pluginregistry.Inspection{}, err
	}
	registry, err := e.sourcePluginRegistry()
	if err != nil {
		return pluginregistry.Inspection{}, err
	}
	inspection, err := registry.InspectSource(e.sourcePluginDirectory(operation.PluginID))
	if err != nil {
		return pluginregistry.Inspection{}, fmt.Errorf("inspect source plugin: %w", err)
	}
	kind, err := pluginKind(operation.PluginKind)
	if err != nil {
		return pluginregistry.Inspection{}, err
	}
	if inspection.Manifest.ID != operation.PluginID || inspection.Manifest.Kind != kind ||
		inspection.Manifest.Version != operation.Version || inspection.Manifest.Publisher != operation.Publisher ||
		inspection.Digest != operation.Digest || !slices.Equal(inspection.Manifest.Capabilities, operation.Capabilities) ||
		!slices.Equal(inspection.Manifest.RequestedScopes, operation.RequestedScopes) {
		return pluginregistry.Inspection{}, errors.New("source plugin no longer matches the approved identity, version, publisher, digest, capabilities, and requested scopes")
	}
	return inspection, nil
}

func (e *OSExecutor) preparePluginRegister(scope ExecutionScope, operation *protocol.PluginRegister) (ExecutionResult, error) {
	if scope.ApprovedBy == "" || scope.ApprovedAt.IsZero() {
		return ExecutionResult{}, errors.New("source plugin registration requires an authenticated approval identity")
	}
	if _, err := e.inspectPluginRegistration(operation); err != nil {
		return ExecutionResult{}, err
	}
	registry, err := e.sourcePluginRegistry()
	if err != nil {
		return ExecutionResult{}, err
	}
	rollback := pluginRegistrationRollback{}
	backupRef := "source-plugin:" + operation.PluginID + "@none"
	current, err := registry.Current(operation.PluginID)
	if err == nil {
		rollback.Previous = &pluginRegistrationPrevious{
			PluginID: current.PluginID, Kind: current.Kind, Digest: current.Digest,
			RequestedScopes: slices.Clone(current.RequestedScopes),
			ApprovedBy:      current.ApprovedBy, ApprovedAt: current.ApprovedAt,
		}
		backupRef = "source-plugin:" + current.PluginID + "@" + current.Digest
	} else if !errors.Is(err, os.ErrNotExist) {
		return ExecutionResult{}, fmt.Errorf("read current source plugin: %w", err)
	}
	payload, err := json.Marshal(rollback)
	if err != nil {
		return ExecutionResult{}, err
	}
	return ExecutionResult{
		BackupRefs: []string{backupRef}, RollbackData: payload, RollbackAvailable: true,
	}, nil
}

func (e *OSExecutor) executePluginRegister(scope ExecutionScope, operation *protocol.PluginRegister) error {
	if _, err := e.inspectPluginRegistration(operation); err != nil {
		return err
	}
	kind, _ := pluginKind(operation.PluginKind)
	registry, err := e.sourcePluginRegistry()
	if err != nil {
		return err
	}
	_, err = registry.Register(e.sourcePluginDirectory(operation.PluginID), pluginregistry.Grant{
		PluginID: operation.PluginID, Kind: kind, Digest: operation.Digest,
		RequestedScopes: slices.Clone(operation.RequestedScopes),
		ApprovedBy:      scope.ApprovedBy, ApprovedAt: scope.ApprovedAt,
	})
	if err != nil {
		return fmt.Errorf("register approved source plugin: %w", err)
	}
	return nil
}

func (e *OSExecutor) verifyPluginRegistration(operation *protocol.PluginRegister) (string, error) {
	// Reinspect the immutable source tree instead of relying on the grant alone.
	// The digest transitively binds the manifest, but comparing every displayed
	// identity field here keeps Verify aligned with what the human approved.
	if _, err := e.inspectPluginRegistration(operation); err != nil {
		return "", err
	}
	registry, err := e.sourcePluginRegistry()
	if err != nil {
		return "", err
	}
	current, err := registry.Current(operation.PluginID)
	if err != nil {
		return "", err
	}
	kind, _ := pluginKind(operation.PluginKind)
	if current.PluginID != operation.PluginID || current.Kind != kind || current.Digest != operation.Digest ||
		!slices.Equal(current.RequestedScopes, operation.RequestedScopes) {
		return "", errors.New("active source plugin does not match the approved registration")
	}
	return fmt.Sprintf("registered %s %s %s", current.Kind, current.PluginID, current.Digest), nil
}

func (e *OSExecutor) rollbackPluginRegistration(operation *protocol.PluginRegister, result ExecutionResult) error {
	var rollback pluginRegistrationRollback
	if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
		return fmt.Errorf("decode source plugin rollback: %w", err)
	}
	registry, err := e.sourcePluginRegistry()
	if err != nil {
		return err
	}
	current, err := registry.Current(operation.PluginID)
	if errors.Is(err, os.ErrNotExist) && rollback.Previous == nil {
		// Execute may have failed before atomic activation (for example because
		// an in-flight workload held the shared invocation lease). The desired
		// pre-change state is already present, so rollback is idempotently done.
		return nil
	}
	if err != nil {
		return fmt.Errorf("read current source plugin before rollback: %w", err)
	}
	if current.Digest != operation.Digest {
		if rollback.Previous != nil && current.PluginID == rollback.Previous.PluginID &&
			current.Digest == rollback.Previous.Digest {
			// The exclusive mutation lease is non-blocking. If activation never
			// started, current still equals the durable rollback record.
			return nil
		}
		return errors.New("active source plugin changed after execution; refusing to roll back another registration")
	}
	if rollback.Previous == nil {
		if err := registry.Deactivate(operation.PluginID, operation.Digest); err != nil {
			return err
		}
		if _, err := registry.Current(operation.PluginID); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return errors.New("source plugin remained active after rollback")
			}
			return fmt.Errorf("verify source plugin deactivation: %w", err)
		}
		return nil
	}
	previous := rollback.Previous
	if previous.PluginID != operation.PluginID {
		return errors.New("source plugin rollback identity does not match the operation")
	}
	_, err = registry.Activate(previous.PluginID, previous.Digest, pluginregistry.Grant{
		PluginID: previous.PluginID, Kind: previous.Kind, Digest: previous.Digest,
		RequestedScopes: slices.Clone(previous.RequestedScopes),
		ApprovedBy:      previous.ApprovedBy, ApprovedAt: previous.ApprovedAt,
	})
	if err != nil {
		return fmt.Errorf("reactivate previous source plugin: %w", err)
	}
	restored, err := registry.Current(previous.PluginID)
	if err != nil || restored.Digest != previous.Digest {
		return errors.New("previous source plugin was not restored")
	}
	return nil
}
