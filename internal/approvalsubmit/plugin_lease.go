package approvalsubmit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const fixedRuntimePluginRegistry = "/var/lib/ops-agent/plugins"

// RuntimePluginLease is intentionally the smallest injected test boundary.
// The default implementation is always pluginregistry.InvocationLease; the
// root submitter owns it independently of every Client/lease-broker runtime.
type RuntimePluginLease interface {
	Close() error
}

type RuntimePluginLeaseAcquirer func(
	pluginID, digest string,
) (pluginregistry.RuntimeRegistration, RuntimePluginLease, error)

type runtimePluginBinding struct {
	pluginID string
	digest   string
}

func leaseFixedRuntimePlugin(
	pluginID, digest string,
) (pluginregistry.RuntimeRegistration, RuntimePluginLease, error) {
	registry, err := pluginregistry.Open(fixedRuntimePluginRegistry)
	if err != nil {
		return pluginregistry.RuntimeRegistration{}, nil, fmt.Errorf("open fixed source-plugin registry: %w", err)
	}
	registration, lease, err := registry.LeaseRuntimeCurrent(pluginID, digest)
	if err != nil {
		return pluginregistry.RuntimeRegistration{}, nil, err
	}
	return registration, lease, nil
}

// acquireApprovalRuntimePluginLease runs immediately after the first signed
// status check. It intentionally does not trust the unprivileged Client's
// current check or shared lease: this root process resolves the one canonical
// provenance itself and holds a separate shared flock through review, TTY,
// the second status check, and the final broker action.
func (s Submitter) acquireApprovalRuntimePluginLease(status ChangeStatus) (RuntimePluginLease, error) {
	if status.RecoveryOnly || status.Plan == nil {
		return nil, errors.New("runtime plugin approval has no live canonical ApprovalPlan")
	}
	binding, required, err := approvalRuntimePluginBinding(*status.Plan)
	if err != nil {
		return nil, err
	}
	if !required {
		return nil, nil
	}
	registration, lease, err := s.LeaseRuntimePlugin(binding.pluginID, binding.digest)
	if err != nil {
		return nil, fmt.Errorf("lease exact current runtime plugin: %w", err)
	}
	if lease == nil {
		return nil, errors.New("runtime plugin lease acquirer returned no shared lease")
	}
	if registration.Kind != pluginregistry.KindWorkload || registration.PluginID != binding.pluginID ||
		registration.Digest != binding.digest {
		_ = lease.Close()
		return nil, errors.New("leased runtime plugin registration does not match the canonical workload identity and digest")
	}
	return lease, nil
}

// approvalRuntimePluginBinding recognizes only operations whose authority is
// supplied by currently active source Workloads. Artifact/source registration
// operations deliberately remain outside this current-runtime lease: their
// digest is the candidate being approved, not an already active runtime.
func approvalRuntimePluginBinding(plan protocol.ApprovalPlan) (runtimePluginBinding, bool, error) {
	var binding runtimePluginBinding
	foundRuntime := false
	foundOther := false
	for _, step := range plan.Steps {
		digestField, runtimeBound := runtimePluginDigestField(step.Operation)
		if !runtimeBound {
			foundOther = true
			continue
		}
		foundRuntime = true
		pluginID, ok, err := uniqueApprovalPlanField(step, "pluginId")
		if err != nil || !ok || !protocol.ValidWorkloadPluginID(pluginID) {
			return runtimePluginBinding{}, false, errors.New("runtime plugin ApprovalPlan step has missing, duplicate, or invalid workload pluginId")
		}
		digest, ok, err := uniqueApprovalPlanField(step, digestField)
		if err != nil || !ok || !protocol.ValidDigest(digest) {
			return runtimePluginBinding{}, false, errors.New("runtime plugin ApprovalPlan step has missing, duplicate, or invalid digest provenance")
		}
		alternateDigestField := "sourceDigest"
		if digestField == alternateDigestField {
			alternateDigestField = "pluginDigest"
		}
		alternate, alternateOK, alternateErr := uniqueApprovalPlanField(step, alternateDigestField)
		if alternateErr != nil || (alternateOK && alternate != digest) {
			return runtimePluginBinding{}, false, errors.New("runtime plugin ApprovalPlan step has conflicting digest provenance")
		}
		if binding.pluginID == "" {
			binding = runtimePluginBinding{pluginID: pluginID, digest: digest}
			continue
		}
		if binding.pluginID != pluginID || binding.digest != digest {
			return runtimePluginBinding{}, false, errors.New("runtime plugin ApprovalPlan does not contain one canonical plugin identity and digest")
		}
	}
	if !foundRuntime {
		return runtimePluginBinding{}, false, nil
	}
	if foundOther {
		return runtimePluginBinding{}, false, errors.New("ApprovalPlan mixes runtime plugin-bound and non-runtime operations")
	}
	if plan.PluginDigest == "" || plan.PluginDigest != binding.digest {
		return runtimePluginBinding{}, false, errors.New("runtime plugin ApprovalPlan top-level digest does not match its canonical steps")
	}
	return binding, true, nil
}

func runtimePluginDigestField(operation string) (string, bool) {
	switch operation {
	case "service.action", "file.write", "workload.service.action":
		return "pluginDigest", true
	case "workload.json-config.edit":
		return "sourceDigest", true
	default:
		if strings.HasPrefix(operation, "pve.") {
			return "pluginDigest", true
		}
		return "", false
	}
}

func uniqueApprovalPlanField(step protocol.ApprovalPlanStep, name string) (string, bool, error) {
	value := ""
	found := false
	for _, field := range step.Fields {
		if field.Name != name {
			continue
		}
		if found {
			return "", false, fmt.Errorf("ApprovalPlan step %s repeats field %s", step.ID, name)
		}
		value = field.Value
		found = true
	}
	return value, found, nil
}
