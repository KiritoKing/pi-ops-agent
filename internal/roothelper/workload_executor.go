package roothelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginpkg"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const workloadCredentialLimit = 64 * 1024

var (
	credentialSlotPattern        = regexp.MustCompile(`^[a-z][a-zA-Z0-9]{0,63}$`)
	workloadContainerNamePattern = regexp.MustCompile(`^ops-agent-[a-z0-9][a-z0-9_.-]{0,53}$`)
)

type workloadRollback struct {
	Version        int    `json:"version"`
	ChangeID       string `json:"changeId"`
	PluginID       string `json:"pluginId"`
	ArtifactDigest string `json:"artifactDigest"`
	ImageDigest    string `json:"imageDigest"`
	ContainerName  string `json:"containerName"`
}

type workloadMarker struct {
	Version                int    `json:"version"`
	ChangeID               string `json:"changeId"`
	PluginID               string `json:"pluginId"`
	ArtifactDigest         string `json:"artifactDigest"`
	ImageDigest            string `json:"imageDigest"`
	CredentialBundleDigest string `json:"credentialBundleDigest"`
}

type credentialBundle struct {
	Version  int               `json:"version"`
	PluginID string            `json:"pluginId"`
	Values   []credentialValue `json:"values"`
}

type credentialValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type dockerInspectResult struct {
	Config struct {
		Image       string            `json:"Image"`
		Cmd         []string          `json:"Cmd"`
		Entrypoint  []string          `json:"Entrypoint"`
		Env         []string          `json:"Env"`
		Labels      map[string]string `json:"Labels"`
		User        string            `json:"User"`
		StopTimeout *int              `json:"StopTimeout"`
	} `json:"Config"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	HostConfig struct {
		Privileged     bool              `json:"Privileged"`
		NetworkMode    string            `json:"NetworkMode"`
		PidMode        string            `json:"PidMode"`
		IpcMode        string            `json:"IpcMode"`
		UTSMode        string            `json:"UTSMode"`
		UsernsMode     string            `json:"UsernsMode"`
		ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
		Memory         int64             `json:"Memory"`
		NanoCPUs       int64             `json:"NanoCpus"`
		PidsLimit      int64             `json:"PidsLimit"`
		ShmSize        int64             `json:"ShmSize"`
		CapAdd         []string          `json:"CapAdd"`
		CapDrop        []string          `json:"CapDrop"`
		SecurityOpt    []string          `json:"SecurityOpt"`
		Devices        []json.RawMessage `json:"Devices"`
		DeviceRequests []json.RawMessage `json:"DeviceRequests"`
		RestartPolicy  struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		LogConfig struct {
			Type   string            `json:"Type"`
			Config map[string]string `json:"Config"`
		} `json:"LogConfig"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

func (e *OSExecutor) authorizedWorkload(scope ExecutionScope, operation *protocol.WorkloadDeploy) (*pluginpkg.Package, targetpolicy.ArtifactPolicy, error) {
	packageInfo, err := e.inspectArtifact(operation.ArtifactRef, operation.PluginID, operation.Version, operation.Publisher, operation.Digest)
	if err != nil {
		return nil, targetpolicy.ArtifactPolicy{}, err
	}
	if packageInfo.Manifest.Kind != "managed-workload" || packageInfo.Manifest.Workload == nil {
		return nil, targetpolicy.ArtifactPolicy{}, errors.New("artifact is not a managed workload plugin")
	}
	if e.Policy == nil {
		return nil, targetpolicy.ArtifactPolicy{}, errors.New("managed workload deployment requires a root-owned target policy")
	}
	policy, ok := e.Policy.Artifact(scope.TargetID, "managed-workload", operation.PluginID, operation.Version, operation.Publisher, operation.Digest)
	if !ok || !protocol.ValidDigest(policy.CredentialBundleDigest) {
		return nil, targetpolicy.ArtifactPolicy{}, errors.New("managed workload artifact or credential bundle is not pinned by the target policy")
	}
	destination := filepath.Join(e.pluginRoot(), operation.PluginID, operation.Version)
	if err := verifyInstalledArtifact(destination, packageInfo); err != nil {
		return nil, targetpolicy.ArtifactPolicy{}, err
	}
	current, err := os.Readlink(filepath.Join(e.pluginRoot(), operation.PluginID, "current"))
	if err != nil || current != operation.Version {
		return nil, targetpolicy.ArtifactPolicy{}, errors.New("managed workload plugin is not the active installed version")
	}
	return packageInfo, policy, nil
}

func (e *OSExecutor) prepareWorkload(ctx context.Context, scope ExecutionScope, operation *protocol.WorkloadDeploy) (ExecutionResult, error) {
	packageInfo, policy, err := e.authorizedWorkload(scope, operation)
	if err != nil {
		return ExecutionResult{}, err
	}
	if _, err := e.loadWorkloadCredentials(operation.PluginID, policy.CredentialBundleDigest, packageInfo.Manifest.Workload); err != nil {
		return ExecutionResult{}, err
	}
	if err := validateDockerEndpoint(); err != nil {
		return ExecutionResult{}, err
	}
	if _, err := e.Runner.Run(ctx, "/usr/bin/docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		return ExecutionResult{}, fmt.Errorf("Docker daemon is unavailable: %w", err)
	}
	exists, err := e.workloadContainerExists(ctx, packageInfo.Manifest.Workload.ContainerName)
	if err != nil {
		return ExecutionResult{}, err
	}
	if exists {
		return ExecutionResult{}, errors.New("the managed workload container name is already in use")
	}
	root := e.workloadRoot(operation.PluginID)
	if _, err := os.Lstat(root); err == nil {
		return ExecutionResult{}, errors.New("the managed workload data root already exists; greenfield deploy refuses to overwrite it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ExecutionResult{}, fmt.Errorf("inspect managed workload data root: %w", err)
	}
	rollback, err := json.Marshal(workloadRollback{
		Version: 2, ChangeID: scope.ChangeID, PluginID: operation.PluginID,
		ArtifactDigest: operation.Digest, ImageDigest: packageInfo.Manifest.Workload.ImageDigest,
		ContainerName: packageInfo.Manifest.Workload.ContainerName,
	})
	if err != nil {
		return ExecutionResult{}, err
	}
	return ExecutionResult{RollbackData: rollback, RollbackAvailable: true}, nil
}

func (e *OSExecutor) executeWorkload(ctx context.Context, scope ExecutionScope, operation *protocol.WorkloadDeploy, result ExecutionResult) error {
	rollback, packageInfo, policy, err := e.boundWorkload(scope, operation, result)
	if err != nil {
		return err
	}
	workload := packageInfo.Manifest.Workload
	credentials, err := e.loadWorkloadCredentials(operation.PluginID, policy.CredentialBundleDigest, workload)
	if err != nil {
		return err
	}
	image := workload.ImageRepository + "@" + workload.ImageDigest
	if _, err := e.Runner.Run(ctx, "/usr/bin/docker", "pull", image); err != nil {
		return fmt.Errorf("pull pinned managed workload image: %w", err)
	}
	repoDigests, err := e.Runner.Run(ctx, "/usr/bin/docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image)
	if err != nil || !strings.Contains(repoDigests, `"`+image+`"`) {
		return errors.New("pulled image does not expose the approved repository digest")
	}
	if err := e.writeWorkloadData(rollback, policy.CredentialBundleDigest, packageInfo, credentials); err != nil {
		return err
	}
	dataRoot := e.workloadDataRoot(operation.PluginID)
	args := []string{
		"create", "--pull=never", "--name", workload.ContainerName,
		"--label", "io.pi-ops-agent.managed=true",
		"--label", "io.pi-ops-agent.change=" + scope.ChangeID,
		"--label", "io.pi-ops-agent.workload=" + operation.PluginID,
		"--label", "io.pi-ops-agent.artifact-digest=" + operation.Digest,
		"--label", "io.pi-ops-agent.image-digest=" + workload.ImageDigest,
		"--restart", "unless-stopped", "--stop-timeout", "30",
		"--network", "bridge",
		"--publish", fmt.Sprintf("127.0.0.1:%d:%d/tcp", workload.HostPort, workload.ContainerPort),
		"--mount", "type=bind,source=" + dataRoot + ",target=" + workload.DataMountTarget,
		"--memory", strconv.FormatInt(workload.Resources.MemoryBytes, 10),
		"--cpus", formatNanoCPUs(workload.Resources.NanoCPUs),
		"--pids-limit", strconv.FormatInt(workload.Resources.PidsLimit, 10),
		"--shm-size", strconv.FormatInt(workload.Resources.ShmBytes, 10),
		"--user", workload.ExpectedUser,
		"--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
		"--log-driver", "json-file", "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
		"--env-file", filepath.Join(dataRoot, ".env"),
	}
	capabilities := append([]string(nil), workload.CapAdd...)
	sort.Strings(capabilities)
	for _, capability := range capabilities {
		args = append(args, "--cap-add", capability)
	}
	environmentNames := make([]string, 0, len(workload.LiteralEnvironment))
	for name := range workload.LiteralEnvironment {
		environmentNames = append(environmentNames, name)
	}
	sort.Strings(environmentNames)
	for _, name := range environmentNames {
		args = append(args, "--env", name+"="+workload.LiteralEnvironment[name])
	}
	args = append(args, image)
	args = append(args, workload.ContainerCommand...)
	if _, err := e.Runner.Run(ctx, "/usr/bin/docker", args...); err != nil {
		return fmt.Errorf("create managed workload container: %w", err)
	}
	if _, err := e.Runner.Run(ctx, "/usr/bin/docker", "start", workload.ContainerName); err != nil {
		return fmt.Errorf("start managed workload container: %w", err)
	}
	return nil
}

func (e *OSExecutor) verifyWorkload(ctx context.Context, scope ExecutionScope, operation *protocol.WorkloadDeploy, result ExecutionResult) (string, error) {
	rollback, packageInfo, policy, err := e.boundWorkload(scope, operation, result)
	if err != nil {
		return "", err
	}
	credentials, err := e.loadWorkloadCredentials(operation.PluginID, policy.CredentialBundleDigest, packageInfo.Manifest.Workload)
	if err != nil {
		return "", err
	}
	inspect, err := e.inspectWorkloadContainer(ctx, packageInfo.Manifest.Workload.ContainerName)
	if err != nil {
		return "", err
	}
	if err := e.validateWorkloadContainerSpec(inspect, rollback, packageInfo.Manifest.Workload, credentials); err != nil {
		return "", err
	}
	if err := e.waitWorkloadChecks(ctx, packageInfo.Manifest.Workload); err != nil {
		return "", err
	}
	return fmt.Sprintf("managed workload %s passed %d digest-bound checks", operation.PluginID, len(packageInfo.Manifest.Workload.ContainerExecChecks)), nil
}

func (e *OSExecutor) rollbackWorkload(ctx context.Context, scope ExecutionScope, operation *protocol.WorkloadDeploy, result ExecutionResult) error {
	rollback, err := parseWorkloadRollback(scope, operation, result)
	if err != nil {
		return err
	}
	name := rollback.ContainerName
	exists, err := e.workloadContainerExists(ctx, name)
	if err != nil {
		return err
	}
	if exists {
		inspect, err := e.inspectWorkloadContainer(ctx, name)
		if err != nil {
			return err
		}
		if !workloadLabelsMatch(inspect.Config.Labels, rollback) {
			return errors.New("managed workload container labels drifted; refusing destructive rollback")
		}
		if _, err := e.Runner.Run(ctx, "/usr/bin/docker", "rm", "--force", name); err != nil {
			return fmt.Errorf("remove managed workload container: %w", err)
		}
	}
	root := e.workloadRoot(operation.PluginID)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	marker, err := e.readWorkloadMarker(operation.PluginID)
	if err != nil {
		return err
	}
	if marker.ChangeID != rollback.ChangeID || marker.PluginID != rollback.PluginID || marker.ArtifactDigest != rollback.ArtifactDigest || marker.ImageDigest != rollback.ImageDigest {
		return errors.New("managed workload data marker drifted; refusing destructive rollback")
	}
	recovery := filepath.Join(e.StateDir, "changes", rollback.ChangeID, "workload-recovery", safeUnitFragment(operation.PluginID))
	if _, err := os.Lstat(recovery); err == nil {
		return errors.New("managed workload recovery destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(recovery), 0o700); err != nil {
		return err
	}
	return os.Rename(root, recovery)
}

func (e *OSExecutor) boundWorkload(scope ExecutionScope, operation *protocol.WorkloadDeploy, result ExecutionResult) (workloadRollback, *pluginpkg.Package, targetpolicy.ArtifactPolicy, error) {
	rollback, err := parseWorkloadRollback(scope, operation, result)
	if err != nil {
		return rollback, nil, targetpolicy.ArtifactPolicy{}, errors.New("decode prepared managed workload metadata")
	}
	packageInfo, policy, err := e.authorizedWorkload(scope, operation)
	if err != nil {
		return rollback, nil, targetpolicy.ArtifactPolicy{}, err
	}
	if rollback.Version != 2 || rollback.ChangeID != scope.ChangeID || rollback.PluginID != operation.PluginID || rollback.ArtifactDigest != operation.Digest || rollback.ImageDigest != packageInfo.Manifest.Workload.ImageDigest || rollback.ContainerName != packageInfo.Manifest.Workload.ContainerName {
		return rollback, nil, targetpolicy.ArtifactPolicy{}, errors.New("prepared managed workload metadata does not match the approved operation")
	}
	return rollback, packageInfo, policy, nil
}

func parseWorkloadRollback(scope ExecutionScope, operation *protocol.WorkloadDeploy, result ExecutionResult) (workloadRollback, error) {
	var rollback workloadRollback
	decoder := json.NewDecoder(bytes.NewReader(result.RollbackData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rollback); err != nil {
		return rollback, errors.New("decode prepared managed workload metadata")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return rollback, errors.New("prepared managed workload metadata has trailing data")
	}
	if rollback.Version != 2 || rollback.ChangeID != scope.ChangeID || rollback.PluginID != operation.PluginID ||
		rollback.ArtifactDigest != operation.Digest || !protocol.ValidDigest(rollback.ImageDigest) ||
		!workloadContainerNamePattern.MatchString(rollback.ContainerName) {
		return rollback, errors.New("prepared managed workload metadata does not match the approved operation")
	}
	return rollback, nil
}

func (e *OSExecutor) loadWorkloadCredentials(pluginID, expectedDigest string, workload *pluginpkg.ManagedWorkload) (map[string]string, error) {
	path := filepath.Join(e.workloadCredentialRoot(), pluginID, "credentials.json")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("inspect managed workload credential bundle")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > workloadCredentialLimit {
		return nil, errors.New("managed workload credential bundle must be a bounded regular file with mode 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("managed workload credential bundle must be owned by root")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read managed workload credential bundle")
	}
	digest := sha256.Sum256(payload)
	if "sha256:"+hex.EncodeToString(digest[:]) != expectedDigest {
		return nil, errors.New("managed workload credential bundle digest does not match root policy")
	}
	return parseCredentialBundle(payload, pluginID, workload)
}

func parseCredentialBundle(payload []byte, pluginID string, workload *pluginpkg.ManagedWorkload) (map[string]string, error) {
	var bundle credentialBundle
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return nil, errors.New("managed workload credential bundle is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("managed workload credential bundle has trailing data")
	}
	if bundle.Version != 1 || bundle.PluginID != pluginID || bundle.Values == nil || len(bundle.Values) != len(workload.CredentialEnvironment) {
		return nil, errors.New("managed workload credential bundle identity or slot count is invalid")
	}
	values := make(map[string]string, len(bundle.Values))
	for _, item := range bundle.Values {
		if !credentialSlotPattern.MatchString(item.Name) || len(item.Value) < 1 || len(item.Value) > 4096 || strings.ContainsAny(item.Value, "\x00\r\n") {
			return nil, errors.New("managed workload credential bundle contains an invalid value")
		}
		if _, exists := workload.CredentialEnvironment[item.Name]; !exists {
			return nil, errors.New("managed workload credential bundle contains an undeclared slot")
		}
		if _, duplicate := values[item.Name]; duplicate {
			return nil, errors.New("managed workload credential bundle contains a duplicate slot")
		}
		values[item.Name] = item.Value
	}
	for slot := range workload.CredentialEnvironment {
		if _, exists := values[slot]; !exists {
			return nil, errors.New("managed workload credential bundle is missing a required slot")
		}
	}
	return values, nil
}

func (e *OSExecutor) writeWorkloadData(rollback workloadRollback, credentialDigest string, packageInfo *pluginpkg.Package, credentials map[string]string) error {
	root := e.workloadRoot(rollback.PluginID)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return err
	}
	marker, err := json.Marshal(workloadMarker{
		Version: 1, ChangeID: rollback.ChangeID, PluginID: rollback.PluginID,
		ArtifactDigest: rollback.ArtifactDigest, ImageDigest: rollback.ImageDigest,
		CredentialBundleDigest: credentialDigest,
	})
	if err != nil {
		return err
	}
	if err := atomicReplace(filepath.Join(root, "managed.json"), append(marker, '\n'), 0o600, 0, 0); err != nil {
		return err
	}
	workload := packageInfo.Manifest.Workload
	dataRoot := e.workloadDataRoot(rollback.PluginID)
	if err := os.Mkdir(dataRoot, 0o700); err != nil {
		return err
	}
	if err := os.Chown(dataRoot, workload.UID, workload.GID); err != nil {
		return err
	}
	environment := make([]string, 0, len(credentials))
	for slot, value := range credentials {
		environment = append(environment, workload.CredentialEnvironment[slot]+"="+value)
	}
	sort.Strings(environment)
	if err := atomicReplace(filepath.Join(dataRoot, ".env"), []byte(strings.Join(environment, "\n")+"\n"), 0o600, workload.UID, workload.GID); err != nil {
		return err
	}
	installed := filepath.Join(e.pluginRoot(), rollback.PluginID, packageInfo.Manifest.Version)
	for _, directory := range workload.Directories {
		target, err := workloadHostPath(dataRoot, workload.DataMountTarget, directory.Path)
		if err != nil {
			return err
		}
		mode, _ := strconv.ParseUint(directory.Mode, 8, 32)
		if err := os.MkdirAll(target, os.FileMode(mode)); err != nil {
			return err
		}
		if err := os.Chmod(target, os.FileMode(mode)); err != nil {
			return err
		}
		if err := os.Chown(target, workload.UID, workload.GID); err != nil {
			return err
		}
	}
	for _, file := range workload.Files {
		target, err := workloadHostPath(dataRoot, workload.DataMountTarget, file.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		mode, _ := strconv.ParseUint(file.Mode, 8, 32)
		if err := copyFile(filepath.Join(installed, filepath.FromSlash(file.Source)), target, os.FileMode(mode)); err != nil {
			return err
		}
		if err := os.Chown(target, workload.UID, workload.GID); err != nil {
			return err
		}
	}
	return nil
}

func workloadHostPath(dataRoot, mountTarget, containerPath string) (string, error) {
	relative := strings.TrimPrefix(containerPath, mountTarget+"/")
	if relative == containerPath || relative == "" {
		return "", errors.New("managed workload path is outside its data mount")
	}
	target := filepath.Join(dataRoot, filepath.FromSlash(relative))
	resolved, err := filepath.Rel(dataRoot, target)
	if err != nil || resolved == ".." || strings.HasPrefix(resolved, ".."+string(filepath.Separator)) {
		return "", errors.New("managed workload path escapes its data root")
	}
	return target, nil
}

func (e *OSExecutor) inspectWorkloadContainer(ctx context.Context, name string) (dockerInspectResult, error) {
	output, err := e.Runner.Run(ctx, "/usr/bin/docker", "inspect", name)
	if err != nil {
		return dockerInspectResult{}, errors.New("inspect managed workload container")
	}
	var values []dockerInspectResult
	if err := json.Unmarshal([]byte(output), &values); err != nil || len(values) != 1 {
		return dockerInspectResult{}, errors.New("Docker returned invalid managed workload inspect data")
	}
	return values[0], nil
}

func (e *OSExecutor) validateWorkloadContainerSpec(value dockerInspectResult, rollback workloadRollback, workload *pluginpkg.ManagedWorkload, credentials map[string]string) error {
	image := workload.ImageRepository + "@" + workload.ImageDigest
	if !value.State.Running || value.Config.Image != image || value.Config.User != workload.ExpectedUser {
		return errors.New("managed workload runtime identity drifted")
	}
	if !equalStrings(value.Config.Cmd, workload.ContainerCommand) || !equalStrings(value.Config.Entrypoint, workload.ExpectedEntrypoint) {
		return errors.New("managed workload entrypoint or command drifted")
	}
	if !workloadLabelsMatch(value.Config.Labels, rollback) {
		return errors.New("managed workload labels drifted")
	}
	if value.Config.StopTimeout == nil || *value.Config.StopTimeout != 30 || value.HostConfig.Privileged || value.HostConfig.NetworkMode != "bridge" ||
		value.HostConfig.PidMode != "" || value.HostConfig.IpcMode != "private" && value.HostConfig.IpcMode != "" || value.HostConfig.UTSMode != "" || value.HostConfig.UsernsMode != "" ||
		value.HostConfig.ReadonlyRootfs || value.HostConfig.RestartPolicy.Name != "unless-stopped" {
		return errors.New("managed workload privilege, namespace, filesystem, or restart policy drifted")
	}
	resources := workload.Resources
	if value.HostConfig.Memory != resources.MemoryBytes || value.HostConfig.NanoCPUs != resources.NanoCPUs || value.HostConfig.PidsLimit != resources.PidsLimit || value.HostConfig.ShmSize != resources.ShmBytes || len(value.HostConfig.Devices) != 0 || len(value.HostConfig.DeviceRequests) != 0 {
		return errors.New("managed workload resource or device policy drifted")
	}
	expectedCaps := make([]string, 0, len(workload.CapAdd))
	for _, capability := range workload.CapAdd {
		expectedCaps = append(expectedCaps, "CAP_"+capability)
	}
	sort.Strings(expectedCaps)
	actualCaps := append([]string(nil), value.HostConfig.CapAdd...)
	sort.Strings(actualCaps)
	if !equalStrings(actualCaps, expectedCaps) || !equalStrings(value.HostConfig.CapDrop, []string{"ALL"}) || !containsPrefix(value.HostConfig.SecurityOpt, "no-new-privileges") {
		return errors.New("managed workload capability policy drifted")
	}
	if value.HostConfig.LogConfig.Type != "json-file" || value.HostConfig.LogConfig.Config["max-size"] != "10m" || value.HostConfig.LogConfig.Config["max-file"] != "3" || len(value.HostConfig.LogConfig.Config) != 2 {
		return errors.New("managed workload logging policy drifted")
	}
	portKey := strconv.Itoa(workload.ContainerPort) + "/tcp"
	bindings := value.HostConfig.PortBindings[portKey]
	if len(value.HostConfig.PortBindings) != 1 || len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort != strconv.Itoa(workload.HostPort) {
		return errors.New("managed workload loopback port binding drifted")
	}
	if len(value.Mounts) != 1 || value.Mounts[0].Type != "bind" || value.Mounts[0].Source != e.workloadDataRoot(rollback.PluginID) || value.Mounts[0].Destination != workload.DataMountTarget || !value.Mounts[0].RW {
		return errors.New("managed workload mount policy drifted")
	}
	for name, expected := range workload.LiteralEnvironment {
		if !containsString(value.Config.Env, name+"="+expected) {
			return errors.New("managed workload literal environment drifted")
		}
	}
	for slot, expected := range credentials {
		if !containsString(value.Config.Env, workload.CredentialEnvironment[slot]+"="+expected) {
			return errors.New("managed workload credential environment drifted")
		}
	}
	return nil
}

func workloadLabelsMatch(labels map[string]string, rollback workloadRollback) bool {
	return labels["io.pi-ops-agent.managed"] == "true" &&
		labels["io.pi-ops-agent.change"] == rollback.ChangeID &&
		labels["io.pi-ops-agent.workload"] == rollback.PluginID &&
		labels["io.pi-ops-agent.artifact-digest"] == rollback.ArtifactDigest &&
		labels["io.pi-ops-agent.image-digest"] == rollback.ImageDigest
}

func (e *OSExecutor) waitWorkloadChecks(ctx context.Context, workload *pluginpkg.ManagedWorkload) error {
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	lastFailure := "checks have not completed"
	for {
		allPassed := true
		if err := e.validateWorkloadProcesses(ctx, workload); err != nil {
			allPassed = false
			lastFailure = err.Error()
		}
		for _, check := range workload.ContainerExecChecks {
			if !allPassed {
				break
			}
			args := append([]string{"exec", workload.ContainerName}, check.Argv...)
			output, err := e.Runner.Run(ctx, "/usr/bin/docker", args...)
			if err != nil || !strings.Contains(output, check.OutputContains) {
				allPassed = false
				lastFailure = "a digest-bound container check did not pass"
				break
			}
		}
		if allPassed {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("managed workload verification timed out: " + lastFailure)
		case <-ticker.C:
		}
	}
}

func (e *OSExecutor) validateWorkloadProcesses(ctx context.Context, workload *pluginpkg.ManagedWorkload) error {
	output, err := e.Runner.Run(ctx, "/usr/bin/docker", "top", workload.ContainerName, "-eo", "uid,gid,pid,comm")
	if err != nil {
		return errors.New("managed workload process inspection failed")
	}
	return validateWorkloadProcessTable(output, workload.ProcessPolicy)
}

func validateWorkloadProcessTable(output string, policy pluginpkg.WorkloadProcessPolicy) error {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		return errors.New("managed workload process table is empty")
	}
	header := strings.Fields(lines[0])
	if len(header) != 4 || !strings.EqualFold(header[0], "UID") || !strings.EqualFold(header[1], "GID") || !strings.EqualFold(header[2], "PID") || !strings.EqualFold(header[3], "COMMAND") {
		return errors.New("managed workload process table has an unexpected header")
	}
	runtimeParts := strings.Split(policy.RuntimeUser, ":")
	if len(runtimeParts) != 2 {
		return errors.New("managed workload runtime identity is invalid")
	}
	runtimeUID, uidErr := strconv.ParseUint(runtimeParts[0], 10, 32)
	runtimeGID, gidErr := strconv.ParseUint(runtimeParts[1], 10, 32)
	if uidErr != nil || gidErr != nil || runtimeUID == 0 || runtimeGID == 0 {
		return errors.New("managed workload runtime identity is invalid")
	}
	allowedRuntime := make(map[string]struct{}, len(policy.AllowedRuntimeCommands))
	for _, command := range policy.AllowedRuntimeCommands {
		allowedRuntime[command] = struct{}{}
	}
	allowedRoot := make(map[string]struct{}, len(policy.AllowedRootCommands))
	for _, command := range policy.AllowedRootCommands {
		allowedRoot[command] = struct{}{}
	}
	seenRequired := make(map[string]bool, len(policy.RequiredRuntimeCommands))
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return errors.New("managed workload process table is malformed")
		}
		uid, uidParseErr := strconv.ParseUint(fields[0], 10, 32)
		gid, gidParseErr := strconv.ParseUint(fields[1], 10, 32)
		pid, pidParseErr := strconv.ParseUint(fields[2], 10, 32)
		if uidParseErr != nil || gidParseErr != nil || pidParseErr != nil || pid == 0 {
			return errors.New("managed workload process table contains a non-numeric identity")
		}
		command := fields[3]
		if uid == 0 || gid == 0 {
			if uid != 0 || gid != 0 {
				return errors.New("managed workload process has a mixed root identity")
			}
			if _, ok := allowedRoot[command]; !ok {
				return errors.New("managed workload contains an undeclared root process")
			}
			continue
		}
		if uid != runtimeUID || gid != runtimeGID {
			return errors.New("managed workload contains an undeclared runtime identity")
		}
		if _, ok := allowedRuntime[command]; !ok {
			return errors.New("managed workload contains an undeclared runtime process")
		}
		seenRequired[command] = true
	}
	for _, command := range policy.RequiredRuntimeCommands {
		if !seenRequired[command] {
			return errors.New("managed workload is missing a required runtime process")
		}
	}
	return nil
}

func (e *OSExecutor) workloadContainerExists(ctx context.Context, name string) (bool, error) {
	output, err := e.Runner.Run(ctx, "/usr/bin/docker", "container", "ls", "--all", "--filter", "name=^/"+name+"$", "--format", "{{.Names}}")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(output) == name, nil
}

func (e *OSExecutor) readWorkloadMarker(pluginID string) (workloadMarker, error) {
	payload, err := os.ReadFile(filepath.Join(e.workloadRoot(pluginID), "managed.json"))
	if err != nil {
		return workloadMarker{}, err
	}
	var marker workloadMarker
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil || marker.Version != 1 || marker.PluginID != pluginID {
		return workloadMarker{}, errors.New("managed workload marker is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return workloadMarker{}, errors.New("managed workload marker has trailing data")
	}
	return marker, nil
}

func (e *OSExecutor) workloadRoot(pluginID string) string {
	return filepath.Join(e.StateDir, "managed", pluginID)
}

func (e *OSExecutor) workloadDataRoot(pluginID string) string {
	return filepath.Join(e.workloadRoot(pluginID), "data")
}

func (e *OSExecutor) workloadCredentialRoot() string {
	if e.PluginCredentialRoot != "" {
		return e.PluginCredentialRoot
	}
	return "/etc/ops-agent/workloads"
}

func formatNanoCPUs(value int64) string {
	return strconv.FormatFloat(float64(value)/1_000_000_000, 'f', 9, 64)
}

func validateDockerEndpoint() error {
	info, err := os.Lstat("/usr/bin/docker")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("/usr/bin/docker must be a non-writable regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("/usr/bin/docker must be owned by root")
	}
	socket, err := os.Lstat("/run/docker.sock")
	if err != nil || socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm()&0o002 != 0 {
		return errors.New("/run/docker.sock must be a non-world-writable Unix socket")
	}
	stat, ok = socket.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("/run/docker.sock must be owned by root")
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsPrefix(values []string, expected string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, expected) {
			return true
		}
	}
	return false
}
