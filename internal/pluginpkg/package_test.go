package pluginpkg

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestInspectAndExtractPackage(t *testing.T) {
	catalog := t.TempDir()
	packagePath := filepath.Join(catalog, "adapter-botmux.opspkg")
	writeTestPackage(t, packagePath, map[string]string{
		"manifest.json": validManifest,
		"adapter.mjs":   "export const ready = true;\n",
	})

	packageInfo, err := Inspect(packagePath, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if packageInfo.Manifest.ID != "adapter.botmux" || packageInfo.Manifest.Version != "0.2.0" {
		t.Fatalf("unexpected manifest: %#v", packageInfo.Manifest)
	}
	if !strings.HasPrefix(packageInfo.Digest, "sha256:") {
		t.Fatalf("unexpected digest: %q", packageInfo.Digest)
	}
	destination := filepath.Join(t.TempDir(), "plugin")
	previousUmask := syscall.Umask(0o077)
	defer syscall.Umask(previousUmask)
	if err := packageInfo.Extract(destination); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(destination)
	if err != nil || directoryInfo.Mode().Perm() != 0o755 {
		t.Fatalf("unexpected extraction directory mode: %v, %v", directoryInfo, err)
	}
	payload, err := os.ReadFile(filepath.Join(destination, "adapter.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "export const ready = true;\n" {
		t.Fatalf("unexpected entrypoint payload: %q", payload)
	}
	entrypointInfo, err := os.Stat(filepath.Join(destination, "adapter.mjs"))
	if err != nil || entrypointInfo.Mode().Perm() != 0o644 {
		t.Fatalf("unexpected extracted file mode: %v, %v", entrypointInfo, err)
	}
}

func TestInspectManagedWorkloadAndArtifactReference(t *testing.T) {
	catalog := t.TempDir()
	packagePath := filepath.Join(catalog, "workload-hermes.opspkg")
	writeTestPackage(t, packagePath, map[string]string{
		"manifest.json":           validWorkloadManifest,
		"config.yaml":             "model:\n  provider: deepseek\n",
		"ops-healthcheck.py":      "print('ops-healthcheck: ok')\n",
		"prepare-credentials.mjs": "process.stdout.write('{}\\n');\n",
	})

	packageInfo, err := Inspect(packagePath, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if packageInfo.Manifest.Kind != "managed-workload" || packageInfo.Manifest.Workload == nil {
		t.Fatalf("unexpected workload manifest: %#v", packageInfo.Manifest)
	}
	if packageInfo.Manifest.Workload.Runtime != "docker" || packageInfo.Manifest.Workload.HostPort != 9119 {
		t.Fatalf("unexpected workload: %#v", packageInfo.Manifest.Workload)
	}
	if !strings.HasPrefix(packageInfo.Reference(), "builtin:sha256:") {
		t.Fatalf("unexpected artifact reference: %q", packageInfo.Reference())
	}
	resolved, err := InspectArtifactRef(catalog, packageInfo.Reference())
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Path != packageInfo.Path || resolved.Digest != packageInfo.Digest {
		t.Fatalf("artifact reference resolved to the wrong package: %#v", resolved)
	}
	if _, err := InspectArtifactRef(catalog, "https://example.com/workload.opspkg"); err == nil {
		t.Fatal("remote URL was accepted as a builtin artifact reference")
	}
}

func TestRepositoryHermesWorkloadManifest(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	pluginRoot := filepath.Join(filepath.Dir(sourceFile), "..", "..", "plugins", "workload-hermes")
	payload, err := os.ReadFile(filepath.Join(pluginRoot, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseManifest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ID != "workload.hermes" || manifest.Version != "0.3.0" || manifest.Workload == nil {
		t.Fatalf("unexpected repository workload manifest: %#v", manifest)
	}
	for _, file := range manifest.Workload.Files {
		if info, statErr := os.Stat(filepath.Join(pluginRoot, filepath.FromSlash(file.Source))); statErr != nil || !info.Mode().IsRegular() {
			t.Fatalf("declared source %q is missing: %v", file.Source, statErr)
		}
	}
}

func TestInspectManagedWorkloadRejectsExecutableEscapeHatches(t *testing.T) {
	tests := map[string]string{
		"unknown host executable":  strings.Replace(validWorkloadManifest, `"description":"Hermes managed workload"`, `"description":"Hermes managed workload","hostExecutable":"/bin/sh"`, 1),
		"raw Docker arguments":     strings.Replace(validWorkloadManifest, `"runtime":"docker"`, `"runtime":"docker","dockerArgs":["--privileged"]`, 1),
		"unsafe capability":        strings.Replace(validWorkloadManifest, `"CHOWN"`, `"SYS_ADMIN"`, 1),
		"unmanaged container name": strings.Replace(validWorkloadManifest, `"ops-agent-hermes"`, `"hermes"`, 1),
		"relative entrypoint":      strings.Replace(validWorkloadManifest, `"/opt/hermes/docker/entrypoint-dispatch.sh"`, `"entrypoint-dispatch.sh"`, 1),
		"secret literal":           strings.Replace(validWorkloadManifest, `"HERMES_DASHBOARD":"1"`, `"DEEPSEEK_API_KEY":"secret"`, 1),
		"shell health check":       strings.Replace(validWorkloadManifest, `"/opt/hermes/.venv/bin/python","/opt/data/ops-healthcheck.py"`, `"/bin/sh","-c","curl localhost"`, 1),
		"host filesystem path":     strings.Replace(validWorkloadManifest, `"/opt/data/config.yaml"`, `"/etc/shadow"`, 1),
	}
	for name, manifest := range tests {
		t.Run(name, func(t *testing.T) {
			catalog := t.TempDir()
			packagePath := filepath.Join(catalog, "unsafe.opspkg")
			writeTestPackage(t, packagePath, map[string]string{
				"manifest.json": manifest, "config.yaml": "safe", "ops-healthcheck.py": "safe",
			})
			if _, err := Inspect(packagePath, catalog); err == nil {
				t.Fatal("unsafe managed workload manifest was accepted")
			}
		})
	}
}

func TestInspectManagedWorkloadRequiresDeclaredSources(t *testing.T) {
	catalog := t.TempDir()
	packagePath := filepath.Join(catalog, "missing-source.opspkg")
	writeTestPackage(t, packagePath, map[string]string{
		"manifest.json": validWorkloadManifest,
		"config.yaml":   "safe",
	})
	if _, err := Inspect(packagePath, catalog); err == nil || !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("expected missing workload source rejection, got %v", err)
	}
}

func TestInspectRejectsArchiveTraversal(t *testing.T) {
	catalog := t.TempDir()
	packagePath := filepath.Join(catalog, "unsafe.opspkg")
	writeTestPackage(t, packagePath, map[string]string{
		"manifest.json": validManifest,
		"../escape":     "nope",
	})
	if _, err := Inspect(packagePath, catalog); err == nil || !strings.Contains(err.Error(), "unsafe plugin archive path") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
}

func TestInspectRejectsUnknownManifestFields(t *testing.T) {
	catalog := t.TempDir()
	packagePath := filepath.Join(catalog, "unknown.opspkg")
	manifest := strings.Replace(validManifest, `"description":"BotMux adapter"`, `"description":"BotMux adapter","installCommand":"sudo sh"`, 1)
	writeTestPackage(t, packagePath, map[string]string{"manifest.json": manifest})
	if _, err := Inspect(packagePath, catalog); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected strict manifest rejection, got %v", err)
	}
}

func TestInspectAdapterSchemaMatchesSetupAndSecretConstraints(t *testing.T) {
	tests := []string{
		strings.Replace(validManifest, `"credential.install","config.write","service.start"`, `"root.shell"`, 1),
		strings.Replace(validManifest, `"credential.install","config.write","service.start"`, `"config.write","config.write"`, 1),
		strings.Replace(validManifest, `"credential.install","config.write","service.start"`, `"config.write","service.start"`, 1),
		strings.Replace(validManifest, `"larkAppSecret"`, `"Lark.App.Secret"`, 1),
		strings.Replace(validManifest, `"adapter.mjs"`, `"adapter.mjs;sh"`, 1),
		strings.Replace(validManifest, `"adapter.mjs"`, `"nested//adapter.mjs"`, 1),
	}
	for index, manifest := range tests {
		catalog := t.TempDir()
		packagePath := filepath.Join(catalog, "invalid-adapter.opspkg")
		writeTestPackage(t, packagePath, map[string]string{"manifest.json": manifest, "adapter.mjs": "safe"})
		if _, err := Inspect(packagePath, catalog); err == nil {
			t.Fatalf("invalid adapter manifest %d was accepted", index)
		}
	}
}

func writeTestPackage(t *testing.T, output string, files map[string]string) {
	t.Helper()
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	archive := tar.NewWriter(gzipWriter)
	for name, payload := range files {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(payload)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

const validManifest = `{"schemaVersion":1,"id":"adapter.botmux","kind":"im-adapter","version":"0.2.0","publisher":"KiritoKing/pi-ops-agent","coreProtocol":1,"entrypoint":"adapter.mjs","description":"BotMux adapter","capabilities":{"inboundText":true,"verifiedSender":true,"privateConversation":true,"proactiveDelivery":true,"approvalIntent":true,"streaming":false},"secrets":["larkAppSecret"],"setupOperations":["credential.install","config.write","service.start"]}`

const validWorkloadManifest = `{"schemaVersion":2,"id":"workload.hermes","kind":"managed-workload","version":"0.2.0","publisher":"KiritoKing/pi-ops-agent","coreProtocol":1,"description":"Hermes managed workload","workload":{"runtime":"docker","imageRepository":"nousresearch/hermes-agent","imageDigest":"sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e","containerName":"ops-agent-hermes","containerCommand":["gateway","run"],"expectedEntrypoint":["/opt/hermes/docker/entrypoint-dispatch.sh"],"expectedUser":"root","processPolicy":{"runtimeUser":"10000:10000","allowedRuntimeCommands":["hermes","s6-log","sleep"],"requiredRuntimeCommands":["hermes"],"allowedRootCommands":["s6-svscan","rc.init","s6-supervise","s6-linux-init-s","s6-ipcserverd","sleep"]},"containerPort":9119,"hostPort":9119,"dataMountTarget":"/opt/data","uid":10000,"gid":10000,"resources":{"memoryBytes":4294967296,"nanoCpus":2000000000,"pidsLimit":512,"shmBytes":1073741824},"capAdd":["CHOWN","DAC_OVERRIDE","FOWNER","KILL","SETGID","SETUID"],"literalEnvironment":{"HERMES_UID":"10000","HERMES_GID":"10000","HERMES_DASHBOARD":"1"},"credentialEnvironment":{"deepseekApiKey":"DEEPSEEK_API_KEY","dashboardUsername":"HERMES_DASHBOARD_BASIC_AUTH_USERNAME","dashboardPasswordHash":"HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH","dashboardSessionSecret":"HERMES_DASHBOARD_BASIC_AUTH_SECRET"},"directories":[{"path":"/opt/data/workspace","mode":"0750"}],"files":[{"source":"config.yaml","path":"/opt/data/config.yaml","mode":"0644"},{"source":"ops-healthcheck.py","path":"/opt/data/ops-healthcheck.py","mode":"0555"}],"containerExecChecks":[{"argv":["/opt/hermes/.venv/bin/python","/opt/data/ops-healthcheck.py"],"outputContains":"ops-healthcheck: ok"}]}}`
