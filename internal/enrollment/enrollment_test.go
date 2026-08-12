package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/agentserver"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

func TestParseBundleRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	bundle := Bundle{
		Version: Version, Controller: "https://controller.example:7443",
		Endpoint: "https://endpoint.example:7443", ExpiresAt: "2030-01-01T00:00:00Z",
		Identity:     agentserver.Identity{Version: 1, ServerID: "server-12345678", MachineID: "machine-12345678", MachineName: "endpoint", Account: "ops-agent-server"},
		TargetPolicy: json.RawMessage(`{"version":1}`), Signature: "signature",
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := strings.Replace(string(payload), `"signature":`, `"unexpected":true,"signature":`, 1)
	if _, err := parseBundle([]byte(withUnknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field rejection, got %v", err)
	}
	if _, err := parseBundle(append(payload, []byte(" {}")...)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing-value rejection, got %v", err)
	}
}

func TestBundleAuthorityRequiresExternallyPinnedControllerCA(t *testing.T) {
	trustedCertificate, _, _ := testEnrollmentCA(t, "trusted controller")
	attackerCertificate, attackerPrivateKey, attackerPEM := testEnrollmentCA(t, "attacker")
	bundle := Bundle{
		Version: Version, Controller: "https://controller.example:7443",
		Endpoint: "https://endpoint.example:7443", ExpiresAt: "2030-01-01T00:00:00Z",
		Identity: agentserver.Identity{Version: 1, ServerID: "server-12345678",
			MachineID: "machine-12345678", MachineName: "endpoint", Account: "ops-agent-server"},
		TargetPolicy:     json.RawMessage(`{"version":1}`),
		CACertificatePEM: string(attackerPEM),
	}
	payload, err := bundlePayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(attackerPrivateKey, payload))

	if _, err := verifyBundleAuthority(bundle, controllerCAFingerprint(attackerCertificate)); err != nil {
		t.Fatalf("valid bundle under the externally pinned CA was rejected: %v", err)
	}
	if _, err := verifyBundleAuthority(bundle, ""); err == nil ||
		!strings.Contains(err.Error(), "fingerprint is invalid") {
		t.Fatalf("bundle without an external CA pin was accepted: %v", err)
	}
	if _, err := verifyBundleAuthority(bundle, controllerCAFingerprint(trustedCertificate)); err == nil ||
		!strings.Contains(err.Error(), "pinned controller CA") {
		t.Fatalf("self-consistent attacker bundle bypassed the external CA pin: %v", err)
	}
	uppercase := strings.ToUpper(controllerCAFingerprint(attackerCertificate))
	if _, err := verifyBundleAuthority(bundle, uppercase); err == nil ||
		!strings.Contains(err.Error(), "fingerprint is invalid") {
		t.Fatalf("non-canonical CA fingerprint was accepted: %v", err)
	}
}

func TestControllerCAFingerprintReadsTrustedControllerConfiguration(t *testing.T) {
	certificate, _, certificatePEM := testEnrollmentCA(t, "controller")
	configRoot := t.TempDir()
	tlsRoot := filepath.Join(configRoot, "tls")
	if err := os.Mkdir(tlsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tlsRoot, "ca.crt"), certificatePEM, 0o644); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := ControllerCAFingerprint(configRoot)
	if err != nil {
		t.Fatal(err)
	}
	if expected := controllerCAFingerprint(certificate); fingerprint != expected {
		t.Fatalf("unexpected controller CA fingerprint: got %q want %q", fingerprint, expected)
	}
}

type installedEndpointFixture struct {
	configRoot string
	options    ValidateInstalledOptions
	uid        int
	gid        int
}

func TestValidateInstalledEndpointAcceptsCompleteReadOnlyTopology(t *testing.T) {
	fixture := createInstalledEndpointFixture(t, false)
	metadataPath := filepath.Join(fixture.configRoot, "endpoint-enrollment.json")
	before, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledEndpoint(fixture.options, fixture.uid, fixture.gid,
		fixture.gid, fixture.gid, false); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("installed enrollment validation modified metadata")
	}
}

func TestValidateInstalledEndpointRejectsPartialOrDamagedTopology(t *testing.T) {
	tests := []struct {
		name      string
		damage    func(t *testing.T, fixture installedEndpointFixture)
		wantError string
	}{
		{
			name: "missing metadata",
			damage: func(t *testing.T, fixture installedEndpointFixture) {
				t.Helper()
				if err := os.Remove(filepath.Join(fixture.configRoot, "endpoint-enrollment.json")); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "missing or unsafe",
		},
		{
			name: "changed controller binding",
			damage: func(t *testing.T, fixture installedEndpointFixture) {
				t.Helper()
				path := filepath.Join(fixture.configRoot, "endpoint-enrollment.json")
				payload, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				payload = []byte(strings.Replace(string(payload),
					"https://controller.example:7443", "https://other.example:7443", 1))
				writeFixtureFile(t, path, payload, 0o640)
			},
			wantError: "another controller",
		},
		{
			name: "missing PVE binding",
			damage: func(t *testing.T, fixture installedEndpointFixture) {
				t.Helper()
				path := filepath.Join(fixture.configRoot, "endpoint-enrollment.json")
				payload, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				payload = []byte(strings.Replace(string(payload), ",\"pve\":false", "", 1))
				writeFixtureFile(t, path, payload, 0o640)
			},
			wantError: "missing the PVE binding",
		},
		{
			name: "receipt permissions widened",
			damage: func(t *testing.T, fixture installedEndpointFixture) {
				t.Helper()
				if err := os.Chmod(filepath.Join(fixture.configRoot,
					"broker-receipts", "core-public.pem"), 0o660); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "unsafe ownership or mode",
		},
		{
			name: "partial PVE receipt pair",
			damage: func(t *testing.T, fixture installedEndpointFixture) {
				t.Helper()
				core := filepath.Join(fixture.configRoot, "broker-receipts", "private", "core.key.pem")
				payload, err := os.ReadFile(core)
				if err != nil {
					t.Fatal(err)
				}
				writeFixtureFile(t, filepath.Join(fixture.configRoot,
					"broker-receipts", "private", "pve.key.pem"), payload, 0o600)
			},
			wantError: "incomplete",
		},
		{
			name: "invalid mutable policy",
			damage: func(t *testing.T, fixture installedEndpointFixture) {
				t.Helper()
				writeFixtureFile(t, filepath.Join(fixture.configRoot, "targets.json"),
					[]byte("{\"version\":1,\"unknown\":true}\n"), 0o640)
			},
			wantError: "target policy",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := createInstalledEndpointFixture(t, false)
			test.damage(t, fixture)
			err := validateInstalledEndpoint(fixture.options, fixture.uid, fixture.gid,
				fixture.gid, fixture.gid, false)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("damaged installed enrollment was accepted: %v", err)
			}
		})
	}
}

func TestValidateInstalledEndpointRequiresExactPVEHostBinding(t *testing.T) {
	fixture := createInstalledEndpointFixture(t, true)
	if err := validateInstalledEndpoint(fixture.options, fixture.uid, fixture.gid,
		fixture.gid, fixture.gid, true); err != nil {
		t.Fatal(err)
	}
	if err := validateInstalledEndpoint(fixture.options, fixture.uid, fixture.gid,
		fixture.gid, fixture.gid, false); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("PVE enrollment was reused on a non-PVE endpoint: %v", err)
	}
}

func createInstalledEndpointFixture(t *testing.T, pve bool) installedEndpointFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	caCertificate, caKey, caPEM := testEnrollmentCA(t, "controller")
	identity := agentserver.Identity{
		Version: 1, ServerID: "server-endpoint-1234", MachineID: "machine-endpoint-1234",
		MachineName: "endpoint", Account: "ops-agent-server",
	}
	endpoint := "https://endpoint.example:7443"
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityURI, err := url.Parse("spiffe://ops-agent/server/" + identity.ServerID + "/machine/" + identity.MachineID)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "endpoint.example"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"endpoint.example"}, URIs: []*url.URL{identityURI},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, serverPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, approvalPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approvalDER, err := x509.MarshalPKIXPublicKey(approvalPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	coreReceipt, err := generateReceiptKeyMaterial(coreReceiptKeyID)
	if err != nil {
		t.Fatal(err)
	}
	var pveReceipt receiptKeyMaterial
	if pve {
		pveReceipt, err = generateReceiptKeyMaterial(pveReceiptKeyID)
		if err != nil {
			t.Fatal(err)
		}
	}
	configRoot := t.TempDir()
	if err := os.Chmod(configRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	tlsRoot := filepath.Join(configRoot, "tls")
	receiptRoot := filepath.Join(configRoot, "broker-receipts")
	privateRoot := filepath.Join(receiptRoot, "private")
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{tlsRoot, 0o755},
		{receiptRoot, 0o755},
		{privateRoot, 0o700},
	} {
		if err := os.Mkdir(directory.path, directory.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			t.Fatal(err)
		}
	}
	pin := controllerCAFingerprint(caCertificate)
	metadata, err := json.Marshal(installedEndpointEnrollment{
		Version: installedVersion, Controller: "https://controller.example:7443", Endpoint: endpoint,
		ControllerCASHA256: pin, ServerID: identity.ServerID, MachineID: identity.MachineID, PVE: pve,
	})
	if err != nil {
		t.Fatal(err)
	}
	identityPayload, _ := json.Marshal(identity)
	writeFixtureFile(t, filepath.Join(configRoot, "endpoint-enrollment.json"), append(metadata, '\n'), 0o640)
	writeFixtureFile(t, filepath.Join(configRoot, "server-identity.json"), append(identityPayload, '\n'), 0o640)
	writeFixtureFile(t, filepath.Join(configRoot, "targets.json"),
		append(initialEndpointPolicy("policy-endpoint-12345678"), '\n'), 0o640)
	writeFixtureFile(t, filepath.Join(tlsRoot, "ca.crt"), caPEM, 0o640)
	writeFixtureFile(t, filepath.Join(tlsRoot, "client-ca.crt"), caPEM, 0o640)
	writeFixtureFile(t, filepath.Join(tlsRoot, "server.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o640)
	writeFixtureFile(t, filepath.Join(tlsRoot, "server.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}), 0o640)
	writeFixtureFile(t, filepath.Join(tlsRoot, "approval.pub.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: approvalDER}), 0o644)
	writeFixtureFile(t, filepath.Join(privateRoot, "core.key.pem"), []byte(coreReceipt.PrivateKeyPEM), 0o600)
	writeFixtureFile(t, filepath.Join(receiptRoot, "core-public.pem"), []byte(coreReceipt.PublicKeyPEM), 0o640)
	if pve {
		writeFixtureFile(t, filepath.Join(privateRoot, "pve.key.pem"), []byte(pveReceipt.PrivateKeyPEM), 0o600)
		writeFixtureFile(t, filepath.Join(receiptRoot, "pve-public.pem"), []byte(pveReceipt.PublicKeyPEM), 0o640)
	}
	return installedEndpointFixture{
		configRoot: configRoot, uid: os.Getuid(), gid: os.Getgid(),
		options: ValidateInstalledOptions{
			Controller: "https://controller.example:7443", ControllerCASHA256: pin,
			ConfigRoot: configRoot, ServerUser: identity.Account, Now: now,
		},
	}
}

func writeFixtureFile(t *testing.T, path string, payload []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func testEnrollmentCA(t *testing.T, commonName string) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certificate, privateKey, certificatePEM
}

func TestInitialEndpointPolicyGrantsNoControlPlaneOrPluginMutation(t *testing.T) {
	policy, err := targetpolicy.Parse(initialEndpointPolicy("policy-endpoint-12345678"))
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Targets) != 1 {
		t.Fatalf("unexpected endpoint targets: %#v", policy.Targets)
	}
	target := policy.Targets[0]
	if len(target.Inspect.ReadPaths) != 0 || len(target.Inspect.Units) != 0 ||
		len(target.Changes.WritePaths) != 0 || len(target.Changes.Units) != 0 ||
		len(target.Changes.Packages) != 0 || len(target.Changes.Plugins) != 0 || target.PVE != nil ||
		target.Authorization == nil || len(target.Authorization.StandingScopes) != 0 {
		t.Fatalf("initial endpoint policy is not fail-closed: %#v", target)
	}
}

func TestBundleReceiptKeysAreSignedAndDomainSeparated(t *testing.T) {
	core, err := generateReceiptKeyMaterial(coreReceiptKeyID)
	if err != nil {
		t.Fatal(err)
	}
	pve, err := generateReceiptKeyMaterial(pveReceiptKeyID)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{
		Version: Version, Controller: "https://controller.example:7443",
		Endpoint: "https://endpoint.example:7443", ExpiresAt: "2030-01-01T00:00:00Z",
		Identity: agentserver.Identity{Version: 1, ServerID: "server-12345678",
			MachineID: "machine-12345678", MachineName: "endpoint", Account: "ops-agent-server"},
		TargetPolicy:     json.RawMessage(`{"version":1}`),
		CoreReceiptKeyID: core.KeyID, CoreReceiptPrivatePEM: core.PrivateKeyPEM,
		CoreReceiptPublicPEM: core.PublicKeyPEM,
		PVEReceiptKeyID:      pve.KeyID, PVEReceiptPrivatePEM: pve.PrivateKeyPEM,
		PVEReceiptPublicPEM: pve.PublicKeyPEM,
	}
	originalPayload, err := bundlePayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, installedPVE, err := validateBundleReceiptKeys(bundle); err != nil || installedPVE == nil {
		t.Fatalf("valid domain-separated receipt keys were rejected: pve=%v err=%v", installedPVE, err)
	}

	tampered := bundle
	tampered.CoreReceiptPublicPEM = pve.PublicKeyPEM
	if _, _, err := validateBundleReceiptKeys(tampered); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched core receipt keypair was accepted: %v", err)
	}
	tamperedPayload, err := bundlePayload(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if string(originalPayload) == string(tamperedPayload) {
		t.Fatal("broker receipt keys are not covered by the enrollment signature payload")
	}

	shared := bundle
	shared.PVEReceiptPrivatePEM = core.PrivateKeyPEM
	shared.PVEReceiptPublicPEM = core.PublicKeyPEM
	if _, _, err := validateBundleReceiptKeys(shared); err == nil || !strings.Contains(err.Error(), "separate") {
		t.Fatalf("core and PVE receipt domains shared a key: %v", err)
	}
	incomplete := bundle
	incomplete.PVEReceiptPrivatePEM = ""
	if _, _, err := validateBundleReceiptKeys(incomplete); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("partial PVE receipt material was accepted: %v", err)
	}
}

func TestEndpointReceiptInstallIsAtomicAndRollbackSafe(t *testing.T) {
	core, err := generateReceiptKeyMaterial(coreReceiptKeyID)
	if err != nil {
		t.Fatal(err)
	}
	pve, err := generateReceiptKeyMaterial(pveReceiptKeyID)
	if err != nil {
		t.Fatal(err)
	}
	configRoot := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	staging, err := stageEndpointReceiptKeysOwned(configRoot, core, &pve, uid, gid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(configRoot, "broker-receipts")); !os.IsNotExist(err) {
		t.Fatalf("receipt files became visible before atomic commit: %v", err)
	}
	if err := os.Mkdir(filepath.Join(configRoot, "broker-receipts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := staging.commit(); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("commit did not fail closed on a destination race: %v", err)
	}
	stagingPath := staging.stagingRoot
	staging.cleanup()
	if _, err := os.Stat(stagingPath); !os.IsNotExist(err) {
		t.Fatalf("failed enrollment left staged private keys behind: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(configRoot, "broker-receipts"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed commit modified the reserved destination: entries=%v err=%v", entries, err)
	}
	if err := os.Remove(filepath.Join(configRoot, "broker-receipts")); err != nil {
		t.Fatal(err)
	}

	staging, err = stageEndpointReceiptKeysOwned(configRoot, core, &pve, uid, gid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := staging.commit(); err != nil {
		t.Fatal(err)
	}
	for path, wantMode := range map[string]os.FileMode{
		"private/core.key.pem": 0o600,
		"private/pve.key.pem":  0o600,
		"core-public.pem":      0o640,
		"pve-public.pem":       0o640,
	} {
		info, err := os.Lstat(filepath.Join(configRoot, "broker-receipts", path))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != wantMode {
			t.Fatalf("receipt file %s has wrong type/mode: info=%v err=%v", path, info, err)
		}
	}
}

func TestPVEEnrollmentBundleMustMatchEndpoint(t *testing.T) {
	for _, test := range []struct {
		name      string
		bundlePVE bool
		hostPVE   bool
		wantError string
	}{
		{name: "ordinary endpoint", bundlePVE: false, hostPVE: false},
		{name: "PVE endpoint", bundlePVE: true, hostPVE: true},
		{name: "missing --pve", bundlePVE: false, hostPVE: true, wantError: "issued with --pve"},
		{name: "PVE bundle on ordinary endpoint", bundlePVE: true, hostPVE: false, wantError: "non-PVE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validatePVEEnrollmentMode(test.bundlePVE, test.hostPVE)
			if test.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("unexpected PVE mode error: %v", err)
			}
		})
	}
}

func TestEndpointEnrollmentWriteFailureRollsBackEveryFile(t *testing.T) {
	core, err := generateReceiptKeyMaterial(coreReceiptKeyID)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	tlsRoot := filepath.Join(directory, "tls")
	if err := os.Mkdir(tlsRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	receiptStaging, err := stageEndpointReceiptKeysOwned(directory, core, nil, uid, gid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer receiptStaging.cleanup()
	writes := []endpointEnrollmentWrite{
		{filepath.Join(directory, "server-identity.json"), []byte("identity\n"), 0o640, uid, gid},
		{filepath.Join(directory, "targets.json"), []byte("policy\n"), 0o640, uid, gid},
		{filepath.Join(tlsRoot, "server.crt"), []byte("certificate\n"), 0o640, uid, gid},
	}
	if err := commitEndpointEnrollment(writes, receiptStaging, 2); err == nil ||
		!strings.Contains(err.Error(), "injected") {
		t.Fatalf("expected injected enrollment failure, got %v", err)
	}
	for _, write := range writes {
		if _, err := os.Stat(write.path); !os.IsNotExist(err) {
			t.Fatalf("failed enrollment retained partial file %s: %v", write.path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "broker-receipts")); !os.IsNotExist(err) {
		t.Fatalf("failed enrollment committed its receipt tree: %v", err)
	}
}

func TestRegistryEntryPinsEndpointReceiptVerifiersAndObserver(t *testing.T) {
	directory := t.TempDir()
	registryPath := filepath.Join(directory, "servers.json")
	registry := registryDocument{Version: 1, Servers: []registryRegistration{{
		ServerID: "server-controller", MachineID: "machine-controller",
		BaseURL: "https://127.0.0.1:7443", CAPath: "/ca", CertPath: "/agent.crt",
		KeyPath: "/agent.key", ObserverCertPath: "/observer.crt",
		ObserverKeyPath: "/observer.key", Enabled: true,
	}}}
	payload, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, append(payload, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
	endpoint, _ := url.Parse("https://endpoint.example:7443")
	receipts := controllerReceiptVerifiers{
		Directory:         "/etc/ops-agent/broker-receipts/remotes/server-endpoint",
		CoreKeyID:         coreReceiptKeyID,
		CorePublicKeyPath: "/etc/ops-agent/broker-receipts/remotes/server-endpoint/core-public.pem",
		PVEKeyID:          pveReceiptKeyID,
		PVEPublicKeyPath:  "/etc/ops-agent/broker-receipts/remotes/server-endpoint/pve-public.pem",
	}
	identity := agentserver.Identity{Version: 1, ServerID: "server-endpoint",
		MachineID: "machine-endpoint", MachineName: "endpoint", Account: "ops-agent-server"}
	if err := addRegistryEntry(registryPath, identity, endpoint, receipts); err != nil {
		t.Fatal(err)
	}
	updatedPayload, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	var updated registryDocument
	if err := json.Unmarshal(updatedPayload, &updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Servers) != 2 {
		t.Fatalf("unexpected registry entries: %#v", updated.Servers)
	}
	added := updated.Servers[1]
	if added.ObserverCertPath != "/observer.crt" || added.ObserverKeyPath != "/observer.key" {
		t.Fatalf("endpoint lost the controller observer identity: %#v", added)
	}
	if added.CoreReceiptKeyID != receipts.CoreKeyID ||
		added.CoreReceiptPublicKeyPath != receipts.CorePublicKeyPath ||
		added.PVEReceiptKeyID != receipts.PVEKeyID ||
		added.PVEReceiptPublicKeyPath != receipts.PVEPublicKeyPath {
		t.Fatalf("endpoint receipt verifiers were not pinned: %#v", added)
	}
}

func TestRegistryCommitFailureRestoresOriginalDocument(t *testing.T) {
	directory := t.TempDir()
	registryPath := filepath.Join(directory, "servers.json")
	original := []byte("original registry\n")
	updated := []byte("updated registry\n")
	if err := os.WriteFile(registryPath, original, 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	syncCalls := 0
	err = replaceRegistryAtomically(registryPath, updated, original, info.Mode().Perm(),
		int(stat.Uid), int(stat.Gid), func(string) error {
			syncCalls++
			if syncCalls == 1 {
				return errors.New("injected registry directory sync failure")
			}
			return nil
		})
	if err == nil || !strings.Contains(err.Error(), "injected registry directory sync failure") {
		t.Fatalf("expected injected registry commit failure, got %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("registry rollback did not fsync its restoration: calls=%d", syncCalls)
	}
	restored, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Fatalf("failed registry commit left the issued entry visible: %q", restored)
	}
}

func TestValidateHTTPSOrigin(t *testing.T) {
	valid, err := validateHTTPSOrigin("https://machine.example:7443/")
	if err != nil || valid.String() != "https://machine.example:7443" {
		t.Fatalf("unexpected valid origin result %v, %v", valid, err)
	}
	for _, invalid := range []string{
		"http://machine.example:7443",
		"https://user@machine.example:7443",
		"https://machine.example:7443/path",
		"https://machine.example:7443?query=1",
	} {
		if _, err := validateHTTPSOrigin(invalid); err == nil {
			t.Fatalf("expected invalid origin rejection for %q", invalid)
		}
	}
}
