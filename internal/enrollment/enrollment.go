package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/agentserver"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const Version = 1

type Bundle struct {
	Version          int                  `json:"version"`
	Controller       string               `json:"controller"`
	Endpoint         string               `json:"endpoint"`
	ExpiresAt        string               `json:"expiresAt"`
	Identity         agentserver.Identity `json:"identity"`
	TargetPolicy     json.RawMessage      `json:"targetPolicy"`
	CACertificatePEM string               `json:"caCertificatePem"`
	ServerCertPEM    string               `json:"serverCertificatePem"`
	ServerKeyPEM     string               `json:"serverPrivateKeyPem"`
	ApprovalKeyPEM   string               `json:"approvalPublicKeyPem"`
	Signature        string               `json:"signature"`
}

type IssueOptions struct {
	Controller  string
	Endpoint    string
	MachineID   string
	MachineName string
	OutputPath  string
	ConfigRoot  string
	Now         time.Time
}

type InstallOptions struct {
	Controller string
	BundlePath string
	ConfigRoot string
	ServerUser string
	Now        time.Time
}

type registryDocument struct {
	Version int                    `json:"version"`
	Servers []registryRegistration `json:"servers"`
}

type registryRegistration struct {
	ServerID               string `json:"serverId"`
	MachineID              string `json:"machineId"`
	BaseURL                string `json:"baseUrl"`
	CAPath                 string `json:"caPath"`
	CertPath               string `json:"certPath"`
	KeyPath                string `json:"keyPath"`
	ApproverCertPath       string `json:"approverCertPath,omitempty"`
	ApproverKeyPath        string `json:"approverKeyPath,omitempty"`
	ApprovalSigningKeyPath string `json:"approvalSigningKeyPath,omitempty"`
	ApprovalKeyID          string `json:"approvalKeyId,omitempty"`
	ServerName             string `json:"serverName,omitempty"`
	Enabled                bool   `json:"enabled"`
}

func Issue(options IssueOptions) error {
	if os.Geteuid() != 0 {
		return errors.New("enrollment issuance must run as root")
	}
	if options.ConfigRoot == "" {
		options.ConfigRoot = "/etc/ops-agent"
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	if options.OutputPath == "" {
		return errors.New("output path is required")
	}
	controllerURL, err := validateHTTPSOrigin(options.Controller)
	if err != nil {
		return fmt.Errorf("controller: %w", err)
	}
	endpointURL, err := validateHTTPSOrigin(options.Endpoint)
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if options.MachineName == "" || len(options.MachineName) > 256 {
		return errors.New("machine name is required and must be at most 256 characters")
	}
	serverID, err := randomID("server-")
	if err != nil {
		return err
	}
	identityPayload, err := json.Marshal(agentserver.Identity{
		Version: 1, ServerID: serverID, MachineID: options.MachineID,
		MachineName: options.MachineName, Account: "ops-agent-server",
	})
	if err != nil {
		return err
	}
	identity, err := agentserver.ParseIdentity(identityPayload)
	if err != nil {
		return err
	}
	policyRevision, err := randomID("policy-")
	if err != nil {
		return err
	}
	policyPayload := []byte(fmt.Sprintf(`{"version":1,"revision":%q,"targets":[{"id":"target-local-system","account":"root","displayName":"Local system","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":["/etc","/proc","/var/log"]},"changes":{"writePaths":["/etc/ops-agent"],"units":[],"packages":[],"plugins":["adapter.botmux"]}}]}`, policyRevision))
	if _, err := targetpolicy.Parse(policyPayload); err != nil {
		return err
	}
	caCertificatePEM, err := os.ReadFile(filepath.Join(options.ConfigRoot, "tls", "ca.crt"))
	if err != nil {
		return err
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(options.ConfigRoot, "tls", "ca.key"))
	if err != nil {
		return err
	}
	approvalKeyPEM, err := os.ReadFile(filepath.Join(options.ConfigRoot, "tls", "approval.pub.pem"))
	if err != nil {
		return err
	}
	caCertificate, caKey, err := parseCA(caCertificatePEM, caKeyPEM)
	if err != nil {
		return err
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: endpointURL.Hostname()},
		NotBefore: options.Now.Add(-time.Minute), NotAfter: options.Now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if address := net.ParseIP(endpointURL.Hostname()); address != nil {
		template.IPAddresses = []net.IP{address}
	} else {
		template.DNSNames = []string{endpointURL.Hostname()}
	}
	identityURI, _ := url.Parse("spiffe://ops-agent/server/" + identity.ServerID + "/machine/" + identity.MachineID)
	template.URIs = []*url.URL{identityURI}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, caCertificate, serverPublic, caKey)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		return err
	}
	bundle := Bundle{
		Version: Version, Controller: controllerURL.String(), Endpoint: endpointURL.String(),
		ExpiresAt: options.Now.Add(30 * time.Minute).UTC().Format(time.RFC3339Nano),
		Identity:  identity, TargetPolicy: policyPayload,
		CACertificatePEM: string(caCertificatePEM),
		ServerCertPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})),
		ServerKeyPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		ApprovalKeyPEM:   string(approvalKeyPEM),
	}
	payload, err := bundlePayload(bundle)
	if err != nil {
		return err
	}
	bundle.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(caKey, payload))
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	if err := writeExclusive(options.OutputPath, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	if err := addRegistryEntry(filepath.Join(options.ConfigRoot, "servers.json"), identity, endpointURL); err != nil {
		_ = os.Remove(options.OutputPath)
		return err
	}
	return nil
}

func Install(options InstallOptions) error {
	if os.Geteuid() != 0 {
		return errors.New("endpoint enrollment must run as root")
	}
	if options.ConfigRoot == "" {
		options.ConfigRoot = "/etc/ops-agent"
	}
	if options.ServerUser == "" {
		options.ServerUser = "ops-agent-server"
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	info, err := os.Lstat(options.BundlePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 16 || info.Size() > 128*1024 {
		return errors.New("enrollment bundle must be a private bounded regular file")
	}
	payload, err := os.ReadFile(options.BundlePath)
	if err != nil {
		return err
	}
	bundle, err := parseBundle(payload)
	if err != nil {
		return err
	}
	controllerURL, err := validateHTTPSOrigin(options.Controller)
	if err != nil || controllerURL.String() != bundle.Controller {
		return errors.New("enrollment bundle is bound to another controller")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, bundle.ExpiresAt)
	if err != nil || !options.Now.Before(expiresAt) || expiresAt.After(options.Now.Add(time.Hour)) {
		return errors.New("enrollment bundle is expired or has an invalid validity window")
	}
	caCertificate, _, err := parseCA([]byte(bundle.CACertificatePEM), nil)
	if err != nil {
		return err
	}
	unsigned, err := bundlePayload(bundle)
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(bundle.Signature)
	caPublic, ok := caCertificate.PublicKey.(ed25519.PublicKey)
	if err != nil || !ok || !ed25519.Verify(caPublic, unsigned, signature) {
		return errors.New("enrollment bundle signature is invalid")
	}
	if _, err := agentserver.ParseIdentity(mustJSON(bundle.Identity)); err != nil {
		return err
	}
	if _, err := targetpolicy.Parse(bundle.TargetPolicy); err != nil {
		return err
	}
	serverCertificate, serverKey, err := parseLeaf([]byte(bundle.ServerCertPEM), []byte(bundle.ServerKeyPEM))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCertificate)
	if _, err := serverCertificate.Verify(x509.VerifyOptions{Roots: pool, DNSName: mustEndpointHost(bundle.Endpoint), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: options.Now}); err != nil {
		return fmt.Errorf("verify enrolled server certificate: %w", err)
	}
	if !serverKey.Public().(ed25519.PublicKey).Equal(serverCertificate.PublicKey) {
		return errors.New("enrolled server certificate and private key do not match")
	}
	if !certificateBindsIdentity(serverCertificate, bundle.Identity) {
		return errors.New("enrolled server certificate does not bind the bundle identity")
	}
	account, err := user.Lookup(options.ServerUser)
	if err != nil {
		return err
	}
	gid, _ := strconv.Atoi(account.Gid)
	tlsRoot := filepath.Join(options.ConfigRoot, "tls")
	if err := os.MkdirAll(tlsRoot, 0o750); err != nil {
		return err
	}
	writes := []struct {
		path    string
		payload []byte
		mode    os.FileMode
		uid     int
		gid     int
	}{
		{filepath.Join(options.ConfigRoot, "server-identity.json"), append(mustJSON(bundle.Identity), '\n'), 0o640, 0, gid},
		{filepath.Join(options.ConfigRoot, "targets.json"), append(bundle.TargetPolicy, '\n'), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "ca.crt"), []byte(bundle.CACertificatePEM), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "client-ca.crt"), []byte(bundle.CACertificatePEM), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "server.crt"), []byte(bundle.ServerCertPEM), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "server.key"), []byte(bundle.ServerKeyPEM), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "approval.pub.pem"), []byte(bundle.ApprovalKeyPEM), 0o644, 0, 0},
	}
	for _, write := range writes {
		if err := atomicWrite(write.path, write.payload, write.mode, write.uid, write.gid); err != nil {
			return err
		}
	}
	return nil
}

func parseBundle(payload []byte) (Bundle, error) {
	var bundle Bundle
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Bundle{}, errors.New("enrollment bundle contains trailing data")
	}
	if bundle.Version != Version || bundle.Signature == "" {
		return Bundle{}, errors.New("unsupported enrollment bundle")
	}
	return bundle, nil
}

func bundlePayload(bundle Bundle) ([]byte, error) {
	unsigned := struct {
		Version          int                  `json:"version"`
		Controller       string               `json:"controller"`
		Endpoint         string               `json:"endpoint"`
		ExpiresAt        string               `json:"expiresAt"`
		Identity         agentserver.Identity `json:"identity"`
		TargetPolicy     json.RawMessage      `json:"targetPolicy"`
		CACertificatePEM string               `json:"caCertificatePem"`
		ServerCertPEM    string               `json:"serverCertificatePem"`
		ServerKeyPEM     string               `json:"serverPrivateKeyPem"`
		ApprovalKeyPEM   string               `json:"approvalPublicKeyPem"`
	}{bundle.Version, bundle.Controller, bundle.Endpoint, bundle.ExpiresAt, bundle.Identity, bundle.TargetPolicy, bundle.CACertificatePEM, bundle.ServerCertPEM, bundle.ServerKeyPEM, bundle.ApprovalKeyPEM}
	return json.Marshal(unsigned)
}

func parseCA(certificatePEM, keyPEM []byte) (*x509.Certificate, ed25519.PrivateKey, error) {
	block, rest := pem.Decode(certificatePEM)
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("CA certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA {
		return nil, nil, errors.New("CA certificate is invalid")
	}
	if keyPEM == nil {
		return certificate, nil, nil
	}
	keyBlock, keyRest := pem.Decode(keyPEM)
	if keyBlock == nil || len(keyRest) != 0 || keyBlock.Type != "PRIVATE KEY" {
		return nil, nil, errors.New("CA private key PEM is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || !key.Public().(ed25519.PublicKey).Equal(certificate.PublicKey) {
		return nil, nil, errors.New("CA private key does not match its certificate")
	}
	return certificate, key, nil
}

func parseLeaf(certificatePEM, keyPEM []byte) (*x509.Certificate, ed25519.PrivateKey, error) {
	block, rest := pem.Decode(certificatePEM)
	keyBlock, keyRest := pem.Decode(keyPEM)
	if block == nil || len(rest) != 0 || keyBlock == nil || len(keyRest) != 0 {
		return nil, nil, errors.New("server certificate or key PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, nil, errors.New("server private key must be Ed25519 PKCS8")
	}
	return certificate, key, nil
}

func addRegistryEntry(path string, identity agentserver.Identity, endpoint *url.URL) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("controller server registry must already exist as a protected regular file")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var registry registryDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil || registry.Version != 1 {
		return errors.New("controller server registry is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("controller server registry contains trailing data")
	}
	if len(registry.Servers) == 0 {
		return errors.New("controller registry has no local credential template")
	}
	for _, existing := range registry.Servers {
		if existing.ServerID == identity.ServerID || existing.MachineID == identity.MachineID {
			return errors.New("server or machine identity is already registered")
		}
	}
	template := registry.Servers[0]
	serverName := endpoint.Hostname()
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	registry.Servers = append(registry.Servers, registryRegistration{
		ServerID: identity.ServerID, MachineID: identity.MachineID, BaseURL: endpoint.String(),
		CAPath: template.CAPath, CertPath: template.CertPath, KeyPath: template.KeyPath,
		ApproverCertPath: template.ApproverCertPath, ApproverKeyPath: template.ApproverKeyPath,
		ApprovalSigningKeyPath: template.ApprovalSigningKeyPath, ApprovalKeyID: template.ApprovalKeyID,
		ServerName: serverName, Enabled: true,
	})
	encoded, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot preserve controller registry ownership")
	}
	return atomicWrite(path, append(encoded, '\n'), info.Mode().Perm(), int(stat.Uid), int(stat.Gid))
}

func validateHTTPSOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("value must be an https origin without credentials, path, query, or fragment")
	}
	parsed.Path = ""
	return parsed, nil
}

func randomID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}

func writeExclusive(path string, payload []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("output path must be a clean absolute path")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func atomicWrite(path string, payload []byte, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".enroll-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chown(uid, gid); err != nil {
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func certificateBindsIdentity(certificate *x509.Certificate, identity agentserver.Identity) bool {
	expected := "spiffe://ops-agent/server/" + identity.ServerID + "/machine/" + identity.MachineID
	for _, candidate := range certificate.URIs {
		if candidate.String() == expected {
			return true
		}
	}
	return false
}

func mustEndpointHost(value string) string {
	parsed, _ := url.Parse(value)
	return parsed.Hostname()
}

func mustJSON(value interface{}) []byte {
	payload, _ := json.Marshal(value)
	return payload
}

func SanitizeMachineID(value string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	random, _ := randomID("machine-")
	return random
}
