package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const (
	Version             = 2
	installedVersion    = 1
	coreReceiptKeyID    = "local-core-receipt-v1"
	pveReceiptKeyID     = "local-pve-receipt-v1"
	maxReceiptPEM       = 16 * 1024
	maxEnrollmentFile   = 128 * 1024
	remoteReceiptFolder = "remotes"
)

type receiptKeyMaterial struct {
	KeyID         string
	PrivateKeyPEM string
	PublicKeyPEM  string
}

type Bundle struct {
	Version               int                  `json:"version"`
	Controller            string               `json:"controller"`
	Endpoint              string               `json:"endpoint"`
	ExpiresAt             string               `json:"expiresAt"`
	Identity              agentserver.Identity `json:"identity"`
	TargetPolicy          json.RawMessage      `json:"targetPolicy"`
	CACertificatePEM      string               `json:"caCertificatePem"`
	ServerCertPEM         string               `json:"serverCertificatePem"`
	ServerKeyPEM          string               `json:"serverPrivateKeyPem"`
	ApprovalKeyPEM        string               `json:"approvalPublicKeyPem"`
	CoreReceiptKeyID      string               `json:"coreReceiptKeyId"`
	CoreReceiptPrivatePEM string               `json:"coreReceiptPrivateKeyPem"`
	CoreReceiptPublicPEM  string               `json:"coreReceiptPublicKeyPem"`
	PVEReceiptKeyID       string               `json:"pveReceiptKeyId,omitempty"`
	PVEReceiptPrivatePEM  string               `json:"pveReceiptPrivateKeyPem,omitempty"`
	PVEReceiptPublicPEM   string               `json:"pveReceiptPublicKeyPem,omitempty"`
	Signature             string               `json:"signature"`
}

type IssueOptions struct {
	Controller         string
	ControllerCASHA256 string
	Endpoint           string
	MachineID          string
	MachineName        string
	OutputPath         string
	ConfigRoot         string
	PVE                bool
	Now                time.Time
}

type InstallOptions struct {
	Controller         string
	ControllerCASHA256 string
	BundlePath         string
	ConfigRoot         string
	ServerUser         string
	ReceiptPublicGroup string
	Now                time.Time
}

// ValidateInstalledOptions identifies the immutable enrollment trust binding
// that an endpoint must already have before a join-mode release upgrade can
// reuse it. Validation never rewrites endpoint identity, policy, TLS material,
// or broker receipt keys.
type ValidateInstalledOptions struct {
	Controller         string
	ControllerCASHA256 string
	ConfigRoot         string
	ServerUser         string
	ReceiptPublicGroup string
	Now                time.Time
}

type installedEndpointEnrollment struct {
	Version            int    `json:"version"`
	Controller         string `json:"controller"`
	Endpoint           string `json:"endpoint"`
	ControllerCASHA256 string `json:"controllerCaSha256"`
	ServerID           string `json:"serverId"`
	MachineID          string `json:"machineId"`
	PVE                bool   `json:"pve"`
}

type registryDocument struct {
	Version int                    `json:"version"`
	Servers []registryRegistration `json:"servers"`
}

type registryRegistration struct {
	ServerID                 string `json:"serverId"`
	MachineID                string `json:"machineId"`
	BaseURL                  string `json:"baseUrl"`
	CAPath                   string `json:"caPath"`
	CertPath                 string `json:"certPath"`
	KeyPath                  string `json:"keyPath"`
	ObserverCertPath         string `json:"observerCertPath,omitempty"`
	ObserverKeyPath          string `json:"observerKeyPath,omitempty"`
	ApproverCertPath         string `json:"approverCertPath,omitempty"`
	ApproverKeyPath          string `json:"approverKeyPath,omitempty"`
	ApprovalSigningKeyPath   string `json:"approvalSigningKeyPath,omitempty"`
	ApprovalKeyID            string `json:"approvalKeyId,omitempty"`
	CoreReceiptKeyID         string `json:"coreReceiptKeyId,omitempty"`
	CoreReceiptPublicKeyPath string `json:"coreReceiptPublicKeyPath,omitempty"`
	PVEReceiptKeyID          string `json:"pveReceiptKeyId,omitempty"`
	PVEReceiptPublicKeyPath  string `json:"pveReceiptPublicKeyPath,omitempty"`
	ServerName               string `json:"serverName,omitempty"`
	Enabled                  bool   `json:"enabled"`
}

type controllerReceiptVerifiers struct {
	Directory         string
	CoreKeyID         string
	CorePublicKeyPath string
	PVEKeyID          string
	PVEPublicKeyPath  string
}

type endpointReceiptStaging struct {
	stagingRoot string
	finalRoot   string
}

type endpointEnrollmentWrite struct {
	path    string
	payload []byte
	mode    os.FileMode
	uid     int
	gid     int
}

func (staging *endpointReceiptStaging) cleanup() {
	if staging == nil || staging.stagingRoot == "" {
		return
	}
	_ = cleanupReceiptTree(staging.stagingRoot)
}

func (staging *endpointReceiptStaging) commit() error {
	if staging == nil || staging.stagingRoot == "" || staging.finalRoot == "" {
		return errors.New("broker receipt staging is invalid")
	}
	if _, err := os.Lstat(staging.finalRoot); err == nil {
		return errors.New("broker receipt destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDirectory(staging.stagingRoot); err != nil {
		return err
	}
	if err := os.Rename(staging.stagingRoot, staging.finalRoot); err != nil {
		return err
	}
	staging.stagingRoot = ""
	return syncDirectory(filepath.Dir(staging.finalRoot))
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
	policyPayload := initialEndpointPolicy(policyRevision)
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
	coreReceipt, err := generateReceiptKeyMaterial(coreReceiptKeyID)
	if err != nil {
		return fmt.Errorf("generate core broker receipt key: %w", err)
	}
	var pveReceipt *receiptKeyMaterial
	if options.PVE {
		generated, generateErr := generateReceiptKeyMaterial(pveReceiptKeyID)
		if generateErr != nil {
			return fmt.Errorf("generate PVE broker receipt key: %w", generateErr)
		}
		pveReceipt = &generated
	}
	caCertificate, caKey, err := parseCA(caCertificatePEM, caKeyPEM)
	if err != nil {
		return err
	}
	if options.ControllerCASHA256 != "" {
		if err := verifyControllerCAFingerprint(caCertificate, options.ControllerCASHA256); err != nil {
			return fmt.Errorf("controller CA changed during enrollment issuance: %w", err)
		}
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
		CACertificatePEM:      string(caCertificatePEM),
		ServerCertPEM:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})),
		ServerKeyPEM:          string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		ApprovalKeyPEM:        string(approvalKeyPEM),
		CoreReceiptKeyID:      coreReceipt.KeyID,
		CoreReceiptPrivatePEM: coreReceipt.PrivateKeyPEM,
		CoreReceiptPublicPEM:  coreReceipt.PublicKeyPEM,
	}
	if pveReceipt != nil {
		bundle.PVEReceiptKeyID = pveReceipt.KeyID
		bundle.PVEReceiptPrivatePEM = pveReceipt.PrivateKeyPEM
		bundle.PVEReceiptPublicPEM = pveReceipt.PublicKeyPEM
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
	verifiers, err := installControllerReceiptVerifiers(options.ConfigRoot, identity.ServerID,
		coreReceipt.PublicKeyPEM, publicPEM(pveReceipt))
	if err != nil {
		return errors.Join(err, removeEnrollmentOutput(options.OutputPath))
	}
	if err := addRegistryEntry(filepath.Join(options.ConfigRoot, "servers.json"), identity, endpointURL,
		verifiers); err != nil {
		return errors.Join(err, removeEnrollmentOutput(options.OutputPath),
			cleanupControllerReceiptVerifiers(verifiers))
	}
	return nil
}

func initialEndpointPolicy(revision string) []byte {
	return []byte(fmt.Sprintf(`{"version":1,"revision":%q,"targets":[{"id":"target-local-system","account":"root","displayName":"Local system","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"authorization":{"standingScopes":[]}}]}`, revision))
}

func removeEnrollmentOutput(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
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
	if options.ReceiptPublicGroup == "" {
		options.ReceiptPublicGroup = "ops-agent-server"
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	if options.ControllerCASHA256 == "" {
		return errors.New("endpoint enrollment requires an externally pinned controller CA SHA-256 fingerprint")
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
	caCertificate, err := verifyBundleAuthority(bundle, options.ControllerCASHA256)
	if err != nil {
		return err
	}
	if _, err := agentserver.ParseIdentity(mustJSON(bundle.Identity)); err != nil {
		return err
	}
	if _, err := targetpolicy.Parse(bundle.TargetPolicy); err != nil {
		return err
	}
	coreReceipt, pveReceipt, err := validateBundleReceiptKeys(bundle)
	if err != nil {
		return err
	}
	if err := validatePVEEnrollmentMode(pveReceipt != nil,
		executableRegularFile("/usr/bin/pvesh")); err != nil {
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
	receiptPublicGroup, err := user.LookupGroup(options.ReceiptPublicGroup)
	if err != nil {
		return err
	}
	receiptPublicGID, err := strconv.Atoi(receiptPublicGroup.Gid)
	if err != nil || receiptPublicGID <= 0 {
		return errors.New("broker receipt reader group has an invalid GID")
	}
	if err := verifyProtectedRootDirectory(options.ConfigRoot); err != nil {
		return err
	}
	receiptStaging, err := stageEndpointReceiptKeys(options.ConfigRoot, coreReceipt,
		pveReceipt, receiptPublicGID)
	if err != nil {
		return err
	}
	defer receiptStaging.cleanup()
	tlsRoot := filepath.Join(options.ConfigRoot, "tls")
	if info, statErr := os.Lstat(tlsRoot); statErr == nil &&
		(!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("endpoint TLS path must be a real directory")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := os.MkdirAll(tlsRoot, 0o755); err != nil {
		return err
	}
	if err := os.Chown(tlsRoot, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(tlsRoot, 0o755); err != nil {
		return err
	}
	installedPayload, err := json.Marshal(installedEndpointEnrollment{
		Version: installedVersion, Controller: bundle.Controller, Endpoint: bundle.Endpoint,
		ControllerCASHA256: controllerCAFingerprint(caCertificate),
		ServerID:           bundle.Identity.ServerID,
		MachineID:          bundle.Identity.MachineID,
		PVE:                pveReceipt != nil,
	})
	if err != nil {
		return err
	}
	writes := []endpointEnrollmentWrite{
		{filepath.Join(options.ConfigRoot, "endpoint-enrollment.json"), append(installedPayload, '\n'), 0o640, 0, gid},
		{filepath.Join(options.ConfigRoot, "server-identity.json"), append(mustJSON(bundle.Identity), '\n'), 0o640, 0, gid},
		{filepath.Join(options.ConfigRoot, "targets.json"), append(bundle.TargetPolicy, '\n'), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "ca.crt"), []byte(bundle.CACertificatePEM), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "client-ca.crt"), []byte(bundle.CACertificatePEM), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "server.crt"), []byte(bundle.ServerCertPEM), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "server.key"), []byte(bundle.ServerKeyPEM), 0o640, 0, gid},
		{filepath.Join(tlsRoot, "approval.pub.pem"), []byte(bundle.ApprovalKeyPEM), 0o644, 0, 0},
	}
	if err := commitEndpointEnrollment(writes, receiptStaging, 0); err != nil {
		return err
	}
	return nil
}

// ValidateInstalled verifies a complete, previously enrolled endpoint before
// the release installer reuses it. It is intentionally read-only: a partial,
// stale, or permission-damaged topology is an error rather than an invitation
// to regenerate or overwrite identity, policy, TLS, or receipt material.
func ValidateInstalled(options ValidateInstalledOptions) error {
	if os.Geteuid() != 0 {
		return errors.New("installed endpoint validation must run as root")
	}
	if options.ConfigRoot == "" {
		options.ConfigRoot = "/etc/ops-agent"
	}
	if options.ServerUser == "" {
		options.ServerUser = "ops-agent-server"
	}
	if options.ReceiptPublicGroup == "" {
		options.ReceiptPublicGroup = "ops-agent-server"
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	account, err := user.Lookup(options.ServerUser)
	if err != nil {
		return err
	}
	serverGID, err := strconv.Atoi(account.Gid)
	if err != nil || serverGID <= 0 {
		return errors.New("endpoint server account has an invalid GID")
	}
	receiptGroup, err := user.LookupGroup(options.ReceiptPublicGroup)
	if err != nil {
		return err
	}
	receiptGID, err := strconv.Atoi(receiptGroup.Gid)
	if err != nil || receiptGID <= 0 {
		return errors.New("broker receipt reader group has an invalid GID")
	}
	return validateInstalledEndpoint(options, 0, 0, serverGID, receiptGID,
		executableRegularFile("/usr/bin/pvesh"))
}

func validateInstalledEndpoint(options ValidateInstalledOptions, rootUID, rootGID,
	serverGID, receiptGID int, hostHasPVE bool) error {
	if !filepath.IsAbs(options.ConfigRoot) || filepath.Clean(options.ConfigRoot) != options.ConfigRoot {
		return errors.New("configuration root must be a clean absolute path")
	}
	if options.ControllerCASHA256 == "" {
		return errors.New("installed endpoint validation requires an externally pinned controller CA SHA-256 fingerprint")
	}
	controllerURL, err := validateHTTPSOrigin(options.Controller)
	if err != nil {
		return fmt.Errorf("controller: %w", err)
	}
	if err := verifyOwnedDirectory(options.ConfigRoot, rootUID, rootGID, 0o755); err != nil {
		return err
	}
	tlsRoot := filepath.Join(options.ConfigRoot, "tls")
	receiptRoot := filepath.Join(options.ConfigRoot, "broker-receipts")
	privateRoot := filepath.Join(receiptRoot, "private")
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{tlsRoot, 0o755},
		{receiptRoot, 0o755},
		{privateRoot, 0o700},
	} {
		if err := verifyOwnedDirectory(directory.path, rootUID, rootGID, directory.mode); err != nil {
			return err
		}
	}
	metadataPayload, err := readOwnedEnrollmentFile(
		filepath.Join(options.ConfigRoot, "endpoint-enrollment.json"), rootUID, serverGID, 0o640, maxEnrollmentFile)
	if err != nil {
		return err
	}
	metadata, err := parseInstalledEndpointEnrollment(metadataPayload)
	if err != nil {
		return err
	}
	if metadata.Controller != controllerURL.String() {
		return errors.New("installed endpoint is bound to another controller")
	}
	endpointURL, err := validateHTTPSOrigin(metadata.Endpoint)
	if err != nil {
		return fmt.Errorf("installed endpoint origin: %w", err)
	}
	identityPayload, err := readOwnedEnrollmentFile(
		filepath.Join(options.ConfigRoot, "server-identity.json"), rootUID, serverGID, 0o640, maxEnrollmentFile)
	if err != nil {
		return err
	}
	identity, err := agentserver.ParseIdentity(identityPayload)
	if err != nil {
		return err
	}
	if identity.Account != options.ServerUser || metadata.ServerID != identity.ServerID ||
		metadata.MachineID != identity.MachineID {
		return errors.New("installed enrollment metadata does not bind the server identity")
	}
	policyPayload, err := readOwnedEnrollmentFile(
		filepath.Join(options.ConfigRoot, "targets.json"), rootUID, serverGID, 0o640, maxEnrollmentFile)
	if err != nil {
		return err
	}
	if _, err := targetpolicy.Parse(policyPayload); err != nil {
		return fmt.Errorf("validate installed target policy: %w", err)
	}
	caPayload, err := readOwnedEnrollmentFile(
		filepath.Join(tlsRoot, "ca.crt"), rootUID, serverGID, 0o640, maxEnrollmentFile)
	if err != nil {
		return err
	}
	clientCAPayload, err := readOwnedEnrollmentFile(
		filepath.Join(tlsRoot, "client-ca.crt"), rootUID, serverGID, 0o640, maxEnrollmentFile)
	if err != nil {
		return err
	}
	if !bytes.Equal(caPayload, clientCAPayload) {
		return errors.New("installed server client CA does not match the enrollment CA")
	}
	caCertificate, _, err := parseCA(caPayload, nil)
	if err != nil {
		return err
	}
	if err := verifyControllerCAFingerprint(caCertificate, options.ControllerCASHA256); err != nil {
		return err
	}
	actualFingerprint := controllerCAFingerprint(caCertificate)
	if metadata.ControllerCASHA256 != actualFingerprint || metadata.ControllerCASHA256 != options.ControllerCASHA256 {
		return errors.New("installed enrollment metadata does not bind the pinned controller CA")
	}
	serverCertificatePayload, err := readOwnedEnrollmentFile(
		filepath.Join(tlsRoot, "server.crt"), rootUID, serverGID, 0o640, maxEnrollmentFile)
	if err != nil {
		return err
	}
	serverKeyPayload, err := readOwnedEnrollmentFile(
		filepath.Join(tlsRoot, "server.key"), rootUID, serverGID, 0o640, maxEnrollmentFile)
	if err != nil {
		return err
	}
	serverCertificate, serverKey, err := parseLeaf(serverCertificatePayload, serverKeyPayload)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCertificate)
	if _, err := serverCertificate.Verify(x509.VerifyOptions{
		Roots: pool, DNSName: endpointURL.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: options.Now,
	}); err != nil {
		return fmt.Errorf("verify installed server certificate: %w", err)
	}
	if !serverKey.Public().(ed25519.PublicKey).Equal(serverCertificate.PublicKey) ||
		!certificateBindsIdentity(serverCertificate, identity) {
		return errors.New("installed server certificate, key, and identity do not match")
	}
	approvalPayload, err := readOwnedEnrollmentFile(
		filepath.Join(tlsRoot, "approval.pub.pem"), rootUID, rootGID, 0o644, maxReceiptPEM)
	if err != nil {
		return err
	}
	if _, err := parseReceiptPublicKey(approvalPayload); err != nil {
		return fmt.Errorf("parse installed approval public key: %w", err)
	}
	corePublic, err := validateInstalledReceiptPair(
		"core", filepath.Join(privateRoot, "core.key.pem"), filepath.Join(receiptRoot, "core-public.pem"),
		rootUID, rootGID, receiptGID)
	if err != nil {
		return err
	}
	pvePrivate := filepath.Join(privateRoot, "pve.key.pem")
	pvePublic := filepath.Join(receiptRoot, "pve-public.pem")
	hasPVEPrivate, err := enrollmentPathExists(pvePrivate)
	if err != nil {
		return err
	}
	hasPVEPublic, err := enrollmentPathExists(pvePublic)
	if err != nil {
		return err
	}
	if hasPVEPrivate != hasPVEPublic {
		return errors.New("installed PVE broker receipt keypair is incomplete")
	}
	if metadata.PVE != hasPVEPrivate || metadata.PVE != hostHasPVE {
		return errors.New("installed PVE enrollment does not match this endpoint")
	}
	if hasPVEPrivate {
		pveVerifier, err := validateInstalledReceiptPair(
			"PVE", pvePrivate, pvePublic, rootUID, rootGID, receiptGID)
		if err != nil {
			return err
		}
		if corePublic.Equal(pveVerifier) {
			return errors.New("installed core and PVE broker receipt keys are not domain-separated")
		}
	}
	return nil
}

func parseInstalledEndpointEnrollment(payload []byte) (installedEndpointEnrollment, error) {
	var metadata installedEndpointEnrollment
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return installedEndpointEnrollment{}, fmt.Errorf("decode installed enrollment metadata: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return installedEndpointEnrollment{}, errors.New("decode installed enrollment metadata: trailing value")
		}
		return installedEndpointEnrollment{}, fmt.Errorf("decode installed enrollment metadata: %w", err)
	}
	if metadata.Version != installedVersion || metadata.Controller == "" || metadata.Endpoint == "" ||
		metadata.ControllerCASHA256 == "" || metadata.ServerID == "" || metadata.MachineID == "" {
		return installedEndpointEnrollment{}, errors.New("installed enrollment metadata is incomplete")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || fields["pve"] == nil {
		return installedEndpointEnrollment{}, errors.New("installed enrollment metadata is missing the PVE binding")
	}
	return metadata, nil
}

func verifyOwnedDirectory(path string, uid, gid int, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("installed enrollment directory is missing or unsafe: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid || info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("installed enrollment directory has unsafe ownership or mode: %s", path)
	}
	return nil
}

func readOwnedEnrollmentFile(path string, uid, gid int, mode os.FileMode, maxSize int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Size() < 1 || info.Size() > maxSize {
		return nil, fmt.Errorf("installed enrollment file is missing or unsafe: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid || info.Mode().Perm() != mode.Perm() {
		return nil, fmt.Errorf("installed enrollment file has unsafe ownership or mode: %s", path)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func validateInstalledReceiptPair(domain, privatePath, publicPath string, rootUID, rootGID,
	receiptGID int) (ed25519.PublicKey, error) {
	privatePayload, err := readOwnedEnrollmentFile(privatePath, rootUID, rootGID, 0o600, maxReceiptPEM)
	if err != nil {
		return nil, err
	}
	publicPayload, err := readOwnedEnrollmentFile(publicPath, rootUID, receiptGID, 0o640, maxReceiptPEM)
	if err != nil {
		return nil, err
	}
	return validateReceiptKeyMaterial(domain, receiptKeyMaterial{
		KeyID: domainReceiptKeyID(domain), PrivateKeyPEM: string(privatePayload), PublicKeyPEM: string(publicPayload),
	})
}

func domainReceiptKeyID(domain string) string {
	if domain == "PVE" {
		return pveReceiptKeyID
	}
	return coreReceiptKeyID
}

func enrollmentPathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// ControllerCAFingerprint returns the canonical SHA-256 fingerprint of the
// controller enrollment CA. It is intended for display by the trusted
// controller-side issuance command and must reach the endpoint independently
// of the bearer enrollment bundle.
func ControllerCAFingerprint(configRoot string) (string, error) {
	if configRoot == "" {
		configRoot = "/etc/ops-agent"
	}
	if !filepath.IsAbs(configRoot) || filepath.Clean(configRoot) != configRoot {
		return "", errors.New("configuration root must be a clean absolute path")
	}
	payload, err := os.ReadFile(filepath.Join(configRoot, "tls", "ca.crt"))
	if err != nil {
		return "", err
	}
	certificate, _, err := parseCA(payload, nil)
	if err != nil {
		return "", err
	}
	return controllerCAFingerprint(certificate), nil
}

func verifyBundleAuthority(bundle Bundle, expectedFingerprint string) (*x509.Certificate, error) {
	caCertificate, _, err := parseCA([]byte(bundle.CACertificatePEM), nil)
	if err != nil {
		return nil, err
	}
	if err := verifyControllerCAFingerprint(caCertificate, expectedFingerprint); err != nil {
		return nil, err
	}
	unsigned, err := bundlePayload(bundle)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawStdEncoding.DecodeString(bundle.Signature)
	caPublic, ok := caCertificate.PublicKey.(ed25519.PublicKey)
	if err != nil || !ok || !ed25519.Verify(caPublic, unsigned, signature) {
		return nil, errors.New("enrollment bundle signature is invalid")
	}
	return caCertificate, nil
}

func controllerCAFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func verifyControllerCAFingerprint(certificate *x509.Certificate, expected string) error {
	if certificate == nil || len(certificate.Raw) == 0 || len(expected) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(expected, "sha256:") {
		return errors.New("controller CA SHA-256 fingerprint is invalid")
	}
	expectedDigest, err := hex.DecodeString(strings.TrimPrefix(expected, "sha256:"))
	if err != nil || len(expectedDigest) != sha256.Size || expected != "sha256:"+hex.EncodeToString(expectedDigest) {
		return errors.New("controller CA SHA-256 fingerprint is invalid")
	}
	actualDigest := sha256.Sum256(certificate.Raw)
	if subtle.ConstantTimeCompare(expectedDigest, actualDigest[:]) != 1 {
		return errors.New("enrollment bundle is not signed by the pinned controller CA")
	}
	return nil
}

func commitEndpointEnrollment(writes []endpointEnrollmentWrite,
	receiptStaging *endpointReceiptStaging, failAfter int) error {
	for _, write := range writes {
		if _, err := os.Lstat(write.path); err == nil {
			return fmt.Errorf("enrollment destination already exists: %s", write.path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	written := make([]string, 0, len(writes))
	rollback := func(cause error) error {
		var failures []error
		failures = append(failures, cause)
		for index := len(written) - 1; index >= 0; index-- {
			if err := os.Remove(written[index]); err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, fmt.Errorf("remove partial enrollment file %s: %w", written[index], err))
			}
		}
		return errors.Join(failures...)
	}
	for index, write := range writes {
		if err := writeExclusiveOwned(write.path, write.payload, write.mode, write.uid, write.gid); err != nil {
			return rollback(err)
		}
		written = append(written, write.path)
		if failAfter > 0 && index+1 == failAfter {
			return rollback(errors.New("injected endpoint enrollment write failure"))
		}
	}
	if err := receiptStaging.commit(); err != nil {
		return rollback(err)
	}
	return nil
}

func generateReceiptKeyMaterial(keyID string) (receiptKeyMaterial, error) {
	if !protocol.ValidBrokerReceiptKeyID(keyID) {
		return receiptKeyMaterial{}, errors.New("broker receipt key ID is invalid")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return receiptKeyMaterial{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return receiptKeyMaterial{}, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return receiptKeyMaterial{}, err
	}
	return receiptKeyMaterial{
		KeyID:         keyID,
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
	}, nil
}

func publicPEM(material *receiptKeyMaterial) string {
	if material == nil {
		return ""
	}
	return material.PublicKeyPEM
}

func executableRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func validatePVEEnrollmentMode(bundleHasPVE, hostHasPVE bool) error {
	if bundleHasPVE == hostHasPVE {
		return nil
	}
	if hostHasPVE {
		return errors.New("PVE endpoint requires an enrollment bundle issued with --pve")
	}
	return errors.New("PVE enrollment bundle cannot be installed on a non-PVE endpoint")
}

func validateBundleReceiptKeys(bundle Bundle) (receiptKeyMaterial, *receiptKeyMaterial, error) {
	core := receiptKeyMaterial{
		KeyID: bundle.CoreReceiptKeyID, PrivateKeyPEM: bundle.CoreReceiptPrivatePEM,
		PublicKeyPEM: bundle.CoreReceiptPublicPEM,
	}
	if core.KeyID != coreReceiptKeyID {
		return receiptKeyMaterial{}, nil, errors.New("enrollment bundle has an invalid core broker receipt key ID")
	}
	corePublic, err := validateReceiptKeyMaterial("core", core)
	if err != nil {
		return receiptKeyMaterial{}, nil, err
	}
	pveFields := []string{bundle.PVEReceiptKeyID, bundle.PVEReceiptPrivatePEM,
		bundle.PVEReceiptPublicPEM}
	present := 0
	for _, field := range pveFields {
		if field != "" {
			present++
		}
	}
	if present == 0 {
		return core, nil, nil
	}
	if present != len(pveFields) {
		return receiptKeyMaterial{}, nil, errors.New("enrollment bundle has an incomplete PVE broker receipt keypair")
	}
	pve := &receiptKeyMaterial{
		KeyID: bundle.PVEReceiptKeyID, PrivateKeyPEM: bundle.PVEReceiptPrivatePEM,
		PublicKeyPEM: bundle.PVEReceiptPublicPEM,
	}
	if pve.KeyID != pveReceiptKeyID || pve.KeyID == core.KeyID {
		return receiptKeyMaterial{}, nil, errors.New("enrollment bundle has an invalid PVE broker receipt key ID")
	}
	pvePublic, err := validateReceiptKeyMaterial("PVE", *pve)
	if err != nil {
		return receiptKeyMaterial{}, nil, err
	}
	if corePublic.Equal(pvePublic) {
		return receiptKeyMaterial{}, nil, errors.New("core and PVE broker receipts must use separate keys")
	}
	return core, pve, nil
}

func validateReceiptKeyMaterial(domain string, material receiptKeyMaterial) (ed25519.PublicKey, error) {
	if !protocol.ValidBrokerReceiptKeyID(material.KeyID) {
		return nil, fmt.Errorf("%s broker receipt key ID is invalid", domain)
	}
	privateKey, err := parseReceiptPrivateKey([]byte(material.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse %s broker receipt private key: %w", domain, err)
	}
	publicKey, err := parseReceiptPublicKey([]byte(material.PublicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse %s broker receipt public key: %w", domain, err)
	}
	if !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		return nil, fmt.Errorf("%s broker receipt public and private keys do not match", domain)
	}
	return publicKey, nil
}

func parseReceiptPrivateKey(payload []byte) (ed25519.PrivateKey, error) {
	if len(payload) == 0 || len(payload) > maxReceiptPEM {
		return nil, errors.New("private key PEM has an invalid size")
	}
	block, rest := pem.Decode(payload)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("private key must contain one PKCS8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("private key must be Ed25519 PKCS8")
	}
	return privateKey, nil
}

func parseReceiptPublicKey(payload []byte) (ed25519.PublicKey, error) {
	if len(payload) == 0 || len(payload) > maxReceiptPEM {
		return nil, errors.New("public key PEM has an invalid size")
	}
	block, rest := pem.Decode(payload)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("public key must contain one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("public key must be Ed25519")
	}
	return publicKey, nil
}

func stageEndpointReceiptKeys(configRoot string, core receiptKeyMaterial,
	pve *receiptKeyMaterial, clientGID int) (*endpointReceiptStaging, error) {
	return stageEndpointReceiptKeysOwned(configRoot, core, pve, 0, 0, clientGID)
}

func stageEndpointReceiptKeysOwned(configRoot string, core receiptKeyMaterial,
	pve *receiptKeyMaterial, ownerUID, ownerGID, clientGID int) (*endpointReceiptStaging, error) {
	if !filepath.IsAbs(configRoot) || filepath.Clean(configRoot) != configRoot {
		return nil, errors.New("configuration root must be a clean absolute path")
	}
	finalRoot := filepath.Join(configRoot, "broker-receipts")
	if _, err := os.Lstat(finalRoot); err == nil {
		return nil, errors.New("broker receipt destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	stagingRoot, err := os.MkdirTemp(configRoot, ".broker-receipts.enroll-")
	if err != nil {
		return nil, err
	}
	staging := &endpointReceiptStaging{stagingRoot: stagingRoot, finalRoot: finalRoot}
	fail := func(cause error) (*endpointReceiptStaging, error) {
		return nil, errors.Join(cause, cleanupReceiptTree(stagingRoot))
	}
	if err := os.Chown(stagingRoot, ownerUID, ownerGID); err != nil {
		return fail(err)
	}
	if err := os.Chmod(stagingRoot, 0o755); err != nil {
		return fail(err)
	}
	privateRoot := filepath.Join(stagingRoot, "private")
	if err := os.Mkdir(privateRoot, 0o700); err != nil {
		return fail(err)
	}
	if err := os.Chown(privateRoot, ownerUID, ownerGID); err != nil {
		return fail(err)
	}
	writes := []struct {
		path    string
		payload string
		mode    os.FileMode
		gid     int
	}{
		{filepath.Join(privateRoot, "core.key.pem"), core.PrivateKeyPEM, 0o600, ownerGID},
		{filepath.Join(stagingRoot, "core-public.pem"), core.PublicKeyPEM, 0o640, clientGID},
	}
	if pve != nil {
		writes = append(writes,
			struct {
				path    string
				payload string
				mode    os.FileMode
				gid     int
			}{filepath.Join(privateRoot, "pve.key.pem"), pve.PrivateKeyPEM, 0o600, ownerGID},
			struct {
				path    string
				payload string
				mode    os.FileMode
				gid     int
			}{filepath.Join(stagingRoot, "pve-public.pem"), pve.PublicKeyPEM, 0o640, clientGID},
		)
	}
	for _, write := range writes {
		if err := writeExclusiveOwned(write.path, []byte(write.payload), write.mode, ownerUID, write.gid); err != nil {
			return fail(err)
		}
	}
	if err := syncDirectory(privateRoot); err != nil {
		return fail(err)
	}
	return staging, nil
}

func installControllerReceiptVerifiers(configRoot, serverID, corePublicPEM,
	pvePublicPEM string) (controllerReceiptVerifiers, error) {
	if !filepath.IsAbs(configRoot) || filepath.Clean(configRoot) != configRoot {
		return controllerReceiptVerifiers{}, errors.New("configuration root must be a clean absolute path")
	}
	if filepath.Base(serverID) != serverID || !strings.HasPrefix(serverID, "server-") {
		return controllerReceiptVerifiers{}, errors.New("server identity is unsafe for a receipt verifier path")
	}
	if _, err := parseReceiptPublicKey([]byte(corePublicPEM)); err != nil {
		return controllerReceiptVerifiers{}, fmt.Errorf("validate core broker receipt verifier: %w", err)
	}
	if pvePublicPEM != "" {
		corePublic, _ := parseReceiptPublicKey([]byte(corePublicPEM))
		pvePublic, err := parseReceiptPublicKey([]byte(pvePublicPEM))
		if err != nil {
			return controllerReceiptVerifiers{}, fmt.Errorf("validate PVE broker receipt verifier: %w", err)
		}
		if corePublic.Equal(pvePublic) {
			return controllerReceiptVerifiers{}, errors.New("core and PVE broker receipt verifiers must be distinct")
		}
	}
	registryPath := filepath.Join(configRoot, "servers.json")
	registryInfo, err := os.Lstat(registryPath)
	if err != nil || !registryInfo.Mode().IsRegular() || registryInfo.Mode()&os.ModeSymlink != 0 ||
		registryInfo.Mode().Perm()&0o022 != 0 {
		return controllerReceiptVerifiers{}, errors.New("controller server registry must be a protected regular file")
	}
	registryStat, ok := registryInfo.Sys().(*syscall.Stat_t)
	if !ok || registryStat.Uid != 0 || registryStat.Gid == 0 {
		return controllerReceiptVerifiers{}, errors.New("controller server registry must be root-owned with a dedicated reader group")
	}
	if err := verifyProtectedRootDirectory(configRoot); err != nil {
		return controllerReceiptVerifiers{}, err
	}
	receiptRoot := filepath.Join(configRoot, "broker-receipts")
	if err := ensureProtectedRootDirectory(receiptRoot, 0o755, 0); err != nil {
		return controllerReceiptVerifiers{}, err
	}
	remoteRoot := filepath.Join(receiptRoot, remoteReceiptFolder)
	if err := ensureProtectedRootDirectory(remoteRoot, 0o750, int(registryStat.Gid)); err != nil {
		return controllerReceiptVerifiers{}, err
	}
	serverRoot := filepath.Join(remoteRoot, serverID)
	if err := os.Mkdir(serverRoot, 0o750); err != nil {
		if errors.Is(err, os.ErrExist) {
			return controllerReceiptVerifiers{}, errors.New("controller already has receipt verifiers for the generated server identity")
		}
		return controllerReceiptVerifiers{}, err
	}
	if err := os.Chown(serverRoot, 0, int(registryStat.Gid)); err != nil {
		_ = os.Remove(serverRoot)
		return controllerReceiptVerifiers{}, err
	}
	if err := os.Chmod(serverRoot, 0o750); err != nil {
		_ = os.Remove(serverRoot)
		return controllerReceiptVerifiers{}, err
	}
	verifiers := controllerReceiptVerifiers{
		Directory: serverRoot, CoreKeyID: coreReceiptKeyID,
		CorePublicKeyPath: filepath.Join(serverRoot, "core-public.pem"),
	}
	if pvePublicPEM != "" {
		verifiers.PVEKeyID = pveReceiptKeyID
		verifiers.PVEPublicKeyPath = filepath.Join(serverRoot, "pve-public.pem")
	}
	if err := writeExclusiveOwned(verifiers.CorePublicKeyPath, []byte(corePublicPEM),
		0o640, 0, int(registryStat.Gid)); err != nil {
		return controllerReceiptVerifiers{}, errors.Join(err, cleanupControllerReceiptVerifiers(verifiers))
	}
	if verifiers.PVEPublicKeyPath != "" {
		if err := writeExclusiveOwned(verifiers.PVEPublicKeyPath, []byte(pvePublicPEM),
			0o640, 0, int(registryStat.Gid)); err != nil {
			return controllerReceiptVerifiers{}, errors.Join(err, cleanupControllerReceiptVerifiers(verifiers))
		}
	}
	if err := syncDirectory(serverRoot); err != nil {
		return controllerReceiptVerifiers{}, errors.Join(err, cleanupControllerReceiptVerifiers(verifiers))
	}
	if err := syncDirectory(remoteRoot); err != nil {
		return controllerReceiptVerifiers{}, errors.Join(err, cleanupControllerReceiptVerifiers(verifiers))
	}
	return verifiers, nil
}

func cleanupControllerReceiptVerifiers(verifiers controllerReceiptVerifiers) error {
	if verifiers.Directory == "" {
		return nil
	}
	var failures []error
	for _, path := range []string{verifiers.CorePublicKeyPath, verifiers.PVEPublicKeyPath} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	if err := os.Remove(verifiers.Directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func ensureProtectedRootDirectory(path string, mode os.FileMode, gid int) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		if err := os.Chown(path, 0, gid); err != nil {
			_ = os.Remove(path)
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			_ = os.Remove(path)
			return err
		}
		return syncDirectory(filepath.Dir(path))
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("protected path is not a real directory: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || int(stat.Gid) != gid || info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("protected directory has unsafe ownership or mode: %s", path)
	}
	return nil
}

func verifyProtectedRootDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("configuration root is not a real directory: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("configuration root has unsafe ownership or mode: %s", path)
	}
	return nil
}

func writeExclusiveOwned(path string, payload []byte, mode os.FileMode, uid, gid int) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chown(uid, gid); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func cleanupReceiptTree(root string) error {
	if root == "" {
		return nil
	}
	var failures []error
	for _, path := range []string{
		filepath.Join(root, "private", "core.key.pem"),
		filepath.Join(root, "private", "pve.key.pem"),
		filepath.Join(root, "core-public.pem"),
		filepath.Join(root, "pve-public.pem"),
	} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	for _, path := range []string{filepath.Join(root, "private"), root} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
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
		Version               int                  `json:"version"`
		Controller            string               `json:"controller"`
		Endpoint              string               `json:"endpoint"`
		ExpiresAt             string               `json:"expiresAt"`
		Identity              agentserver.Identity `json:"identity"`
		TargetPolicy          json.RawMessage      `json:"targetPolicy"`
		CACertificatePEM      string               `json:"caCertificatePem"`
		ServerCertPEM         string               `json:"serverCertificatePem"`
		ServerKeyPEM          string               `json:"serverPrivateKeyPem"`
		ApprovalKeyPEM        string               `json:"approvalPublicKeyPem"`
		CoreReceiptKeyID      string               `json:"coreReceiptKeyId"`
		CoreReceiptPrivatePEM string               `json:"coreReceiptPrivateKeyPem"`
		CoreReceiptPublicPEM  string               `json:"coreReceiptPublicKeyPem"`
		PVEReceiptKeyID       string               `json:"pveReceiptKeyId,omitempty"`
		PVEReceiptPrivatePEM  string               `json:"pveReceiptPrivateKeyPem,omitempty"`
		PVEReceiptPublicPEM   string               `json:"pveReceiptPublicKeyPem,omitempty"`
	}{bundle.Version, bundle.Controller, bundle.Endpoint, bundle.ExpiresAt, bundle.Identity,
		bundle.TargetPolicy, bundle.CACertificatePEM, bundle.ServerCertPEM,
		bundle.ServerKeyPEM, bundle.ApprovalKeyPEM, bundle.CoreReceiptKeyID,
		bundle.CoreReceiptPrivatePEM, bundle.CoreReceiptPublicPEM, bundle.PVEReceiptKeyID,
		bundle.PVEReceiptPrivatePEM, bundle.PVEReceiptPublicPEM}
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

func addRegistryEntry(path string, identity agentserver.Identity, endpoint *url.URL,
	receipts controllerReceiptVerifiers) error {
	if receipts.CoreKeyID != coreReceiptKeyID || !filepath.IsAbs(receipts.CorePublicKeyPath) ||
		filepath.Clean(receipts.CorePublicKeyPath) != receipts.CorePublicKeyPath {
		return errors.New("core broker receipt verifier registration is invalid")
	}
	if (receipts.PVEKeyID == "") != (receipts.PVEPublicKeyPath == "") {
		return errors.New("PVE broker receipt verifier registration is incomplete")
	}
	if receipts.PVEKeyID != "" && (receipts.PVEKeyID != pveReceiptKeyID ||
		!filepath.IsAbs(receipts.PVEPublicKeyPath) ||
		filepath.Clean(receipts.PVEPublicKeyPath) != receipts.PVEPublicKeyPath ||
		receipts.PVEPublicKeyPath == receipts.CorePublicKeyPath) {
		return errors.New("PVE broker receipt verifier registration is invalid")
	}
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
		ObserverCertPath: template.ObserverCertPath, ObserverKeyPath: template.ObserverKeyPath,
		ApproverCertPath: template.ApproverCertPath, ApproverKeyPath: template.ApproverKeyPath,
		ApprovalSigningKeyPath: template.ApprovalSigningKeyPath, ApprovalKeyID: template.ApprovalKeyID,
		CoreReceiptKeyID:         receipts.CoreKeyID,
		CoreReceiptPublicKeyPath: receipts.CorePublicKeyPath,
		PVEReceiptKeyID:          receipts.PVEKeyID,
		PVEReceiptPublicKeyPath:  receipts.PVEPublicKeyPath,
		ServerName:               serverName, Enabled: true,
	})
	encoded, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot preserve controller registry ownership")
	}
	return replaceRegistryAtomically(path, append(encoded, '\n'), payload, info.Mode().Perm(),
		int(stat.Uid), int(stat.Gid), syncDirectory)
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

func replaceRegistryAtomically(path string, updated, previous []byte, mode os.FileMode,
	uid, gid int, syncer func(string) error) error {
	committed, err := atomicWrite(path, updated, mode, uid, gid, syncer)
	if err == nil {
		return nil
	}
	if !committed {
		return err
	}
	// A post-rename directory sync failure means the new registry entry is
	// visible even though durability could not be proven. Restore the exact
	// protected registry snapshot before Issue removes the enrollment bundle
	// and verifier directory; otherwise a failed issuance could leave a live
	// entry pointing at deleted receipt verification material.
	_, rollbackErr := atomicWrite(path, previous, mode, uid, gid, syncer)
	if rollbackErr != nil {
		return errors.Join(err, fmt.Errorf("restore controller registry after failed commit: %w", rollbackErr))
	}
	return err
}

func atomicWrite(path string, payload []byte, mode os.FileMode, uid, gid int,
	syncer func(string) error) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".enroll-*.tmp")
	if err != nil {
		return false, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Chown(uid, gid); err != nil {
		temporary.Close()
		return false, err
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(name, path); err != nil {
		return false, err
	}
	if err := syncer(filepath.Dir(path)); err != nil {
		return true, err
	}
	return true, nil
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
