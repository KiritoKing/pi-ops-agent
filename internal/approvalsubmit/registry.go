package approvalsubmit

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const (
	maxRegistryBytes  = protocol.MaxFrameBytes
	maxCertificatePEM = 128 * 1024
	maxPrivateKeyPEM  = 32 * 1024
)

var approvalKeyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$`)

type ServerRegistration struct {
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

type registryDocument struct {
	Version int                  `json:"version"`
	Servers []ServerRegistration `json:"servers"`
}

type LoadedServer struct {
	Registration     ServerRegistration
	TLSConfig        *tls.Config
	SigningKey       func() (ed25519.PrivateKey, error)
	ReceiptDomain    string
	ReceiptKeyID     string
	ReceiptPublicKey ed25519.PublicKey
}

func LoadFixedServer(request Request) (LoadedServer, error) {
	return loadServer(RegistryPath, request, 0)
}

func loadServer(registryPath string, request Request, ownerUID uint32) (LoadedServer, error) {
	payload, err := readOwnedFile(registryPath, ownerUID, maxRegistryBytes, false)
	if err != nil {
		return LoadedServer{}, fmt.Errorf("load root-owned server registry: %w", err)
	}
	document, err := parseRegistry(payload)
	if err != nil {
		return LoadedServer{}, err
	}
	var selected *ServerRegistration
	for index := range document.Servers {
		candidate := &document.Servers[index]
		if candidate.ServerID == request.ServerID {
			selected = candidate
			break
		}
	}
	if selected == nil || !selected.Enabled || selected.MachineID != request.MachineID {
		return LoadedServer{}, errors.New("requested server does not resolve to an enabled pinned server and machine")
	}
	if selected.ApproverCertPath == "" || selected.ApproverKeyPath == "" ||
		selected.ApprovalSigningKeyPath == "" || selected.ApprovalKeyID == "" {
		return LoadedServer{}, errors.New("server registration has no complete root-owned approver credentials")
	}
	receiptDomain, err := brokerDomainForChangeID(request.ChangeID)
	if err != nil {
		return LoadedServer{}, err
	}
	receiptKeyID, receiptPublicKeyPath := selected.CoreReceiptKeyID, selected.CoreReceiptPublicKeyPath
	if receiptDomain == "pve" {
		receiptKeyID, receiptPublicKeyPath = selected.PVEReceiptKeyID, selected.PVEReceiptPublicKeyPath
	}
	if receiptKeyID == "" || receiptPublicKeyPath == "" {
		return LoadedServer{}, fmt.Errorf("server registration has no complete %s broker receipt verifier", receiptDomain)
	}
	caPEM, err := readOwnedFile(selected.CAPath, ownerUID, maxCertificatePEM, false)
	if err != nil {
		return LoadedServer{}, fmt.Errorf("load approval CA: %w", err)
	}
	certPEM, err := readOwnedFile(selected.ApproverCertPath, ownerUID, maxCertificatePEM, false)
	if err != nil {
		return LoadedServer{}, fmt.Errorf("load approver certificate: %w", err)
	}
	keyPEM, err := readOwnedFile(selected.ApproverKeyPath, ownerUID, maxPrivateKeyPEM, true)
	if err != nil {
		return LoadedServer{}, fmt.Errorf("load approver TLS private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return LoadedServer{}, fmt.Errorf("parse approver TLS identity: %w", err)
	}
	if len(certificate.Certificate) != 1 {
		return LoadedServer{}, errors.New("approver TLS identity must contain exactly one leaf certificate")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return LoadedServer{}, fmt.Errorf("parse approver leaf certificate: %w", err)
	}
	if !hasOnlyApproverRole(leaf) {
		return LoadedServer{}, errors.New("approver TLS certificate must contain only the approver role URI")
	}
	certificate.Leaf = leaf
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return LoadedServer{}, errors.New("approval CA contains no certificate")
	}
	base, _ := url.Parse(selected.BaseURL)
	serverName := selected.ServerName
	if serverName == "" {
		serverName = base.Hostname()
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: serverName,
	}
	signingPath := selected.ApprovalSigningKeyPath
	receiptPublicPEM, err := readOwnedFile(receiptPublicKeyPath, ownerUID, maxPrivateKeyPEM, false)
	if err != nil {
		return LoadedServer{}, fmt.Errorf("load %s broker receipt public key: %w", receiptDomain, err)
	}
	receiptPublicKey, err := parseEd25519PublicKey(receiptPublicPEM)
	if err != nil {
		return LoadedServer{}, fmt.Errorf("parse %s broker receipt public key: %w", receiptDomain, err)
	}
	return LoadedServer{
		Registration:  *selected,
		TLSConfig:     tlsConfig,
		ReceiptDomain: receiptDomain, ReceiptKeyID: receiptKeyID,
		ReceiptPublicKey: append(ed25519.PublicKey(nil), receiptPublicKey...),
		SigningKey: func() (ed25519.PrivateKey, error) {
			payload, err := readOwnedFile(signingPath, ownerUID, maxPrivateKeyPEM, true)
			if err != nil {
				return nil, fmt.Errorf("load approval signing key: %w", err)
			}
			return parseEd25519PrivateKey(payload)
		},
	}, nil
}

func parseRegistry(payload []byte) (registryDocument, error) {
	var document registryDocument
	if err := strictDecode(payload, &document); err != nil {
		return registryDocument{}, fmt.Errorf("decode server registry: %w", err)
	}
	if document.Version != 1 || len(document.Servers) > 1024 {
		return registryDocument{}, errors.New("server registry has an unsupported version or too many entries")
	}
	serverIDs := make(map[string]struct{}, len(document.Servers))
	machineIDs := make(map[string]struct{}, len(document.Servers))
	for index := range document.Servers {
		registration := &document.Servers[index]
		if err := validateRegistration(*registration); err != nil {
			return registryDocument{}, fmt.Errorf("server registry entry %d: %w", index, err)
		}
		if _, exists := serverIDs[registration.ServerID]; exists {
			return registryDocument{}, fmt.Errorf("server registry contains duplicate serverId %q", registration.ServerID)
		}
		if _, exists := machineIDs[registration.MachineID]; exists {
			return registryDocument{}, fmt.Errorf("server registry contains duplicate machineId %q", registration.MachineID)
		}
		serverIDs[registration.ServerID] = struct{}{}
		machineIDs[registration.MachineID] = struct{}{}
	}
	return document, nil
}

func validateRegistration(registration ServerRegistration) error {
	if !stableIDPattern.MatchString(registration.ServerID) || !stableIDPattern.MatchString(registration.MachineID) || registration.ServerID == registration.MachineID {
		return errors.New("registration has an invalid stable server or machine identity")
	}
	parsed, err := url.Parse(registration.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawPath != "" || parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("baseUrl must be an HTTPS origin without credentials, path, query, or fragment")
	}
	paths := []string{registration.CAPath, registration.CertPath, registration.KeyPath}
	configuredObserverFields := 0
	for _, path := range []string{registration.ObserverCertPath, registration.ObserverKeyPath} {
		if path != "" {
			configuredObserverFields++
			paths = append(paths, path)
		}
	}
	if configuredObserverFields != 0 && configuredObserverFields != 2 {
		return errors.New("both observer credential fields must be configured together")
	}
	approvalPaths := []string{registration.ApproverCertPath, registration.ApproverKeyPath, registration.ApprovalSigningKeyPath}
	configuredApprovalFields := 0
	for _, path := range approvalPaths {
		if path != "" {
			configuredApprovalFields++
			paths = append(paths, path)
		}
	}
	if registration.ApprovalKeyID != "" {
		configuredApprovalFields++
	}
	if configuredApprovalFields != 0 && configuredApprovalFields != 4 {
		return errors.New("all approver credential fields must be configured together")
	}
	if registration.ApprovalKeyID != "" && !approvalKeyIDPattern.MatchString(registration.ApprovalKeyID) {
		return errors.New("approvalKeyId is invalid")
	}
	receiptPairs := []struct {
		label string
		keyID string
		path  string
	}{
		{label: "core", keyID: registration.CoreReceiptKeyID, path: registration.CoreReceiptPublicKeyPath},
		{label: "pve", keyID: registration.PVEReceiptKeyID, path: registration.PVEReceiptPublicKeyPath},
	}
	for _, pair := range receiptPairs {
		if (pair.keyID == "") != (pair.path == "") {
			return fmt.Errorf("both %s broker receipt fields must be configured together", pair.label)
		}
		if pair.keyID != "" {
			if !protocol.ValidBrokerReceiptKeyID(pair.keyID) || !validAbsolutePath(pair.path) {
				return fmt.Errorf("%s broker receipt key ID or public key path is invalid", pair.label)
			}
			paths = append(paths, pair.path)
		}
	}
	if registration.CoreReceiptKeyID != "" && registration.PVEReceiptKeyID != "" &&
		(registration.CoreReceiptKeyID == registration.PVEReceiptKeyID ||
			registration.CoreReceiptPublicKeyPath == registration.PVEReceiptPublicKeyPath) {
		return errors.New("core and PVE broker receipts must use separate keys and paths")
	}
	for _, path := range paths {
		if !validAbsolutePath(path) {
			return errors.New("credential paths must be clean bounded absolute paths")
		}
	}
	if len(registration.ServerName) > 253 || containsUnsafeControl(registration.ServerName) {
		return errors.New("serverName is invalid")
	}
	return nil
}

func validAbsolutePath(path string) bool {
	return path != "" && len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path && !containsUnsafeControl(path)
}

func readOwnedFile(path string, ownerUID uint32, maxBytes int64, private bool) ([]byte, error) {
	if !validAbsolutePath(path) || maxBytes < 1 {
		return nil, errors.New("file path or size bound is invalid")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open security file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxBytes ||
		info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errors.New("security file has an unsafe owner, type, mode, or size")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key must not be accessible to group or other users")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) < 1 || int64(len(payload)) > maxBytes {
		return nil, errors.New("security file changed size while it was read")
	}
	return payload, nil
}

func parseEd25519PrivateKey(payload []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytesTrimSpace(rest)) != 0 {
		return nil, errors.New("approval signing key must contain one PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse approval signing key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("approval signing key must be Ed25519")
	}
	return privateKey, nil
}

func parseEd25519PublicKey(payload []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytesTrimSpace(rest)) != 0 {
		return nil, errors.New("broker receipt public key must contain one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse broker receipt public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("broker receipt public key must be Ed25519")
	}
	return publicKey, nil
}

func hasOnlyApproverRole(certificate *x509.Certificate) bool {
	if certificate == nil || len(certificate.URIs) != 1 || certificate.URIs[0] == nil {
		return false
	}
	return certificate.URIs[0].String() == "spiffe://ops-agent/role/approver"
}

func bytesTrimSpace(value []byte) []byte {
	return []byte(strings.TrimSpace(string(value)))
}
