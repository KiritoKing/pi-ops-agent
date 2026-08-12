package roothelper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

// BrokerReceiptSigner owns the root-only attestation key for exactly one
// broker domain. The private key is intentionally not exposed to callers.
type BrokerReceiptSigner struct {
	KeyID      string
	Domain     string
	privateKey ed25519.PrivateKey
}

func NewBrokerReceiptSigner(keyID, domain string, privateKey ed25519.PrivateKey) (*BrokerReceiptSigner, error) {
	if !protocol.ValidBrokerReceiptKeyID(keyID) || !protocol.ValidBrokerReceiptDomain(domain) {
		return nil, errors.New("broker receipt key ID or domain is invalid")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("broker receipt private key must be Ed25519")
	}
	derived := ed25519.NewKeyFromSeed(privateKey.Seed())
	if !bytes.Equal(derived, privateKey) {
		return nil, errors.New("broker receipt private key has an inconsistent public component")
	}
	return &BrokerReceiptSigner{
		KeyID: keyID, Domain: domain, privateKey: append(ed25519.PrivateKey(nil), privateKey...),
	}, nil
}

// LoadBrokerReceiptSigner reads one PKCS8 Ed25519 key without following a
// symlink. Production callers require a root-owned, owner-only regular file;
// tests may disable only the ownership check, never the mode check.
func LoadBrokerReceiptSigner(keyID, domain, path string, requireRootOwner bool) (*BrokerReceiptSigner, error) {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\x00\r\n") {
		return nil, errors.New("broker receipt private key path is required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open broker receipt private key")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 32*1024 || info.Mode().Perm()&0o077 != 0 ||
		info.Mode().Perm()&0o400 == 0 || info.Mode().Perm()&0o100 != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errors.New("broker receipt private key must be an owner-only regular file")
	}
	if requireRootOwner {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return nil, errors.New("broker receipt private key must be owned by root")
		}
	}
	payload, err := io.ReadAll(io.LimitReader(file, 32*1024+1))
	if err != nil {
		return nil, err
	}
	if len(payload) < 1 || len(payload) > 32*1024 {
		return nil, errors.New("broker receipt private key changed size while it was read")
	}
	block, rest := pem.Decode(payload)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("broker receipt private key must contain one PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse broker receipt private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("broker receipt private key must be Ed25519 PKCS8")
	}
	return NewBrokerReceiptSigner(keyID, domain, privateKey)
}

func (s *BrokerReceiptSigner) ConfiguredFor(domain string) bool {
	return s != nil && s.Domain == domain && protocol.ValidBrokerReceiptKeyID(s.KeyID) && len(s.privateKey) == ed25519.PrivateKeySize
}

func (s *BrokerReceiptSigner) Sign(request protocol.Request, response protocol.Response, planHash string, issuedAt time.Time) (protocol.Response, error) {
	if !s.ConfiguredFor(s.Domain) {
		return protocol.Response{}, errors.New("broker receipt signer is invalid")
	}
	claims := protocol.BrokerReceiptClaims{
		KeyID: s.KeyID, Domain: s.Domain, RequestID: request.RequestID, Method: request.Method,
		ServerID: request.ServerID, MachineID: request.MachineID, TargetID: request.TargetID,
		ChangeID: request.ChangeID, PlanHash: planHash,
		PluginID: request.WorkloadCommand.PluginID, PluginDigest: request.WorkloadCommand.PluginDigest,
		ProfileKey: request.WorkloadCommand.ProfileKey,
	}
	return protocol.SignBrokerResponse(response, claims, issuedAt, s.privateKey)
}

func (s *BrokerReceiptSigner) Verify(request protocol.Request, response protocol.Response, planHash string, now time.Time) error {
	if !s.ConfiguredFor(s.Domain) {
		return errors.New("broker receipt signer is invalid")
	}
	claims := protocol.BrokerReceiptClaims{
		KeyID: s.KeyID, Domain: s.Domain, RequestID: request.RequestID, Method: request.Method,
		ServerID: request.ServerID, MachineID: request.MachineID, TargetID: request.TargetID,
		ChangeID: request.ChangeID, PlanHash: planHash,
		PluginID: request.WorkloadCommand.PluginID, PluginDigest: request.WorkloadCommand.PluginDigest,
		ProfileKey: request.WorkloadCommand.ProfileKey,
	}
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	return protocol.VerifyBrokerResponse(response, claims, now, publicKey)
}
