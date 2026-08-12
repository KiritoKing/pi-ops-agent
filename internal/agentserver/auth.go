package agentserver

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
)

type Role string

const (
	RoleAgent    Role = "agent"
	RoleObserver Role = "observer"
	RoleApprover Role = "approver"
	RoleAdmin    Role = "admin"
)

type Principal struct {
	Role        Role
	Fingerprint string
}

func authenticate(state *tls.ConnectionState) (Principal, error) {
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return Principal{}, errors.New("a single verified client certificate is required")
	}
	certificate := state.PeerCertificates[0]
	roles := make(map[Role]struct{})
	for _, uri := range certificate.URIs {
		if role, ok := roleFromURI(uri); ok {
			roles[role] = struct{}{}
		}
	}
	if len(roles) != 1 {
		return Principal{}, errors.New("client certificate must contain exactly one ops-agent role URI")
	}
	var role Role
	for value := range roles {
		role = value
	}
	digest := sha256.Sum256(certificate.Raw)
	return Principal{Role: role, Fingerprint: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

func roleFromURI(uri *url.URL) (Role, bool) {
	if uri == nil || uri.Scheme != "spiffe" || uri.Host != "ops-agent" {
		return "", false
	}
	value := Role(strings.TrimPrefix(uri.EscapedPath(), "/role/"))
	switch value {
	case RoleAgent, RoleObserver, RoleApprover, RoleAdmin:
		return value, uri.EscapedPath() == "/role/"+string(value)
	default:
		return "", false
	}
}
