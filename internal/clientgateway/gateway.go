package clientgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const (
	PeerAPIVersion         = "agentd.client-peer/v1"
	FixedPublicSocketPath  = "/run/ops-agent/agentd/agentd.sock"
	FixedBackendSocketPath = "/run/ops-agent/agentd/backend.sock"
	maxLiveConnections     = 128
	maxLiveConnectionsUID  = 32
)

var (
	adapterIDPattern = regexp.MustCompile(`^adapter\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$`)
	digestPattern    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{6,158}[A-Za-z0-9]$`)
)

type PeerIdentity struct {
	APIVersion string `json:"apiVersion"`
	AdapterID  string `json:"adapterId"`
	Digest     string `json:"digest"`
}

type hello struct {
	Type          string       `json:"type"`
	SessionID     string       `json:"sessionId"`
	InitialPrompt *string      `json:"initialPrompt,omitempty"`
	Peer          PeerIdentity `json:"peer"`
}

type RuntimeRegistrationReader interface {
	RuntimeCurrent(pluginID string) (pluginregistry.RuntimeRegistration, error)
}

type UsernameLookup func(uid uint32) (string, error)

type Authorizer struct {
	AdministratorUID uint32
	AgentUID         uint32
	BotMuxUID        uint32
	Registry         RuntimeRegistrationReader
	LookupUsername   UsernameLookup
}

func LookupOSUsername(uid uint32) (string, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	return account.Username, nil
}

func (a Authorizer) Validate() error {
	if a.AdministratorUID == 0 || a.AgentUID == 0 || a.BotMuxUID == 0 {
		return errors.New("client gateway principals must use non-root UIDs")
	}
	if a.AdministratorUID == a.AgentUID || a.AdministratorUID == a.BotMuxUID ||
		a.AgentUID == a.BotMuxUID {
		return errors.New("client gateway principals must use distinct UIDs")
	}
	if a.Registry == nil || a.LookupUsername == nil {
		return errors.New("client gateway registry and username lookup are required")
	}
	return nil
}

func (a Authorizer) Authorize(credential peercred.Credential, identity PeerIdentity) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if credential.UID == 0 || identity.APIVersion != PeerAPIVersion ||
		!adapterIDPattern.MatchString(identity.AdapterID) ||
		!digestPattern.MatchString(identity.Digest) {
		return errors.New("client gateway peer or adapter identity is not authorized")
	}
	switch credential.UID {
	case a.AdministratorUID:
		if identity.AdapterID != "adapter.tui" {
			return errors.New("the enrolled administrator may open only adapter.tui sessions")
		}
	case a.AgentUID:
		return errors.New("agentd may not enter the client session gateway")
	case a.BotMuxUID:
		if identity.AdapterID != "adapter.botmux" {
			return errors.New("the BotMux account may open only adapter.botmux sessions")
		}
	default:
		if identity.AdapterID == "adapter.tui" || identity.AdapterID == "adapter.botmux" {
			return errors.New("reserved adapters require their exact enrolled peer UID")
		}
		username, err := a.LookupUsername(credential.UID)
		if err != nil || username != expectedAdapterAccount(identity.AdapterID) {
			return errors.New("custom adapter UID does not match the requested adapter identity")
		}
	}
	registration, err := a.Registry.RuntimeCurrent(identity.AdapterID)
	if err != nil {
		return fmt.Errorf("resolve active adapter registration: %w", err)
	}
	if registration.Kind != pluginregistry.KindAdapter ||
		registration.PluginID != identity.AdapterID || registration.Digest != identity.Digest {
		return errors.New("client gateway identity does not match the active adapter digest")
	}
	return nil
}

func expectedAdapterAccount(pluginID string) string {
	suffix := strings.ReplaceAll(strings.TrimPrefix(pluginID, "adapter."), ".", "-")
	if len(suffix) <= 20 {
		return "ops-adapter-" + suffix
	}
	digest := sha256.Sum256([]byte(pluginID))
	return "ops-adapter-" + hex.EncodeToString(digest[:])[:16]
}

// CanonicalSessionID makes the backend session namespace depend on the
// kernel-observed peer UID and the exact active Adapter identity/digest. The
// caller-provided session ID is never used as a global registry key.
func CanonicalSessionID(uid uint32, identity PeerIdentity, externalSessionID string) (string, error) {
	if uid == 0 || !adapterIDPattern.MatchString(identity.AdapterID) ||
		!digestPattern.MatchString(identity.Digest) || !sessionIDPattern.MatchString(externalSessionID) {
		return "", errors.New("client gateway session namespace input is invalid")
	}
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, "agentd-client-session-namespace-v1\x00")
	_, _ = io.WriteString(hasher, strconv.FormatUint(uint64(uid), 10))
	_, _ = io.WriteString(hasher, "\x00"+identity.AdapterID+"\x00"+identity.Digest+"\x00"+externalSessionID)
	return "gateway-" + hex.EncodeToString(hasher.Sum(nil)), nil
}

type writerLeases struct {
	mu     sync.Mutex
	active map[string]struct{}
}

type connectionAdmission struct {
	mu        sync.Mutex
	total     int
	byUID     map[uint32]int
	maxTotal  int
	maxPerUID int
}

func (limits *connectionAdmission) acquire(uid uint32) (func(), bool) {
	limits.mu.Lock()
	defer limits.mu.Unlock()
	maxTotal := limits.maxTotal
	if maxTotal == 0 {
		maxTotal = maxLiveConnections
	}
	maxPerUID := limits.maxPerUID
	if maxPerUID == 0 {
		maxPerUID = maxLiveConnectionsUID
	}
	if uid == 0 || limits.total >= maxTotal {
		return func() {}, false
	}
	if limits.byUID == nil {
		limits.byUID = make(map[uint32]int)
	}
	if limits.byUID[uid] >= maxPerUID {
		return func() {}, false
	}
	limits.total++
	limits.byUID[uid]++
	var once sync.Once
	return func() {
		once.Do(func() {
			limits.mu.Lock()
			limits.total--
			limits.byUID[uid]--
			if limits.byUID[uid] == 0 {
				delete(limits.byUID, uid)
			}
			limits.mu.Unlock()
		})
	}, true
}

func (leases *writerLeases) acquire(sessionID string) (func(), bool) {
	leases.mu.Lock()
	defer leases.mu.Unlock()
	if leases.active == nil {
		leases.active = make(map[string]struct{})
	}
	if _, exists := leases.active[sessionID]; exists {
		return func() {}, false
	}
	leases.active[sessionID] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			leases.mu.Lock()
			delete(leases.active, sessionID)
			leases.mu.Unlock()
		})
	}, true
}

// BackendDialer is a test seam for in-memory transports. Production leaves it
// nil so every connection validates the managed backend socket pathname and
// its stable filesystem identity around the Unix dial.
type BackendDialer func(context.Context) (net.Conn, error)

type Server struct {
	PublicPath       string
	BackendPath      string
	SocketGID        int
	Resolver         peercred.Resolver
	Authorizer       Authorizer
	DialBackend      BackendDialer
	HandshakeTimeout time.Duration
	WriteTimeout     time.Duration

	mu       sync.Mutex
	listener *net.UnixListener
	writers  writerLeases
	clients  connectionAdmission
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.PublicPath != FixedPublicSocketPath || s.BackendPath != FixedBackendSocketPath {
		return errors.New("client gateway must use the fixed managed socket paths")
	}
	if s.SocketGID < 1 || s.Resolver == nil {
		return errors.New("client gateway requires a peer resolver and non-root client group")
	}
	if err := s.Authorizer.Validate(); err != nil {
		return err
	}
	if err := validateSocketDirectory(filepath.Dir(s.PublicPath), s.SocketGID); err != nil {
		return err
	}
	if err := removeStaleSocket(s.PublicPath); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.PublicPath, Net: "unix"})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	defer func() {
		_ = listener.Close()
		_ = os.Remove(s.PublicPath)
	}()
	if err := os.Chmod(s.PublicPath, 0o660); err != nil {
		return err
	}
	if err := validatePublicSocket(s.PublicPath, s.SocketGID); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		credential, resolveErr := s.Resolver.Resolve(connection)
		if resolveErr != nil {
			_ = connection.Close()
			continue
		}
		release, admitted := s.clients.acquire(credential.UID)
		if !admitted {
			s.writeAdmissionError(connection)
			_ = connection.Close()
			continue
		}
		go s.serveAccepted(ctx, connection, credential, release)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *Server) serveAccepted(
	ctx context.Context,
	connection *net.UnixConn,
	credential peercred.Credential,
	release func(),
) {
	defer connection.Close()
	defer release()
	s.ServeConnection(ctx, connection, credential)
}

// ServeConnection authenticates exactly one hello using SO_PEERCRED-derived
// credentials, holds the process-global writer lease, then proxies only that
// namespaced session to agentd's owner-only backend socket.
func (s *Server) ServeConnection(ctx context.Context, client net.Conn, credential peercred.Credential) {
	_ = client.SetReadDeadline(time.Now().Add(s.handshakeTimeout()))
	payload, err := protocol.ReadFrame(client)
	if err != nil {
		return
	}
	request, err := parseHello(payload)
	if err != nil {
		s.writeError(client, "client gateway rejected an invalid hello")
		return
	}
	if err := s.Authorizer.Authorize(credential, request.Peer); err != nil {
		s.writeError(client, "client gateway rejected the peer Adapter identity")
		return
	}
	externalSessionID := request.SessionID
	canonicalSessionID, err := CanonicalSessionID(credential.UID, request.Peer, externalSessionID)
	if err != nil {
		s.writeError(client, "client gateway rejected the session namespace")
		return
	}
	release, acquired := s.writers.acquire(canonicalSessionID)
	if !acquired {
		s.writeError(client, "client gateway rejected a concurrent writer for this session")
		return
	}
	defer release()

	backend, err := s.dialBackend(ctx)
	if err != nil {
		s.writeError(client, "agentd backend is unavailable")
		return
	}
	defer backend.Close()
	request.SessionID = canonicalSessionID
	backendHello, err := json.Marshal(request)
	if err != nil || protocol.WriteFrame(backend, backendHello) != nil {
		s.writeError(client, "agentd backend rejected the authenticated session")
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	errors := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(backend, client)
		errors <- copyErr
	}()
	go func() {
		errors <- proxyBackendFrames(backend, client, canonicalSessionID, externalSessionID)
	}()
	select {
	case <-ctx.Done():
	case <-errors:
	}
}

func (s *Server) dialBackend(ctx context.Context) (net.Conn, error) {
	if s.DialBackend != nil {
		return s.DialBackend(ctx)
	}
	dialer := net.Dialer{Timeout: s.handshakeTimeout()}
	return dialValidatedBackend(ctx, s.BackendPath, func(ctx context.Context, path string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", path)
	})
}

type backendSocketIdentity struct {
	device uint64
	inode  uint64
}

type unixPathDialer func(context.Context, string) (net.Conn, error)

func dialValidatedBackend(ctx context.Context, path string, dial unixPathDialer) (net.Conn, error) {
	before, err := inspectBackendSocket(path)
	if err != nil {
		return nil, err
	}
	connection, err := dial(ctx, path)
	if err != nil {
		return nil, err
	}
	after, err := inspectBackendSocket(path)
	if err != nil || after != before {
		_ = connection.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("agentd backend socket changed during dial")
	}
	return connection, nil
}

func proxyBackendFrames(backend, client net.Conn, canonicalSessionID, externalSessionID string) error {
	for {
		payload, err := protocol.ReadFrame(backend)
		if err != nil {
			return err
		}
		rewritten, err := rewriteBackendSession(payload, canonicalSessionID, externalSessionID)
		if err != nil {
			return err
		}
		if err := protocol.WriteFrame(client, rewritten); err != nil {
			return err
		}
	}
}

func parseHello(payload []byte) (hello, error) {
	if err := protocol.ValidateUniqueJSONKeys(payload); err != nil {
		return hello{}, err
	}
	var request hello
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return hello{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return hello{}, err
	}
	if request.Type != "hello" || !sessionIDPattern.MatchString(request.SessionID) ||
		request.Peer.APIVersion != PeerAPIVersion ||
		!adapterIDPattern.MatchString(request.Peer.AdapterID) ||
		!digestPattern.MatchString(request.Peer.Digest) {
		return hello{}, errors.New("hello has an invalid type, session, peer identity, or digest")
	}
	if request.InitialPrompt != nil && len(*request.InitialPrompt) > 64*1024 {
		return hello{}, errors.New("hello initial prompt exceeds its bound")
	}
	return request, nil
}

func rewriteBackendSession(payload []byte, canonicalSessionID, externalSessionID string) ([]byte, error) {
	if err := protocol.ValidateUniqueJSONKeys(payload); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, errors.New("agentd backend response is not a JSON object")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	if raw, exists := object["sessionId"]; exists {
		var observed string
		if err := json.Unmarshal(raw, &observed); err != nil || observed != canonicalSessionID {
			return nil, errors.New("agentd backend response escaped the authenticated session namespace")
		}
		replacement, _ := json.Marshal(externalSessionID)
		object["sessionId"] = replacement
	}
	return json.Marshal(object)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON payload contains a trailing value")
		}
		return err
	}
	return nil
}

func (s *Server) writeError(connection net.Conn, message string) {
	payload, _ := json.Marshal(map[string]string{"type": "error", "message": message})
	_ = connection.SetWriteDeadline(time.Now().Add(s.writeTimeout()))
	_ = protocol.WriteFrame(connection, payload)
}

func (s *Server) writeAdmissionError(connection net.Conn) {
	payload, _ := json.Marshal(map[string]string{
		"type": "error", "message": "client gateway connection admission limit reached",
	})
	_ = connection.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
	_ = protocol.WriteFrame(connection, payload)
}

func (s *Server) handshakeTimeout() time.Duration {
	if s.HandshakeTimeout > 0 && s.HandshakeTimeout <= 30*time.Second {
		return s.HandshakeTimeout
	}
	return 10 * time.Second
}

func (s *Server) writeTimeout() time.Duration {
	if s.WriteTimeout > 0 && s.WriteTimeout <= 30*time.Second {
		return s.WriteTimeout
	}
	return 10 * time.Second
}

func validateSocketDirectory(path string, socketGID int) error {
	if path != filepath.Dir(FixedPublicSocketPath) {
		return errors.New("client gateway socket directory is not the fixed managed directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != socketGID || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o750 ||
		info.Mode()&os.ModeSetgid == 0 {
		return errors.New("client gateway directory must be the agent UID's setgid client-group directory")
	}
	return nil
}

func inspectBackendSocket(path string) (backendSocketIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return backendSocketIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode()&os.ModeSocket == 0 ||
		info.Mode().Perm() != 0o600 {
		return backendSocketIdentity{}, errors.New("agentd backend socket must be owner-only and owned by the gateway UID")
	}
	return backendSocketIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func validatePublicSocket(path string, socketGID int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != socketGID ||
		info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 {
		return errors.New("client gateway socket did not inherit the exact agent owner and client group")
	}
	return nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket client gateway path %s", path)
	}
	return os.Remove(path)
}
