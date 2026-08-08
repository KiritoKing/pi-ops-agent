package pluginlease

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
	Version           = 1
	FixedRegistryRoot = "/var/lib/ops-agent/plugins"
	FixedSocketPath   = "/run/ops-agent/plugin-lease/lease.sock"
)

var (
	pluginIDPattern = regexp.MustCompile(`^(adapter|workload)\.[a-z0-9][a-z0-9.-]{0,63}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type Request struct {
	Version  int    `json:"version"`
	PluginID string `json:"pluginId"`
	Digest   string `json:"digest"`
}

type releaseRequest struct {
	Version int    `json:"version"`
	Action  string `json:"action"`
}

type Response struct {
	Version      int                                 `json:"version"`
	OK           bool                                `json:"ok"`
	State        string                              `json:"state,omitempty"`
	Registration *pluginregistry.RuntimeRegistration `json:"registration,omitempty"`
	Error        string                              `json:"error,omitempty"`
}

type UsernameLookup func(uid uint32) (string, error)

type Authorization struct {
	MaxDuration time.Duration
}

type Authorizer struct {
	AdministratorUID    uint32
	AgentUID            uint32
	BotMuxUID           uint32
	WorkloadMaxDuration time.Duration
	LookupUsername      UsernameLookup
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
		return errors.New("plugin lease principals must use non-root UIDs")
	}
	if a.AdministratorUID == a.AgentUID || a.AdministratorUID == a.BotMuxUID || a.AgentUID == a.BotMuxUID {
		return errors.New("plugin lease principals must use distinct UIDs")
	}
	if a.WorkloadMaxDuration <= 0 || a.WorkloadMaxDuration > 30*time.Minute {
		return errors.New("plugin workload lease duration must be positive and at most 30 minutes")
	}
	if a.LookupUsername == nil {
		return errors.New("plugin lease username lookup is required")
	}
	return nil
}

func (a Authorizer) Authorize(uid uint32, pluginID string) (Authorization, error) {
	if err := a.Validate(); err != nil {
		return Authorization{}, err
	}
	if uid == 0 || !pluginIDPattern.MatchString(pluginID) {
		return Authorization{}, errors.New("plugin lease peer or plugin identity is not authorized")
	}
	if uid == a.AdministratorUID {
		if pluginID == "adapter.tui" {
			return Authorization{}, nil
		}
		if strings.HasPrefix(pluginID, "workload.") {
			return Authorization{MaxDuration: a.WorkloadMaxDuration}, nil
		}
		return Authorization{}, errors.New("the enrolled administrator may lease only adapter.tui or workload plugins")
	}
	if uid == a.AgentUID {
		if strings.HasPrefix(pluginID, "workload.") {
			return Authorization{MaxDuration: a.WorkloadMaxDuration}, nil
		}
		return Authorization{}, errors.New("agentd may lease only workload plugins")
	}
	if uid == a.BotMuxUID {
		if pluginID == "adapter.botmux" {
			return Authorization{}, nil
		}
		return Authorization{}, errors.New("the BotMux account may lease only adapter.botmux")
	}
	if !strings.HasPrefix(pluginID, "adapter.") || pluginID == "adapter.tui" || pluginID == "adapter.botmux" {
		return Authorization{}, errors.New("custom adapter accounts may lease only their own adapter")
	}
	username, err := a.LookupUsername(uid)
	if err != nil || username != expectedAdapterAccount(pluginID) {
		return Authorization{}, errors.New("custom adapter UID does not match the requested adapter identity")
	}
	return Authorization{}, nil
}

func expectedAdapterAccount(pluginID string) string {
	suffix := strings.ReplaceAll(strings.TrimPrefix(pluginID, "adapter."), ".", "-")
	if len(suffix) <= 20 {
		return "ops-adapter-" + suffix
	}
	digest := sha256.Sum256([]byte(pluginID))
	return "ops-adapter-" + hex.EncodeToString(digest[:])[:16]
}

type admissionKey struct {
	uid      uint32
	pluginID string
}

type admission struct {
	mu                 sync.Mutex
	total              int
	byUID              map[uint32]int
	byUIDAndPlugin     map[admissionKey]int
	maxTotal           int
	maxPerUID          int
	maxPerUIDAndPlugin int
}

func newAdmission(maxTotal, maxPerUID, maxPerUIDAndPlugin int) (*admission, error) {
	if maxTotal < 1 || maxTotal > 1024 || maxPerUID < 1 || maxPerUID > maxTotal ||
		maxPerUIDAndPlugin < 1 || maxPerUIDAndPlugin > maxPerUID {
		return nil, errors.New("plugin lease admission limits are invalid")
	}
	return &admission{
		byUID: make(map[uint32]int), byUIDAndPlugin: make(map[admissionKey]int),
		maxTotal: maxTotal, maxPerUID: maxPerUID, maxPerUIDAndPlugin: maxPerUIDAndPlugin,
	}, nil
}

func (a *admission) acquireUID(uid uint32) (func(), bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total >= a.maxTotal || a.byUID[uid] >= a.maxPerUID {
		return func() {}, false
	}
	a.total++
	a.byUID[uid]++
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.total--
			a.byUID[uid]--
			if a.byUID[uid] == 0 {
				delete(a.byUID, uid)
			}
		})
	}, true
}

func (a *admission) acquirePlugin(uid uint32, pluginID string) (func(), bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := admissionKey{uid: uid, pluginID: pluginID}
	if a.byUIDAndPlugin[key] >= a.maxPerUIDAndPlugin {
		return func() {}, false
	}
	a.byUIDAndPlugin[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.byUIDAndPlugin[key]--
			if a.byUIDAndPlugin[key] == 0 {
				delete(a.byUIDAndPlugin, key)
			}
		})
	}, true
}

type Server struct {
	Path             string
	SocketGID        int
	Registry         *pluginregistry.Registry
	Resolver         peercred.Resolver
	Authorizer       Authorizer
	HandshakeTimeout time.Duration
	WriteTimeout     time.Duration
	MaxConnections   int
	MaxPerUID        int
	MaxPerUIDPlugin  int

	mu       sync.Mutex
	listener *net.UnixListener
	limits   *admission
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Path != FixedSocketPath {
		return errors.New("plugin lease server must use the fixed managed socket path")
	}
	if s.Registry == nil || s.Resolver == nil {
		return errors.New("plugin lease registry and peer resolver are required")
	}
	if err := s.Authorizer.Validate(); err != nil {
		return err
	}
	limits, err := newAdmission(s.maximumConnections(), s.maximumPerUID(), s.maximumPerUIDPlugin())
	if err != nil {
		return err
	}
	s.limits = limits
	if s.SocketGID < 1 {
		return errors.New("plugin lease socket requires a non-root client group")
	}
	if err := ensureSocketDirectory(filepath.Dir(s.Path), s.SocketGID); err != nil {
		return err
	}
	if err := removeStaleSocket(s.Path); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.Path, Net: "unix"})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	defer func() {
		_ = listener.Close()
		_ = os.Remove(s.Path)
	}()
	if err := os.Chmod(s.Path, 0o660); err != nil {
		return err
	}
	socketInfo, err := os.Lstat(s.Path)
	if err != nil {
		return err
	}
	socketOwner, ok := socketInfo.Sys().(*syscall.Stat_t)
	if !ok || int(socketOwner.Uid) != os.Geteuid() || int(socketOwner.Gid) != s.SocketGID ||
		socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o660 {
		return errors.New("plugin lease socket did not inherit the exact managed owner and client group")
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
		go s.serveAccepted(ctx, connection)
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

func (s *Server) serveAccepted(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	credential, err := s.Resolver.Resolve(connection)
	if err != nil {
		return
	}
	releaseUID, ok := s.limits.acquireUID(credential.UID)
	if !ok {
		_ = writeResponse(connection, s.writeTimeout(), Response{Version: Version, OK: false, Error: "plugin lease admission rejected for peer UID"})
		return
	}
	defer releaseUID()
	s.ServeConnection(ctx, connection, credential)
}

// ServeConnection performs one bounded handshake and holds the exact-digest
// shared registry lock until an authenticated peer releases, disconnects, the
// server exits, or a workload lease reaches its hard maximum duration.
func (s *Server) ServeConnection(ctx context.Context, connection net.Conn, credential peercred.Credential) {
	if s.Registry == nil {
		return
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-done:
		}
	}()
	_ = connection.SetReadDeadline(time.Now().Add(s.handshakeTimeout()))
	payload, err := protocol.ReadFrame(connection)
	if err != nil {
		return
	}
	request, err := parseRequest(payload)
	if err != nil {
		_ = writeResponse(connection, s.writeTimeout(), Response{Version: Version, OK: false, Error: err.Error()})
		return
	}
	if s.limits != nil {
		releasePlugin, ok := s.limits.acquirePlugin(credential.UID, request.PluginID)
		if !ok {
			_ = writeResponse(connection, s.writeTimeout(), Response{Version: Version, OK: false, Error: "plugin lease admission rejected for peer and plugin"})
			return
		}
		defer releasePlugin()
	}
	authorization, err := s.Authorizer.Authorize(credential.UID, request.PluginID)
	if err != nil {
		_ = writeResponse(connection, s.writeTimeout(), Response{Version: Version, OK: false, Error: err.Error()})
		return
	}
	registration, lease, err := s.Registry.LeaseRuntimeCurrent(request.PluginID, request.Digest)
	if err != nil {
		_ = writeResponse(connection, s.writeTimeout(), Response{Version: Version, OK: false, Error: err.Error()})
		return
	}
	defer lease.Close()
	if err := writeResponse(connection, s.writeTimeout(), Response{
		Version: Version, OK: true, State: "LEASED", Registration: &registration,
	}); err != nil {
		return
	}
	if authorization.MaxDuration > 0 {
		_ = connection.SetReadDeadline(time.Now().Add(authorization.MaxDuration))
	} else {
		_ = connection.SetReadDeadline(time.Time{})
	}
	releasePayload, err := protocol.ReadFrame(connection)
	if err != nil {
		return
	}
	if err := parseRelease(releasePayload); err != nil {
		return
	}
	if err := lease.Close(); err != nil {
		return
	}
	lease = nil
	_ = writeResponse(connection, s.writeTimeout(), Response{Version: Version, OK: true, State: "RELEASED"})
}

func parseRequest(payload []byte) (Request, error) {
	var request Request
	if err := decodeExact(payload, &request); err != nil {
		return Request{}, fmt.Errorf("invalid plugin lease request: %w", err)
	}
	if request.Version != Version || !pluginIDPattern.MatchString(request.PluginID) ||
		!digestPattern.MatchString(request.Digest) {
		return Request{}, errors.New("invalid plugin lease version, identity, or digest")
	}
	return request, nil
}

func parseRelease(payload []byte) error {
	var release releaseRequest
	if err := decodeExact(payload, &release); err != nil {
		return fmt.Errorf("invalid plugin lease release: %w", err)
	}
	if release.Version != Version || release.Action != "release" {
		return errors.New("invalid plugin lease release action")
	}
	return nil
}

func decodeExact(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("JSON payload contains trailing data")
	}
	return nil
}

func writeResponse(connection net.Conn, timeout time.Duration, response Response) error {
	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}
	_ = connection.SetWriteDeadline(time.Now().Add(timeout))
	return protocol.WriteFrame(connection, payload)
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

func (s *Server) maximumConnections() int {
	if s.MaxConnections > 0 {
		return s.MaxConnections
	}
	return 128
}

func (s *Server) maximumPerUID() int {
	if s.MaxPerUID > 0 {
		return s.MaxPerUID
	}
	return 32
}

func (s *Server) maximumPerUIDPlugin() int {
	if s.MaxPerUIDPlugin > 0 {
		return s.MaxPerUIDPlugin
	}
	return 16
}

func ensureSocketDirectory(path string, socketGID int) error {
	if path != filepath.Dir(FixedSocketPath) {
		return errors.New("plugin lease socket directory is not the fixed managed directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != socketGID ||
		!info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o750 ||
		info.Mode()&os.ModeSetgid == 0 {
		return errors.New("plugin lease socket directory must be the lease UID's setgid client-group directory")
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
		return fmt.Errorf("refusing to replace non-socket plugin lease path %s", path)
	}
	return os.Remove(path)
}
