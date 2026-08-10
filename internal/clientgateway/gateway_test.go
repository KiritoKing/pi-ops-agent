package clientgateway

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const (
	tuiDigest    = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	botmuxDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fakeRegistry map[string]pluginregistry.RuntimeRegistration

func (registry fakeRegistry) RuntimeCurrent(pluginID string) (pluginregistry.RuntimeRegistration, error) {
	registration, ok := registry[pluginID]
	if !ok {
		return pluginregistry.RuntimeRegistration{}, net.ErrClosed
	}
	return registration, nil
}

func adapterRegistration(pluginID, digest string) pluginregistry.RuntimeRegistration {
	return pluginregistry.RuntimeRegistration{Registration: pluginregistry.Registration{
		APIVersion:    pluginregistry.RegistrationAPIVersion,
		SchemaVersion: 1,
		PluginID:      pluginID,
		Kind:          pluginregistry.KindAdapter,
		Version:       "0.3.0",
		Publisher:     "test",
		Digest:        digest,
	}}
}

func testAuthorizer() Authorizer {
	return Authorizer{
		AdministratorUID: 1000,
		AgentUID:         991,
		BotMuxUID:        992,
		Registry: fakeRegistry{
			"adapter.tui":    adapterRegistration("adapter.tui", tuiDigest),
			"adapter.botmux": adapterRegistration("adapter.botmux", botmuxDigest),
		},
		LookupUsername: func(uid uint32) (string, error) {
			if uid == 993 {
				return "ops-adapter-demo", nil
			}
			return "unknown", nil
		},
	}
}

func helloPayload(sessionID, adapterID, digest string) []byte {
	payload, _ := json.Marshal(map[string]any{
		"type":      "hello",
		"sessionId": sessionID,
		"peer": map[string]any{
			"apiVersion": PeerAPIVersion,
			"adapterId":  adapterID,
			"digest":     digest,
		},
	})
	return payload
}

func readObject(t *testing.T, connection net.Conn) map[string]any {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	payload, err := protocol.ReadFrame(connection)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func TestAuthorizerPreventsBotMuxOrDifferentUIDFromClaimingTUISessions(t *testing.T) {
	authorizer := testAuthorizer()
	tui := PeerIdentity{APIVersion: PeerAPIVersion, AdapterID: "adapter.tui", Digest: tuiDigest}
	if err := authorizer.Authorize(peercred.Credential{UID: 1000}, tui); err != nil {
		t.Fatalf("enrolled TUI peer rejected: %v", err)
	}
	for _, uid := range []uint32{991, 992, 993} {
		if err := authorizer.Authorize(peercred.Credential{UID: uid}, tui); err == nil {
			t.Fatalf("UID %d claimed the TUI adapter namespace", uid)
		}
	}
	botmux := PeerIdentity{
		APIVersion: PeerAPIVersion, AdapterID: "adapter.botmux", Digest: botmuxDigest,
	}
	tuiSession, err := CanonicalSessionID(1000, tui, "shared-session-1234")
	if err != nil {
		t.Fatal(err)
	}
	botmuxSession, err := CanonicalSessionID(992, botmux, "shared-session-1234")
	if err != nil {
		t.Fatal(err)
	}
	if tuiSession == botmuxSession {
		t.Fatal("BotMux and TUI resolved to the same backend session namespace")
	}
	updatedTUISession, err := CanonicalSessionID(1000, PeerIdentity{
		APIVersion: PeerAPIVersion,
		AdapterID:  "adapter.tui",
		Digest:     "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}, "shared-session-1234")
	if err != nil {
		t.Fatal(err)
	}
	if tuiSession == updatedTUISession {
		t.Fatal("an Adapter digest update retained the old backend session namespace")
	}
	if err := authorizer.Authorize(peercred.Credential{UID: 1000}, PeerIdentity{
		APIVersion: "agentd.client-peer/v2", AdapterID: "adapter.tui", Digest: tuiDigest,
	}); err == nil {
		t.Fatal("unsupported peer API version was authorized")
	}
}

func TestGatewayRewritesSessionIntoPeerAdapterDigestNamespace(t *testing.T) {
	client, gatewaySide := net.Pipe()
	backendSide, backend := net.Pipe()
	server := &Server{
		Authorizer:       testAuthorizer(),
		DialBackend:      func(context.Context) (net.Conn, error) { return backendSide, nil },
		HandshakeTimeout: time.Second,
		WriteTimeout:     time.Second,
	}
	done := make(chan struct{})
	go func() {
		server.ServeConnection(context.Background(), gatewaySide, peercred.Credential{UID: 1000})
		close(done)
	}()
	if err := protocol.WriteFrame(client, helloPayload("tui-session-1234", "adapter.tui", tuiDigest)); err != nil {
		t.Fatal(err)
	}
	backendHello := readObject(t, backend)
	canonical, err := CanonicalSessionID(
		1000,
		PeerIdentity{APIVersion: PeerAPIVersion, AdapterID: "adapter.tui", Digest: tuiDigest},
		"tui-session-1234",
	)
	if err != nil {
		t.Fatal(err)
	}
	if backendHello["sessionId"] != canonical {
		t.Fatalf("backend sessionId=%v want=%s", backendHello["sessionId"], canonical)
	}
	ready, _ := json.Marshal(map[string]any{"type": "ready", "sessionId": canonical})
	if err := protocol.WriteFrame(backend, ready); err != nil {
		t.Fatal(err)
	}
	clientReady := readObject(t, client)
	if clientReady["sessionId"] != "tui-session-1234" {
		t.Fatalf("client session correlation leaked backend namespace: %#v", clientReady)
	}
	_ = client.Close()
	_ = backend.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway connection did not release")
	}
}

func TestGatewayRejectsConcurrentWriterForSameGlobalSession(t *testing.T) {
	firstClient, firstGateway := net.Pipe()
	firstBackendSide, firstBackend := net.Pipe()
	var backendDials atomic.Int32
	server := &Server{
		Authorizer: testAuthorizer(),
		DialBackend: func(context.Context) (net.Conn, error) {
			backendDials.Add(1)
			return firstBackendSide, nil
		},
		HandshakeTimeout: time.Second,
		WriteTimeout:     time.Second,
	}
	firstDone := make(chan struct{})
	go func() {
		server.ServeConnection(context.Background(), firstGateway, peercred.Credential{UID: 1000})
		close(firstDone)
	}()
	request := helloPayload("writer-session-1234", "adapter.tui", tuiDigest)
	if err := protocol.WriteFrame(firstClient, request); err != nil {
		t.Fatal(err)
	}
	_ = readObject(t, firstBackend)

	secondClient, secondGateway := net.Pipe()
	secondDone := make(chan struct{})
	go func() {
		server.ServeConnection(context.Background(), secondGateway, peercred.Credential{UID: 1000})
		close(secondDone)
	}()
	if err := protocol.WriteFrame(secondClient, request); err != nil {
		t.Fatal(err)
	}
	rejection := readObject(t, secondClient)
	if rejection["type"] != "error" ||
		!strings.Contains(rejection["message"].(string), "concurrent writer") {
		t.Fatalf("unexpected concurrent writer response: %#v", rejection)
	}
	if backendDials.Load() != 1 {
		t.Fatalf("rejected writer reached backend: dials=%d", backendDials.Load())
	}
	_ = secondClient.Close()
	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("rejected writer did not close")
	}

	_ = firstClient.Close()
	_ = firstBackend.Close()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first writer did not release")
	}
}

func TestGatewayBackendEOFReleasesWriterAndAdmissionForFreshSameSession(t *testing.T) {
	backendQueue := make(chan net.Conn, 2)
	var backendDials atomic.Int32
	server := &Server{
		Authorizer: testAuthorizer(),
		DialBackend: func(ctx context.Context) (net.Conn, error) {
			select {
			case connection := <-backendQueue:
				backendDials.Add(1)
				return connection, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		HandshakeTimeout: time.Second,
		WriteTimeout:     time.Second,
	}
	request := helloPayload("restart-session-1234", "adapter.tui", tuiDigest)
	canonical, err := CanonicalSessionID(
		1000,
		PeerIdentity{APIVersion: PeerAPIVersion, AdapterID: "adapter.tui", Digest: tuiDigest},
		"restart-session-1234",
	)
	if err != nil {
		t.Fatal(err)
	}

	assertReleased := func() {
		t.Helper()
		server.writers.mu.Lock()
		activeWriters := len(server.writers.active)
		server.writers.mu.Unlock()
		server.clients.mu.Lock()
		activeConnections := server.clients.total
		activeUIDs := len(server.clients.byUID)
		server.clients.mu.Unlock()
		if activeWriters != 0 || activeConnections != 0 || activeUIDs != 0 {
			t.Fatalf(
				"gateway retained restart state: writers=%d connections=%d uids=%d",
				activeWriters,
				activeConnections,
				activeUIDs,
			)
		}
	}

	runConnection := func(label string) {
		t.Helper()
		client, gatewaySide := net.Pipe()
		gatewayBackend, agentdBackend := net.Pipe()
		backendQueue <- gatewayBackend
		releaseAdmission, admitted := server.clients.acquire(1000)
		if !admitted {
			t.Fatalf("%s connection was not admitted", label)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer gatewaySide.Close()
			defer releaseAdmission()
			server.ServeConnection(context.Background(), gatewaySide, peercred.Credential{UID: 1000})
		}()
		if err := protocol.WriteFrame(client, request); err != nil {
			t.Fatal(err)
		}
		backendHello := readObject(t, agentdBackend)
		if backendHello["sessionId"] != canonical {
			t.Fatalf("%s backend sessionId=%v want=%s", label, backendHello["sessionId"], canonical)
		}

		// Model an agentd process exit: its accepted backend fd disappears while
		// the public client is still live. The persistent gateway must close the
		// old client and release both in-memory accounting layers.
		if err := agentdBackend.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s gateway connection did not exit after backend EOF", label)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 1)
		if count, readErr := client.Read(buffer); count != 0 || readErr == nil {
			t.Fatalf("%s old client remained live after backend EOF: n=%d err=%v", label, count, readErr)
		}
		_ = client.Close()
		assertReleased()
	}

	runConnection("original")
	runConnection("fresh")
	if backendDials.Load() != 2 {
		t.Fatalf("fresh same-session connection did not reach the restarted backend: dials=%d", backendDials.Load())
	}
}

func TestDefaultBackendDialRequiresStableOwnerOnlySocket(t *testing.T) {
	shortTempDir := func(t *testing.T) string {
		t.Helper()
		directory, err := os.MkdirTemp("/tmp", "agentd-gateway-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
		return directory
	}
	listen := func(t *testing.T, path string, mode os.FileMode) *net.UnixListener {
		t.Helper()
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		return listener
	}

	t.Run("missing", func(t *testing.T) {
		server := &Server{BackendPath: filepath.Join(shortTempDir(t), "missing.sock")}
		if connection, err := server.dialBackend(context.Background()); err == nil {
			_ = connection.Close()
			t.Fatal("missing backend socket was dialed")
		}
	})

	t.Run("unsafe mode", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "backend.sock")
		listener := listen(t, path, 0o660)
		defer listener.Close()
		server := &Server{BackendPath: path}
		if connection, err := server.dialBackend(context.Background()); err == nil {
			_ = connection.Close()
			t.Fatal("group-writable backend socket was dialed")
		}
	})

	t.Run("stable owner-only socket", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "backend.sock")
		listener := listen(t, path, 0o600)
		defer listener.Close()
		accepted := make(chan net.Conn, 1)
		acceptErrors := make(chan error, 1)
		go func() {
			connection, err := listener.AcceptUnix()
			if err != nil {
				acceptErrors <- err
				return
			}
			accepted <- connection
		}()
		server := &Server{BackendPath: path}
		connection, err := server.dialBackend(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
		select {
		case peer := <-accepted:
			_ = peer.Close()
		case err := <-acceptErrors:
			t.Fatal(err)
		case <-time.After(2 * time.Second):
			t.Fatal("validated backend dial was not accepted")
		}
	})

	t.Run("pathname replacement during dial", func(t *testing.T) {
		path := filepath.Join(shortTempDir(t), "backend.sock")
		original := listen(t, path, 0o600)
		defer original.Close()
		var replacement *net.UnixListener
		dialer := net.Dialer{Timeout: time.Second}
		connection, err := dialValidatedBackend(
			context.Background(),
			path,
			func(ctx context.Context, socketPath string) (net.Conn, error) {
				if err := os.Remove(socketPath); err != nil {
					return nil, err
				}
				replacement = listen(t, socketPath, 0o600)
				return dialer.DialContext(ctx, "unix", socketPath)
			},
		)
		if connection != nil {
			_ = connection.Close()
			t.Fatal("dial returned a connection after backend pathname replacement")
		}
		if err == nil || !strings.Contains(err.Error(), "changed during dial") {
			t.Fatalf("backend pathname replacement was not rejected: %v", err)
		}
		if replacement == nil {
			t.Fatal("replacement listener was not created")
		}
		_ = replacement.SetDeadline(time.Now().Add(time.Second))
		peer, acceptErr := replacement.AcceptUnix()
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 1)
		if count, readErr := peer.Read(buffer); count != 0 || readErr == nil {
			t.Fatalf("rejected replacement connection remained open: n=%d err=%v", count, readErr)
		}
		_ = peer.Close()
		_ = replacement.Close()
	})
}

func TestGatewayMissingBackendReleasesStateAndAllowsFreshSameSession(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "agentd-gateway-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "backend.sock")
	server := &Server{
		BackendPath:      path,
		Authorizer:       testAuthorizer(),
		HandshakeTimeout: time.Second,
		WriteTimeout:     time.Second,
	}
	request := helloPayload("missing-backend-session-1234", "adapter.tui", tuiDigest)

	run := func(label string, backendExpected bool) (net.Conn, <-chan struct{}) {
		t.Helper()
		client, gatewaySide := net.Pipe()
		releaseAdmission, admitted := server.clients.acquire(1000)
		if !admitted {
			t.Fatalf("%s connection was not admitted", label)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer gatewaySide.Close()
			defer releaseAdmission()
			server.ServeConnection(context.Background(), gatewaySide, peercred.Credential{UID: 1000})
		}()
		if err := protocol.WriteFrame(client, request); err != nil {
			t.Fatal(err)
		}
		if !backendExpected {
			response := readObject(t, client)
			if response["type"] != "error" || response["message"] != "agentd backend is unavailable" {
				t.Fatalf("unexpected missing-backend response: %#v", response)
			}
		}
		return client, done
	}

	missingClient, missingDone := run("missing", false)
	select {
	case <-missingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("missing backend kept the gateway handler alive")
	}
	_ = missingClient.Close()
	server.writers.mu.Lock()
	missingWriters := len(server.writers.active)
	server.writers.mu.Unlock()
	server.clients.mu.Lock()
	missingConnections := server.clients.total
	missingUIDs := len(server.clients.byUID)
	server.clients.mu.Unlock()
	if missingWriters != 0 || missingConnections != 0 || missingUIDs != 0 {
		t.Fatalf(
			"missing backend leaked state: writers=%d connections=%d uids=%d",
			missingWriters,
			missingConnections,
			missingUIDs,
		)
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	freshClient, freshDone := run("fresh", true)
	var backend net.Conn
	select {
	case backend = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("fresh same-session connection did not reach the restored backend")
	}
	backendHello := readObject(t, backend)
	canonical, err := CanonicalSessionID(
		1000,
		PeerIdentity{APIVersion: PeerAPIVersion, AdapterID: "adapter.tui", Digest: tuiDigest},
		"missing-backend-session-1234",
	)
	if err != nil {
		t.Fatal(err)
	}
	if backendHello["sessionId"] != canonical {
		t.Fatalf("fresh backend sessionId=%v want=%s", backendHello["sessionId"], canonical)
	}
	_ = backend.Close()
	select {
	case <-freshDone:
	case <-time.After(2 * time.Second):
		t.Fatal("fresh restored-backend handler did not exit")
	}
	_ = freshClient.Close()
}

func TestConnectionAdmissionBoundsConcurrentTotalAndPerUIDState(t *testing.T) {
	for _, test := range []struct {
		name       string
		uid        func(int) uint32
		maxTotal   int
		maxPerUID  int
		wantActive int
	}{
		{
			name: "one compromised Adapter UID",
			uid: func(int) uint32 {
				return 1000
			},
			maxTotal: 16, maxPerUID: 4, wantActive: 4,
		},
		{
			name: "many admitted UIDs hit the process total",
			uid: func(attempt int) uint32 {
				return uint32(2000 + attempt)
			},
			maxTotal: 6, maxPerUID: 4, wantActive: 6,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := &connectionAdmission{maxTotal: test.maxTotal, maxPerUID: test.maxPerUID}
			const attempts = 64
			results := make(chan bool, attempts)
			releaseAll := make(chan struct{})
			done := make(chan struct{}, attempts)
			for attempt := 0; attempt < attempts; attempt++ {
				go func(attempt int) {
					release, ok := limits.acquire(test.uid(attempt))
					results <- ok
					if ok {
						<-releaseAll
						release()
						release()
					}
					done <- struct{}{}
				}(attempt)
			}
			active := 0
			for attempt := 0; attempt < attempts; attempt++ {
				if <-results {
					active++
				}
			}
			if active != test.wantActive {
				t.Fatalf("admitted %d concurrent connections, want %d", active, test.wantActive)
			}
			close(releaseAll)
			for attempt := 0; attempt < attempts; attempt++ {
				<-done
			}
			if limits.total != 0 || len(limits.byUID) != 0 {
				t.Fatalf("connection admission leaked state: total=%d byUID=%v", limits.total, limits.byUID)
			}
		})
	}
}

func TestGatewayRejectsDuplicateOrUnregisteredPeerHello(t *testing.T) {
	for name, payload := range map[string][]byte{
		"duplicate":    []byte(`{"type":"hello","type":"hello","sessionId":"session-1234","peer":{"apiVersion":"agentd.client-peer/v1","adapterId":"adapter.tui","digest":"` + tuiDigest + `"}}`),
		"stale digest": helloPayload("session-1234", "adapter.tui", botmuxDigest),
	} {
		t.Run(name, func(t *testing.T) {
			client, gatewaySide := net.Pipe()
			server := &Server{Authorizer: testAuthorizer(), HandshakeTimeout: time.Second, WriteTimeout: time.Second}
			go server.ServeConnection(context.Background(), gatewaySide, peercred.Credential{UID: 1000})
			if err := protocol.WriteFrame(client, payload); err != nil {
				t.Fatal(err)
			}
			response := readObject(t, client)
			if response["type"] != "error" {
				t.Fatalf("invalid hello was not rejected: %#v", response)
			}
			_ = client.Close()
		})
	}
}
