package rpcserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/admission"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type staticResolver struct{ credential peercred.Credential }

func (r staticResolver) Resolve(*net.UnixConn) (peercred.Credential, error) {
	return r.credential, nil
}

type countingHandler struct {
	calls   atomic.Int32
	started chan struct{}
	release <-chan struct{}
}

func (h *countingHandler) Handle(ctx context.Context, _ peercred.Credential, request protocol.Request) protocol.Response {
	h.calls.Add(1)
	if h.started != nil {
		select {
		case h.started <- struct{}{}:
		default:
		}
	}
	if h.release != nil {
		select {
		case <-h.release:
		case <-ctx.Done():
			return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, Error: ctx.Err().Error()}
		}
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true}
}

func TestUnixAdmissionRateLimitsFramesPerUID(t *testing.T) {
	now := time.Date(2026, 8, 8, 13, 0, 0, 0, time.UTC)
	handler := &countingHandler{}
	server, limiter := testRPCServer(t, now, handler, admission.Limits{
		MaxConcurrent: 2, MaxConcurrentPerKey: 1,
		MaxRequestsPerWindow: 1, MaxGlobalPerWindow: 2,
		MaxKeys: 2, Window: time.Second, IdleTTL: time.Minute,
	})
	serverConnection, connection := unixSocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); server.serveConnection(ctx, serverConnection, limiter) }()
	defer func() { cancel(); _ = connection.Close(); <-done }()

	first := exchange(t, connection, requestPayload(now, "unix-rate-request-1"))
	if !first.OK {
		t.Fatalf("first Unix request failed: %#v", first)
	}
	second := exchange(t, connection, requestPayload(now, "unix-rate-request-2"))
	if second.OK || second.Error == "" || handler.calls.Load() != 1 {
		t.Fatalf("Unix rate limit failed: response=%#v calls=%d", second, handler.calls.Load())
	}
}

func TestUnixAdmissionRejectsConcurrentWorkPerUID(t *testing.T) {
	now := time.Date(2026, 8, 8, 13, 30, 0, 0, time.UTC)
	release := make(chan struct{})
	handler := &countingHandler{started: make(chan struct{}, 1), release: release}
	server, limiter := testRPCServer(t, now, handler, admission.Limits{
		MaxConcurrent: 2, MaxConcurrentPerKey: 1,
		MaxRequestsPerWindow: 10, MaxGlobalPerWindow: 20,
		MaxKeys: 2, Window: time.Second, IdleTTL: time.Minute,
	})
	ctx, cancel := context.WithCancel(context.Background())
	firstServer, firstConnection := unixSocketPair(t)
	secondServer, secondConnection := unixSocketPair(t)
	var serving atomic.Int32
	serving.Store(2)
	done := make(chan struct{})
	serve := func(connection *net.UnixConn) {
		server.serveConnection(ctx, connection, limiter)
		if serving.Add(-1) == 0 {
			close(done)
		}
	}
	go serve(firstServer)
	go serve(secondServer)
	defer func() {
		cancel()
		_ = firstConnection.Close()
		_ = secondConnection.Close()
		<-done
	}()

	firstDone := make(chan protocol.Response, 1)
	go func() {
		firstDone <- exchange(t, firstConnection, requestPayload(now, "unix-concurrent-request-1"))
	}()
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("first Unix request did not reach handler")
	}
	second := exchange(t, secondConnection, requestPayload(now, "unix-concurrent-request-2"))
	if second.OK || second.Error == "" || handler.calls.Load() != 1 {
		t.Fatalf("concurrent Unix request was not rejected: response=%#v calls=%d", second, handler.calls.Load())
	}
	close(release)
	if first := <-firstDone; !first.OK {
		t.Fatalf("admitted Unix request failed: %#v", first)
	}
}

func TestUnixDispatchDeadlineUsesBoundedInjectedClock(t *testing.T) {
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	limits := admission.Limits{
		MaxConcurrent: 2, MaxConcurrentPerKey: 1,
		MaxRequestsPerWindow: 10, MaxGlobalPerWindow: 20,
		MaxKeys: 2, Window: time.Second, IdleTTL: time.Minute,
	}
	for _, test := range []struct {
		name        string
		dispatchNow time.Time
		errorText   string
	}{
		{
			name:        "deadline expires after validation",
			dispatchNow: now.Add(2 * time.Minute),
			errorText:   "deadline expired before handler dispatch",
		},
		{
			name:        "clock retreat cannot extend execution window",
			dispatchNow: now.Add(-10 * time.Minute),
			errorText:   "deadline exceeds the bounded handler dispatch window",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := &countingHandler{}
			var clockCalls atomic.Int32
			clock := func() time.Time {
				if clockCalls.Add(1) <= 2 {
					return now
				}
				return test.dispatchNow
			}
			server := &Server{
				Resolver: staticResolver{credential: peercred.Credential{UID: 1001}},
				Handler:  handler,
				Now:      clock,
			}
			limiter, err := admission.New(limits, clock)
			if err != nil {
				t.Fatal(err)
			}
			serverConnection, connection := unixSocketPair(t)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.serveConnection(ctx, serverConnection, limiter)
			}()
			defer func() {
				cancel()
				_ = connection.Close()
				<-done
			}()

			response := exchange(t, connection, requestPayload(now, "unix-deadline-request-1"))
			if response.OK || !strings.Contains(response.Error, test.errorText) || handler.calls.Load() != 0 {
				t.Fatalf("invalid dispatch deadline reached handler: response=%#v calls=%d",
					response, handler.calls.Load())
			}
		})
	}
}

func testRPCServer(t *testing.T, now time.Time, handler Handler, limits admission.Limits) (*Server, *admission.Limiter) {
	t.Helper()
	server := &Server{
		Resolver: staticResolver{credential: peercred.Credential{UID: 1001}}, Handler: handler,
		AdmissionLimits: limits, Now: func() time.Time { return now },
	}
	limiter, err := admission.New(limits, server.Now)
	if err != nil {
		t.Fatal(err)
	}
	return server, limiter
}

func unixSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverFile := os.NewFile(uintptr(descriptors[0]), "rpc-server")
	clientFile := os.NewFile(uintptr(descriptors[1]), "rpc-client")
	serverRaw, serverErr := net.FileConn(serverFile)
	clientRaw, clientErr := net.FileConn(clientFile)
	_ = serverFile.Close()
	_ = clientFile.Close()
	if serverErr != nil || clientErr != nil {
		t.Fatalf("wrap Unix socket pair: server=%v client=%v", serverErr, clientErr)
	}
	server, serverOK := serverRaw.(*net.UnixConn)
	client, clientOK := clientRaw.(*net.UnixConn)
	if !serverOK || !clientOK {
		t.Fatalf("socket pair is not Unix: server=%T client=%T", serverRaw, clientRaw)
	}
	return server, client
}

func requestPayload(now time.Time, requestID string) []byte {
	return []byte(fmt.Sprintf(`{"version":1,"requestId":%q,"deadline":%q,"method":"host.snapshot"}`,
		requestID, now.Add(time.Minute).Format(time.RFC3339Nano)))
}

func exchange(t *testing.T, connection *net.UnixConn, payload []byte) protocol.Response {
	t.Helper()
	if err := protocol.WriteFrame(connection, payload); err != nil {
		t.Fatal(err)
	}
	responsePayload, err := protocol.ReadFrame(connection)
	if err != nil {
		t.Fatal(err)
	}
	var response protocol.Response
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		t.Fatal(err)
	}
	return response
}
