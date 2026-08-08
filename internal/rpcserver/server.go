package rpcserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/admission"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type Handler interface {
	Handle(context.Context, peercred.Credential, protocol.Request) protocol.Response
}

const maxRequestDispatchTimeout = 10 * time.Minute

type Server struct {
	Path            string
	Mode            os.FileMode
	SocketGID       int
	Resolver        peercred.Resolver
	Handler         Handler
	MaxConnections  int
	AdmissionLimits admission.Limits
	Now             func() time.Time

	mu       sync.Mutex
	listener *net.UnixListener
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Resolver == nil || s.Handler == nil {
		return errors.New("resolver and handler are required")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o750); err != nil {
		return err
	}
	if err := removeStaleSocket(s.Path); err != nil {
		return err
	}
	address, err := net.ResolveUnixAddr("unix", s.Path)
	if err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	defer func() {
		listener.Close()
		os.Remove(s.Path)
	}()
	mode := s.Mode
	if mode == 0 {
		mode = 0o660
	}
	if err := os.Chmod(s.Path, mode); err != nil {
		return err
	}
	if s.SocketGID >= 0 {
		if err := os.Chown(s.Path, -1, s.SocketGID); err != nil {
			return err
		}
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	limits := s.AdmissionLimits
	if limits.MaxConcurrent == 0 {
		limits = admission.Limits{
			MaxConcurrent: 64, MaxConcurrentPerKey: 16,
			MaxRequestsPerWindow: 128, MaxGlobalPerWindow: 512,
			MaxKeys: 256, Window: time.Second, IdleTTL: 5 * time.Minute,
		}
	}
	limiter, err := admission.New(limits, s.Now)
	if err != nil {
		return fmt.Errorf("configure Unix admission: %w", err)
	}
	maxConnections := s.MaxConnections
	if maxConnections <= 0 {
		maxConnections = 64
	}
	connectionSlots := make(chan struct{}, maxConnections)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case connectionSlots <- struct{}{}:
			go func(connection *net.UnixConn) {
				defer func() { <-connectionSlots }()
				s.serveConnection(ctx, connection, limiter)
			}(connection)
		default:
			_ = connection.Close()
		}
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

func (s *Server) serveConnection(parent context.Context, connection *net.UnixConn, limiter *admission.Limiter) {
	defer connection.Close()
	credential, err := s.Resolver.Resolve(connection)
	if err != nil {
		return
	}
	for {
		connection.SetReadDeadline(time.Now().Add(15 * time.Second))
		payload, err := protocol.ReadFrame(connection)
		if err != nil {
			return
		}
		release, rejected := limiter.Acquire(strconv.FormatUint(uint64(credential.UID), 10))
		if rejected != "" {
			response := protocol.Response{Version: protocol.Version, RequestID: requestIDFromMalformed(payload), OK: false, Error: "request admission rejected: " + string(rejected)}
			if writeErr := writeResponse(connection, response); writeErr != nil {
				return
			}
			continue
		}
		request, err := protocol.ParseRequest(payload, s.now())
		if err != nil {
			response := protocol.Response{Version: protocol.Version, RequestID: requestIDFromMalformed(payload), OK: false, Error: err.Error()}
			if writeErr := writeResponse(connection, response); writeErr != nil {
				release()
				return
			}
			release()
			continue
		}
		ctx, cancel, contextErr := boundedRequestContext(parent, request.Deadline, s.now())
		if contextErr != nil {
			response := protocol.Response{
				Version: protocol.Version, RequestID: request.RequestID, Error: contextErr.Error(),
			}
			if writeErr := writeResponse(connection, response); writeErr != nil {
				release()
				return
			}
			release()
			continue
		}
		response := s.Handler.Handle(ctx, credential, request)
		cancel()
		if response.Version == 0 {
			response.Version = protocol.Version
		}
		if response.RequestID == "" {
			response.RequestID = request.RequestID
		}
		if err := writeResponse(connection, response); err != nil {
			release()
			return
		}
		release()
	}
}

func boundedRequestContext(parent context.Context, deadline, now time.Time) (context.Context, context.CancelFunc, error) {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return nil, nil, errors.New("request deadline expired before handler dispatch")
	}
	if remaining > maxRequestDispatchTimeout {
		return nil, nil, errors.New("request deadline exceeds the bounded handler dispatch window")
	}
	ctx, cancel := context.WithTimeout(parent, remaining)
	return ctx, cancel, nil
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func writeResponse(connection *net.UnixConn, response protocol.Response) error {
	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}
	connection.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return protocol.WriteFrame(connection, payload)
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
		return fmt.Errorf("refusing to replace non-socket path %s", path)
	}
	return os.Remove(path)
}

func requestIDFromMalformed(payload []byte) string {
	var value struct {
		RequestID string `json:"requestId"`
	}
	if json.Unmarshal(payload, &value) == nil && value.RequestID != "" {
		return value.RequestID
	}
	return "invalid-request"
}
