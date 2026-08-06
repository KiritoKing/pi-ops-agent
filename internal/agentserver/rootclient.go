package agentserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type Backend interface {
	Do(context.Context, protocol.Request) (protocol.Response, error)
}

type RootClient struct {
	Socket  string
	Timeout time.Duration
}

func (c RootClient) Do(ctx context.Context, request protocol.Request) (protocol.Response, error) {
	if c.Socket == "" {
		return protocol.Response{}, errors.New("root-helper socket is required")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return protocol.Response{}, err
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if request.Deadline.Before(deadline) {
		deadline = request.Deadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return protocol.Response{}, err
	}
	if err := protocol.WriteFrame(connection, request.Raw); err != nil {
		return protocol.Response{}, err
	}
	payload, err := protocol.ReadFrame(connection)
	if err != nil {
		return protocol.Response{}, err
	}
	var response protocol.Response
	if err := json.Unmarshal(payload, &response); err != nil {
		return protocol.Response{}, err
	}
	if response.Version != protocol.Version || response.RequestID != request.RequestID {
		return protocol.Response{}, errors.New("root-helper returned a mismatched response")
	}
	return response, nil
}
