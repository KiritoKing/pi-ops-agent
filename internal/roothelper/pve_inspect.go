package roothelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const pveshPath = "/usr/bin/pvesh"

func inspectPVE(ctx context.Context, runner CommandRunner, request protocol.Request) (interface{}, error) {
	var path string
	switch request.Method {
	case protocol.MethodPVEClusterStatus:
		path = "/cluster/status"
	case protocol.MethodPVENodeStatus:
		path = "/nodes/" + request.PVE.Node + "/status"
	case protocol.MethodPVEStorageStatus:
		path = "/nodes/" + request.PVE.Node + "/storage/" + request.PVE.Storage + "/status"
	case protocol.MethodPVETaskStatus:
		path = "/nodes/" + request.PVE.Node + "/tasks/" + request.PVE.UPID + "/status"
	case protocol.MethodPVEGuestStatus:
		path = pveGuestPath(request.PVE.Node, request.PVE.GuestType, request.PVE.VMID) + "/status/current"
	default:
		return nil, errors.New("unsupported PVE inspection method")
	}
	output, err := runner.Run(ctx, pveshPath, "get", path, "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("PVE inspection failed: %w", err)
	}
	return decodeBoundedPVEJSON(output)
}

func decodeBoundedPVEJSON(output string) (interface{}, error) {
	if len(output) > maxCommandOutput {
		return nil, errors.New("PVE JSON response exceeds the output limit")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(output)))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode PVE JSON response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode PVE JSON response: trailing value")
	}
	return value, nil
}

func pveGuestPath(node, guestType string, vmid int) string {
	return "/nodes/" + node + "/" + guestType + "/" + strconv.Itoa(vmid)
}
