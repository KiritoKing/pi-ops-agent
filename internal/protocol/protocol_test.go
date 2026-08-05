package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestFrameRoundTripAndLimits(t *testing.T) {
	payload := []byte(`{"version":1}`)
	var framed bytes.Buffer
	if err := WriteFrame(&framed, payload); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(&framed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded %q, want %q", decoded, payload)
	}
	var invalid bytes.Buffer
	binary.Write(&invalid, binary.BigEndian, uint32(MaxFrameBytes+1))
	if _, err := ReadFrame(&invalid); err == nil {
		t.Fatal("oversized frame was accepted")
	}
}

func TestParseRequestStrictTaggedUnion(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute).Format(time.RFC3339Nano)
	valid := fmt.Sprintf(`{"version":1,"requestId":"request-12345678","deadline":%q,"method":"change.prepare","operation":{"kind":"package.install","package":"nginx","version":"1.2.3"}}`, deadline)
	request, err := ParseRequest([]byte(valid), now)
	if err != nil {
		t.Fatal(err)
	}
	operation, ok := request.Operation.(*PackageInstall)
	if !ok || operation.Package != "nginx" {
		t.Fatalf("unexpected operation %#v", request.Operation)
	}

	unknownTop := strings.Replace(valid, `"method":`, `"unexpected":true,"method":`, 1)
	if _, err := ParseRequest([]byte(unknownTop), now); err == nil {
		t.Fatal("unknown top-level field was accepted")
	}
	unknownOperation := strings.Replace(valid, `"package":"nginx"`, `"package":"nginx","command":"rm"`, 1)
	if _, err := ParseRequest([]byte(unknownOperation), now); err == nil {
		t.Fatal("unknown operation field was accepted")
	}
	wrongTag := strings.Replace(valid, `"package.install"`, `"raw.command"`, 1)
	if _, err := ParseRequest([]byte(wrongTag), now); err == nil {
		t.Fatal("unsupported operation tag was accepted")
	}
}

func TestParseRequestRejectsExpiredAndDistantDeadline(t *testing.T) {
	now := time.Now().UTC()
	for _, deadline := range []time.Time{now.Add(-time.Second), now.Add(11 * time.Minute)} {
		payload := fmt.Sprintf(`{"version":1,"requestId":"request-12345678","deadline":%q,"method":"heartbeat"}`, deadline.Format(time.RFC3339Nano))
		if _, err := ParseRequest([]byte(payload), now); err == nil {
			t.Fatalf("accepted deadline %s", deadline)
		}
	}
}
