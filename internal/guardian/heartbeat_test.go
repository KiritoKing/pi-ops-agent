package guardian

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validHeartbeatJSON(observedAt string) string {
	return fmt.Sprintf(`{
  "version": 1,
  "status": "healthy",
  "pid": 4321,
  "uid": 1001,
  "executable": "/opt/pi-ops-agent/releases/0.2.0/runtime/node",
  "cgroup": "/system.slice/ops-agentd.service",
  "startTimeTicks": 812345,
  "sequence": 7,
  "observedAt": %q
}`, observedAt)
}

func TestParseHeartbeatAcceptsCanonicalRecord(t *testing.T) {
	now := time.Date(2026, time.August, 8, 4, 5, 6, 123, time.UTC)
	record, err := ParseHeartbeat([]byte(validHeartbeatJSON(now.Format(time.RFC3339Nano))))
	if err != nil {
		t.Fatal(err)
	}
	if !record.IsFresh(now.Add(20*time.Second), 45*time.Second, time.Second) {
		t.Fatal("fresh heartbeat was treated as stale")
	}
	if record.IsFresh(now.Add(time.Minute), 45*time.Second, time.Second) {
		t.Fatal("stale heartbeat was treated as fresh")
	}
}

func TestParseHeartbeatRejectsMalformedRecords(t *testing.T) {
	now := time.Date(2026, time.August, 8, 4, 5, 6, 0, time.UTC).Format(time.RFC3339Nano)
	base := validHeartbeatJSON(now)
	tests := map[string]string{
		"unknown field":     base[:len(base)-1] + `, "command": "systemctl restart"}`,
		"duplicate pid":     base[:len(base)-1] + `, "pid": 99}`,
		"trailing value":    base + ` []`,
		"wrong status":      replaceConfigValue(base, `"status": "healthy"`, `"status": "starting"`),
		"root uid":          replaceConfigValue(base, `"uid": 1001`, `"uid": 0`),
		"zero starttime":    replaceConfigValue(base, `"startTimeTicks": 812345`, `"startTimeTicks": 0`),
		"dirty executable":  replaceConfigValue(base, `/opt/pi-ops-agent/releases/0.2.0/runtime/node`, `/opt/pi-ops-agent/../tmp/node`),
		"noncanonical time": replaceConfigValue(base, now, `2026-08-08T12:05:06+08:00`),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseHeartbeat([]byte(payload)); err == nil {
				t.Fatalf("accepted malformed heartbeat: %s", payload)
			}
		})
	}
}

func TestHeartbeatFutureTimestampIsNotFresh(t *testing.T) {
	now := time.Date(2026, time.August, 8, 4, 5, 6, 0, time.UTC)
	record, err := ParseHeartbeat([]byte(validHeartbeatJSON(now.Add(10 * time.Second).Format(time.RFC3339Nano))))
	if err != nil {
		t.Fatal(err)
	}
	if record.IsFresh(now, time.Minute, 2*time.Second) {
		t.Fatal("future heartbeat outside allowed skew was accepted")
	}
}

func TestFileHeartbeatSourceRejectsSymlinkAndOversize(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	directory := t.TempDir()
	recordPath := filepath.Join(directory, "heartbeat.json")
	if err := os.WriteFile(recordPath, []byte(validHeartbeatJSON(now)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileHeartbeatSource{Path: recordPath}).Read(context.Background()); err != nil {
		t.Fatalf("regular heartbeat was rejected: %v", err)
	}
	symlinkPath := filepath.Join(directory, "heartbeat-link.json")
	if err := os.Symlink(recordPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileHeartbeatSource{Path: symlinkPath}).Read(context.Background()); err == nil {
		t.Fatal("symlink heartbeat was accepted")
	}
	oversizedPath := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversizedPath, make([]byte, maximumRecordBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileHeartbeatSource{Path: oversizedPath}).Read(context.Background()); err == nil {
		t.Fatal("oversized heartbeat was accepted")
	}
}
