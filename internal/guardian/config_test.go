package guardian

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func validConfigJSON(uid uint32) string {
	return fmt.Sprintf(`{
  "version": 1,
  "heartbeatPath": "/run/ops-agent/agentd/guardian-heartbeat.json",
  "expectedUid": %d,
  "expectedExecutable": "/opt/pi-ops-agent/releases/0.2.0/runtime/node",
  "expectedCgroup": "/system.slice/ops-agentd.service",
  "heartbeatTimeout": "45s",
  "checkInterval": "5s",
  "operationTimeout": "2s",
  "startupGrace": "20s",
  "termGrace": "10s",
  "maxClockSkew": "2s"
}`, uid)
}

func TestParseConfigAcceptsStrictConfiguration(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		uid = 1001
	}
	config, err := ParseConfig([]byte(validConfigJSON(uid)))
	if err != nil {
		t.Fatal(err)
	}
	if config.ExpectedUID != uid || config.HeartbeatTimeout != 45*time.Second || config.TermGrace != 10*time.Second {
		t.Fatalf("unexpected parsed config: %#v", config)
	}
}

func TestParseConfigRejectsMalformedOrAmbiguousInput(t *testing.T) {
	base := validConfigJSON(1001)
	tests := map[string]string{
		"unknown field":      base[:len(base)-1] + `, "extra": true}`,
		"trailing value":     base + ` {}`,
		"duplicate field":    `{"version":1,"version":1}`,
		"root uid":           replaceConfigValue(base, `"expectedUid": 1001`, `"expectedUid": 0`),
		"relative heartbeat": replaceConfigValue(base, `"/run/ops-agent/agentd/guardian-heartbeat.json"`, `"relative.json"`),
		"root cgroup":        replaceConfigValue(base, `"/system.slice/ops-agentd.service"`, `"/"`),
		"long term grace":    replaceConfigValue(base, `"termGrace": "10s"`, `"termGrace": "31s"`),
		"missing field":      `{"version":1}`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(payload)); err == nil {
				t.Fatalf("accepted invalid config: %s", payload)
			}
		})
	}
}

func TestConfigValidateRuntimeRequiresSameUID(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		t.Skip("test requires a non-root test process")
	}
	config, err := ParseConfig([]byte(validConfigJSON(uid)))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateRuntime(); err != nil {
		t.Fatalf("same UID was rejected: %v", err)
	}
	config.ExpectedUID++
	if err := config.ValidateRuntime(); err == nil {
		t.Fatal("different guardian and agentd UIDs were accepted")
	}
}

func replaceConfigValue(payload, old, replacement string) string {
	for index := 0; index+len(old) <= len(payload); index++ {
		if payload[index:index+len(old)] == old {
			return payload[:index] + replacement + payload[index+len(old):]
		}
	}
	return payload
}
