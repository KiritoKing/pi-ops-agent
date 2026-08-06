package enrollment

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/agentserver"
)

func TestParseBundleRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	bundle := Bundle{
		Version: Version, Controller: "https://controller.example:7443",
		Endpoint: "https://endpoint.example:7443", ExpiresAt: "2030-01-01T00:00:00Z",
		Identity:     agentserver.Identity{Version: 1, ServerID: "server-12345678", MachineID: "machine-12345678", MachineName: "endpoint", Account: "ops-agent-server"},
		TargetPolicy: json.RawMessage(`{"version":1}`), Signature: "signature",
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := strings.Replace(string(payload), `"signature":`, `"unexpected":true,"signature":`, 1)
	if _, err := parseBundle([]byte(withUnknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field rejection, got %v", err)
	}
	if _, err := parseBundle(append(payload, []byte(" {}")...)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing-value rejection, got %v", err)
	}
}

func TestValidateHTTPSOrigin(t *testing.T) {
	valid, err := validateHTTPSOrigin("https://machine.example:7443/")
	if err != nil || valid.String() != "https://machine.example:7443" {
		t.Fatalf("unexpected valid origin result %v, %v", valid, err)
	}
	for _, invalid := range []string{
		"http://machine.example:7443",
		"https://user@machine.example:7443",
		"https://machine.example:7443/path",
		"https://machine.example:7443?query=1",
	} {
		if _, err := validateHTTPSOrigin(invalid); err == nil {
			t.Fatalf("expected invalid origin rejection for %q", invalid)
		}
	}
}
