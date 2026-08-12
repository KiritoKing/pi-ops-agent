package protocol

import "testing"

func TestBreakglassProtocolRequiresExplicitBackupListAndNetworkDeclaration(t *testing.T) {
	invalid := []string{
		`{"kind":"breakglass.script","script":"true","backupPaths":["/etc/hosts"]}`,
		`{"kind":"breakglass.script","script":"true","network":false}`,
		`{"kind":"breakglass.script","script":"true","backupPaths":null,"network":false}`,
		`{"kind":"breakglass.script","script":"true","backupPaths":[],"network":null}`,
		`{"kind":"breakglass.script","script":"true","backupPaths":[],"verifyScript":null,"network":false}`,
	}
	for _, payload := range invalid {
		if _, err := parseOperation([]byte(payload)); err == nil {
			t.Fatalf("incomplete break-glass operation was accepted: %s", payload)
		}
	}
	valid := []string{
		`{"kind":"breakglass.script","script":"true","backupPaths":[],"network":false}`,
		`{"kind":"breakglass.script","script":"true","backupPaths":["/etc/hosts"],"verifyScript":"true","network":true}`,
	}
	for _, payload := range valid {
		operation, err := parseOperation([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		if operation.Kind() != "breakglass.script" {
			t.Fatalf("unexpected operation: %#v", operation)
		}
	}
}
