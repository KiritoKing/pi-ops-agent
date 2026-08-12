//go:build !linux

package jsonconfighelper

import (
	"bytes"
	"strings"
	"testing"
)

func TestNonLinuxFailsClosed(t *testing.T) {
	if currentUIDForTest() == 0 {
		t.Skip("Run rejects root before platform dispatch")
	}
	tests := [][]string{
		{
			"inspect-directory", "--root", "/srv/botmux", "--path", "/srv/botmux/workspace",
		},
		{
			"inspect", "--home", "/home/alice", "--relative", ".botmux/bots.json",
			"--selector-key", "appID", "--selector-value", "cli_one", "--field", "model",
		},
		{
			"mutate", "--home", "/home/alice", "--relative", ".botmux/bots.json",
			"--selector-key", "appID", "--selector-value", "cli_one", "--field", "model",
			"--stage-root", "/run/user/1000/stage", "--output", "/run/user/1000/stage/after.json",
			"--value-kind", "string", "--string-value", "new",
		},
	}
	for _, arguments := range tests {
		err := Run(arguments, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "requires Linux") {
			t.Fatalf("non-Linux helper did not fail closed: %v", err)
		}
	}
}
