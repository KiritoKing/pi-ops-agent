package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/KiritoKing/pi-ops-agent/internal/approvalsubmit"
)

func main() {
	request, err := approvalsubmit.ParseArgs(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	result, err := approvalsubmit.NewDefaultSubmitter().Submit(context.Background(), request)
	if err != nil {
		fatal(err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		fatal(fmt.Errorf("encode helper response: %w", err))
	}
	// stdout is an IPC surface consumed by the unprivileged client. It contains
	// exactly one bounded HelperResponse JSON line and never the human plan.
	if _, err := os.Stdout.Write(append(payload, '\n')); err != nil {
		fatal(errors.New("write helper response"))
	}
}

func fatal(err error) {
	message := strings.NewReplacer("\n", " ", "\r", " ", "\x00", " ").Replace(err.Error())
	if len(message) > 1024 {
		message = message[:1024]
	}
	fmt.Fprintf(os.Stderr, "agentd-approval-submit: %s\n", message)
	os.Exit(1)
}
