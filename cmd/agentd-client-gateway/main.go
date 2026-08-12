package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/KiritoKing/pi-ops-agent/internal/clientgateway"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
)

func main() {
	flags := flag.NewFlagSet("agentd-client-gateway", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socketGID := flags.Int("socket-gid", -1, "client group owner for the fixed public socket")
	agentUID := flags.Int("agent-uid", -1, "ops-agent service UID")
	administratorUID := flags.Int("administrator-uid", -1, "enrolled local administrator UID")
	botmuxUID := flags.Int("botmux-uid", -1, "dedicated BotMux UID")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}
	if flags.NArg() != 0 || *socketGID < 1 || *agentUID < 1 ||
		*administratorUID < 1 || *botmuxUID < 1 {
		fatal(errors.New("positive socket, agent, administrator, and BotMux numeric identities are required"))
	}
	registry, err := pluginregistry.Open("/var/lib/ops-agent/plugins")
	if err != nil {
		fatal(err)
	}
	server := &clientgateway.Server{
		PublicPath:  clientgateway.FixedPublicSocketPath,
		BackendPath: clientgateway.FixedBackendSocketPath,
		SocketGID:   *socketGID,
		Resolver:    peercred.OSResolver{},
		Authorizer: clientgateway.Authorizer{
			AdministratorUID: uint32(*administratorUID),
			AgentUID:         uint32(*agentUID),
			BotMuxUID:        uint32(*botmuxUID),
			Registry:         registry,
			LookupUsername:   clientgateway.LookupOSUsername,
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := server.ListenAndServe(ctx); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "agentd-client-gateway:", err)
	os.Exit(1)
}
