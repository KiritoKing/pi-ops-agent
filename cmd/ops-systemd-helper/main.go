package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/audit"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/rpcserver"
	"github.com/KiritoKing/pi-ops-agent/internal/systemdhelper"
)

func main() {
	socket := flag.String("socket", "/run/ops-agent/systemd-helper.sock", "Unix socket path")
	auditFile := flag.String("audit-file", "/var/log/ops-agent/systemd-helper-audit.jsonl", "append-only hash-chain audit file")
	agentUID := flag.Int("agent-uid", -1, "UID allowed to send heartbeats and inspections (required)")
	socketGID := flag.Int("socket-gid", -1, "group owner for the Unix socket")
	agentUnit := flag.String("agent-unit", "ops-agentd.service", "exact unit the watchdog may restart")
	heartbeatTimeout := flag.Duration("heartbeat-timeout", 45*time.Second, "stale heartbeat threshold")
	checkInterval := flag.Duration("check-interval", 5*time.Second, "watchdog check interval")
	restartCooldown := flag.Duration("restart-cooldown", 2*time.Minute, "minimum time between restarts")
	restartWindow := flag.Duration("restart-window", 30*time.Minute, "restart rate-limit window")
	maxRestarts := flag.Int("max-restarts", 3, "maximum restarts per window")
	flag.Parse()
	if *agentUID < 0 {
		fatal("agent-uid is required")
	}
	if err := systemdhelper.ValidateUnit(*agentUnit); err != nil {
		fatal(err.Error())
	}
	if *heartbeatTimeout <= 0 || *checkInterval <= 0 || *restartCooldown <= 0 || *restartWindow <= 0 || *maxRestarts < 1 {
		fatal("watchdog durations and max-restarts must be positive")
	}
	log, err := audit.Open(*auditFile)
	if err != nil {
		fatal(err.Error())
	}
	restarter := systemdhelper.SystemdRestarter{Runner: systemdhelper.ExecRunner{}}
	monitor := systemdhelper.NewMonitor(*agentUnit, *heartbeatTimeout, *checkInterval, *restartCooldown, *restartWindow, *maxRestarts, restarter, log)
	service := &systemdhelper.Service{AgentUID: uint32(*agentUID), Audit: log, Inspector: systemdhelper.OSInspector{Runner: systemdhelper.ExecRunner{}}, Monitor: monitor}
	server := &rpcserver.Server{Path: *socket, Mode: 0o660, SocketGID: *socketGID, Resolver: peercred.OSResolver{}, Handler: service}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if _, err := log.Append(map[string]interface{}{"type": "systemd_helper_started", "socket": *socket, "agentUid": *agentUID, "agentUnit": *agentUnit}); err != nil {
		fatal(err.Error())
	}
	go monitor.Run(ctx)
	if err := server.ListenAndServe(ctx); err != nil {
		fatal(err.Error())
	}
}
func fatal(message string) { fmt.Fprintln(os.Stderr, "ops-systemd-helper:", message); os.Exit(1) }
