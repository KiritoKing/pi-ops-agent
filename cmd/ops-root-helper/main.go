package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/audit"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/roothelper"
	"github.com/KiritoKing/pi-ops-agent/internal/rpcserver"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

type stringList []string

func (values *stringList) String() string { return fmt.Sprint([]string(*values)) }
func (values *stringList) Set(value string) error {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" {
		return fmt.Errorf("write-root must be a clean absolute path below /")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	var roots stringList
	socket := flag.String("socket", "/run/ops-agent/root-helper.sock", "Unix socket path")
	stateDir := flag.String("state-dir", "/var/lib/ops-agent/root-helper", "root-helper state directory")
	auditFile := flag.String("audit-file", "/var/log/ops-agent/root-helper-audit.jsonl", "append-only hash-chain audit file")
	agentUID := flag.Int("agent-uid", -1, "UID allowed to prepare and inspect changes (required)")
	approverUID := flag.Int("approver-uid", 0, "UID allowed to approve, reject, and roll back changes")
	socketGID := flag.Int("socket-gid", -1, "group owner for the Unix socket")
	allowBreakglass := flag.Bool("allow-breakglass", false, "enable offline digest-bound break-glass capsules")
	rollbackTimeout := flag.Duration("rollback-timeout", 2*time.Minute, "independent timeout for automatic and explicit rollback")
	targetPolicyFile := flag.String("target-policy", "", "root-owned target policy JSON (required for remote server mode)")
	approvalKeyID := flag.String("approval-key-id", "local-approver-v1", "trusted Ed25519 approval key identifier")
	approvalPublicKey := flag.String("approval-public-key", "", "root-owned Ed25519 approval public key PEM")
	flag.Var(&roots, "write-root", "allowed privileged write root; repeat for multiple roots")
	flag.Parse()
	if *agentUID < 0 || *approverUID < 0 || *agentUID == *approverUID {
		fatal("agent-uid and approver-uid must be distinct non-negative UIDs")
	}
	if *rollbackTimeout <= 0 {
		fatal("rollback-timeout must be positive")
	}
	store, err := roothelper.OpenStore(*stateDir)
	if err != nil {
		fatal(err.Error())
	}
	log, err := audit.Open(*auditFile)
	if err != nil {
		fatal(err.Error())
	}
	executor := &roothelper.OSExecutor{StateDir: *stateDir, AllowedRoots: roots, AllowBreakglass: *allowBreakglass, Runner: roothelper.ExecRunner{}}
	var policy *targetpolicy.Policy
	if *targetPolicyFile != "" {
		policy, err = targetpolicy.Load(*targetPolicyFile, true)
		if err != nil {
			fatal("load target policy: " + err.Error())
		}
	}
	var approval *roothelper.ApprovalVerifier
	if *approvalPublicKey != "" {
		approval, err = roothelper.LoadApprovalVerifier(*approvalKeyID, *approvalPublicKey, true)
		if err != nil {
			fatal("load approval public key: " + err.Error())
		}
	}
	service := &roothelper.Service{
		AgentUID: uint32(*agentUID), ApproverUID: uint32(*approverUID), Store: store, Audit: log,
		Executor: executor, Inspector: roothelper.OSInspector{Runner: roothelper.ExecRunner{}}, Policy: policy,
		Approval: approval, RollbackTimeout: *rollbackTimeout,
	}
	if err := service.RecoverInterrupted(); err != nil {
		fatal(err.Error())
	}
	server := &rpcserver.Server{Path: *socket, Mode: 0o660, SocketGID: *socketGID, Resolver: peercred.OSResolver{}, Handler: service}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if _, err := log.Append(map[string]interface{}{"type": "root_helper_started", "socket": *socket, "agentUid": *agentUID, "approverUid": *approverUID}); err != nil {
		fatal(err.Error())
	}
	if err := server.ListenAndServe(ctx); err != nil {
		fatal(err.Error())
	}
}
func fatal(message string) { fmt.Fprintln(os.Stderr, "ops-root-helper:", message); os.Exit(1) }
