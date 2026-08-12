package main

import (
	"context"
	"errors"
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
	socket := flag.String("socket", "/run/ops-agent/helper/root-helper.sock", "Unix socket path")
	stateDir := flag.String("state-dir", "/var/lib/ops-agent/root-helper", "root-helper state directory")
	auditFile := flag.String("audit-file", "/var/log/ops-agent/root-helper-audit.jsonl", "append-only hash-chain audit file")
	agentUID := flag.Int("agent-uid", -1, "UID allowed to prepare and inspect changes (required)")
	approverUID := flag.Int("approver-uid", 0, "UID allowed to approve, reject, and roll back changes")
	socketGID := flag.Int("socket-gid", -1, "group owner for the Unix socket")
	_ = flag.Bool("allow-breakglass", false, "deprecated compatibility flag; core manual root capsules always require per-change approval")
	domain := flag.String("domain", roothelper.DomainCore, "broker operation domain: core or pve")
	changeIDPrefix := flag.String("change-id-prefix", "", "override the domain-specific generated change ID prefix")
	rollbackTimeout := flag.Duration("rollback-timeout", 2*time.Minute, "independent timeout for automatic and explicit rollback")
	targetPolicyFile := flag.String("target-policy", "", "root-owned target policy JSON (required for remote server mode)")
	approvalKeyID := flag.String("approval-key-id", "local-approver-v1", "trusted Ed25519 approval key identifier")
	approvalPublicKey := flag.String("approval-public-key", "", "root-owned Ed25519 approval public key PEM")
	receiptKeyID := flag.String("receipt-key-id", "", "root broker Ed25519 receipt key identifier")
	receiptPrivateKey := flag.String("receipt-private-key", "", "root-owned owner-only Ed25519 receipt private key PEM")
	sourcePluginRoot := flag.String("source-plugin-root", "/var/lib/ops-agent/plugin-sources", "reviewable source plugin candidates")
	sourcePluginRegistry := flag.String("source-plugin-registry", "/var/lib/ops-agent/plugins", "content-addressed source plugin registry")
	flag.Var(&roots, "write-root", "allowed privileged write root; repeat for multiple roots")
	flag.Parse()
	if *agentUID < 0 || *approverUID < 0 || *agentUID == *approverUID {
		fatal("agent-uid and approver-uid must be distinct non-negative UIDs")
	}
	if *rollbackTimeout <= 0 {
		fatal("rollback-timeout must be positive")
	}
	if *domain != roothelper.DomainCore && *domain != roothelper.DomainPVE {
		fatal("domain must be core or pve")
	}
	if *changeIDPrefix != "" {
		expected := "change-"
		if *domain == roothelper.DomainPVE {
			expected = "pve-change-"
		}
		if *changeIDPrefix != expected {
			fatal("change-id-prefix must exactly match the selected broker domain")
		}
	}
	if err := validateRemoteSecurityConfig(*targetPolicyFile, *approvalKeyID,
		*approvalPublicKey, *receiptKeyID, *receiptPrivateKey); err != nil {
		fatal(err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	for label, path := range map[string]string{
		"source-plugin-root": *sourcePluginRoot, "source-plugin-registry": *sourcePluginRegistry,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			fatal(label + " must be a clean absolute path below /")
		}
	}
	store, err := roothelper.OpenStore(*stateDir)
	if err != nil {
		fatal(err.Error())
	}
	log, err := audit.Open(*auditFile)
	if err != nil {
		fatal(err.Error())
	}
	var policy *targetpolicy.Policy
	if *targetPolicyFile != "" {
		policy, err = targetpolicy.Load(*targetPolicyFile, true)
		if err != nil {
			fatal("load target policy: " + err.Error())
		}
	}
	executor := &roothelper.OSExecutor{
		StateDir: *stateDir, AllowedRoots: roots, AllowBreakglass: *domain == roothelper.DomainCore,
		Runner: roothelper.ExecRunner{}, Policy: policy,
		SourcePluginRoot: *sourcePluginRoot, SourcePluginRegistry: *sourcePluginRegistry,
	}
	var approval *roothelper.ApprovalVerifier
	if *approvalPublicKey != "" {
		approval, err = roothelper.LoadApprovalVerifier(*approvalKeyID, *approvalPublicKey, true)
		if err != nil {
			fatal("load approval public key: " + err.Error())
		}
	}
	var receiptSigner *roothelper.BrokerReceiptSigner
	if *receiptPrivateKey != "" {
		receiptSigner, err = roothelper.LoadBrokerReceiptSigner(*receiptKeyID, *domain, *receiptPrivateKey, true)
		if err != nil {
			fatal("load broker receipt private key: " + err.Error())
		}
	}
	service := &roothelper.Service{
		AgentUID: uint32(*agentUID), ApproverUID: uint32(*approverUID), Store: store, Audit: log,
		Executor: executor, Inspector: roothelper.OSInspector{Runner: roothelper.ExecRunner{}}, Policy: policy,
		Approval: approval, ReceiptSigner: receiptSigner, RollbackTimeout: *rollbackTimeout,
		Domain: *domain, ChangeIDPrefix: *changeIDPrefix, PVEBackgroundContext: ctx,
	}
	if err := service.RecoverInterrupted(); err != nil {
		fatal(err.Error())
	}
	server := &rpcserver.Server{Path: *socket, Mode: 0o660, SocketGID: *socketGID, Resolver: peercred.OSResolver{}, Handler: service}
	if _, err := log.Append(map[string]interface{}{"type": "root_helper_started", "socket": *socket, "agentUid": *agentUID, "approverUid": *approverUID, "domain": *domain}); err != nil {
		fatal(err.Error())
	}
	if err := server.ListenAndServe(ctx); err != nil {
		fatal(err.Error())
	}
}

func validateRemoteSecurityConfig(targetPolicyFile, approvalKeyID, approvalPublicKey,
	receiptKeyID, receiptPrivateKey string) error {
	if (receiptKeyID == "") != (receiptPrivateKey == "") {
		return errors.New("receipt-key-id and receipt-private-key must be configured together")
	}
	if targetPolicyFile == "" {
		return nil
	}
	if approvalKeyID == "" || approvalPublicKey == "" {
		return errors.New("remote server mode requires an approval key ID and public key")
	}
	if receiptPrivateKey == "" {
		return errors.New("remote server mode requires a domain-specific broker receipt signing key")
	}
	return nil
}

func fatal(message string) { fmt.Fprintln(os.Stderr, "ops-root-helper:", message); os.Exit(1) }
