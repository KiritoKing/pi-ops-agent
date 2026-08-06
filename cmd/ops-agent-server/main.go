package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/agentserver"
	"github.com/KiritoKing/pi-ops-agent/internal/enrollment"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "enroll":
			runEnroll(os.Args[2:])
			return
		case "issue-enrollment":
			runIssueEnrollment(os.Args[2:])
			return
		case "serve":
			os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		}
	}
	runServer()
}

func runEnroll(arguments []string) {
	flags := flag.NewFlagSet("ops-agent-server enroll", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	controller := flags.String("controller", "", "controller HTTPS origin bound into the enrollment bundle")
	tokenFile := flags.String("token-file", "", "root-only signed enrollment bundle")
	configRoot := flags.String("config-root", "/etc/ops-agent", "endpoint configuration root")
	if err := flags.Parse(arguments); err != nil {
		fatal(err.Error())
	}
	if flags.NArg() != 0 || *controller == "" || *tokenFile == "" {
		fatal("enroll requires --controller and --token-file")
	}
	if err := enrollment.Install(enrollment.InstallOptions{
		Controller: *controller,
		BundlePath: *tokenFile,
		ConfigRoot: *configRoot,
	}); err != nil {
		fatal("enroll endpoint: " + err.Error())
	}
}

func runIssueEnrollment(arguments []string) {
	flags := flag.NewFlagSet("ops-agent-server issue-enrollment", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	controller := flags.String("controller", "", "controller HTTPS origin")
	endpoint := flags.String("endpoint", "", "new endpoint HTTPS origin")
	machineID := flags.String("machine-id", "", "stable new machine identity")
	machineName := flags.String("machine-name", "", "human-readable new machine name")
	output := flags.String("output", "", "new root-only enrollment bundle path")
	configRoot := flags.String("config-root", "/etc/ops-agent", "controller configuration root")
	if err := flags.Parse(arguments); err != nil {
		fatal(err.Error())
	}
	if flags.NArg() != 0 || *controller == "" || *endpoint == "" || *machineID == "" || *machineName == "" || *output == "" {
		fatal("issue-enrollment requires --controller, --endpoint, --machine-id, --machine-name and --output")
	}
	if err := enrollment.Issue(enrollment.IssueOptions{
		Controller:  *controller,
		Endpoint:    *endpoint,
		MachineID:   *machineID,
		MachineName: *machineName,
		OutputPath:  *output,
		ConfigRoot:  *configRoot,
	}); err != nil {
		fatal("issue enrollment: " + err.Error())
	}
}

func runServer() {
	listen := flag.String("listen", "0.0.0.0:7443", "HTTPS listen address")
	identityFile := flag.String("identity-file", "/etc/ops-agent/server-identity.json", "root-owned stable server identity JSON")
	targetPolicyFile := flag.String("target-policy", "/etc/ops-agent/targets.json", "root-owned target policy JSON")
	tlsCertificate := flag.String("tls-cert", "/etc/ops-agent/tls/server.crt", "server TLS certificate")
	tlsKey := flag.String("tls-key", "/etc/ops-agent/tls/server.key", "server TLS private key")
	clientCA := flag.String("client-ca", "/etc/ops-agent/tls/client-ca.crt", "client certificate authority bundle")
	rootSocket := flag.String("root-helper-socket", "/run/ops-agent/helper/root-helper.sock", "root-helper Unix socket")
	pluginCatalog := flag.String("plugin-catalog", "/opt/pi-ops-agent/current/catalog", "root-owned local plugin catalog")
	requestTimeout := flag.Duration("request-timeout", 2*time.Minute, "maximum root broker round trip")
	flag.Parse()
	if *requestTimeout <= 0 || *requestTimeout > 10*time.Minute {
		fatal("request-timeout must be positive and no greater than ten minutes")
	}
	identity, err := agentserver.LoadIdentity(*identityFile, true)
	if err != nil {
		fatal("load identity: " + err.Error())
	}
	policy, err := targetpolicy.Load(*targetPolicyFile, true)
	if err != nil {
		fatal("load target policy: " + err.Error())
	}
	application := &agentserver.Server{
		Identity: identity, Policy: policy,
		Backend: agentserver.RootClient{Socket: *rootSocket, Timeout: *requestTimeout}, CatalogDir: *pluginCatalog,
	}
	handler, err := application.Handler()
	if err != nil {
		fatal(err.Error())
	}
	tlsConfig, err := loadTLS(*tlsCertificate, *tlsKey, *clientCA)
	if err != nil {
		fatal(err.Error())
	}
	server := &http.Server{
		Addr: *listen, Handler: handler, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 3 * time.Minute, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 32 * 1024,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-result:
		if !errors.Is(err, http.ErrServerClosed) {
			fatal(err.Error())
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fatal("shutdown: " + err.Error())
		}
	}
}

func loadTLS(certificateFile, keyFile, caFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPayload, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPayload) {
		return nil, errors.New("client CA file contains no certificates")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		NextProtos: []string{"h2", "http/1.1"},
	}, nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "ops-agent-server:", message)
	os.Exit(1)
}
