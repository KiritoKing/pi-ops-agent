package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/guardian"
)

func main() {
	flags := flag.NewFlagSet("agentd-guardian", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/ops-agent/agentd-guardian.json", "strict guardian configuration file")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fatal(err.Error())
	}
	if flags.NArg() != 0 {
		fatal("unexpected positional arguments")
	}
	config, err := guardian.LoadConfig(*configPath)
	if err != nil {
		fatal(err.Error())
	}
	if err := config.ValidateRuntime(); err != nil {
		fatal(err.Error())
	}
	processes, err := guardian.NewLinuxProcessAccess()
	if err != nil {
		fatal(err.Error())
	}
	supervisor := &guardian.Supervisor{
		Config: config, Source: guardian.FileHeartbeatSource{Path: config.HeartbeatPath},
		Processes: processes, Now: time.Now, SelfPID: os.Getpid(),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("agentd-guardian started for uid=%d executable=%s cgroup=%s", config.ExpectedUID, config.ExpectedExecutable, config.ExpectedCgroup)
	supervisor.Run(ctx, func(result guardian.Result, checkErr error) {
		if checkErr != nil {
			log.Printf("guardian check outcome=%s pid=%d error=%q", result.Outcome, result.PID, checkErr.Error())
			return
		}
		if result.Outcome != guardian.OutcomeHealthy {
			log.Printf("guardian check outcome=%s pid=%d reason=%q", result.Outcome, result.PID, result.Reason)
		}
	})
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "agentd-guardian:", message)
	os.Exit(1)
}
