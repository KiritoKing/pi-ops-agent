package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/pluginlease"
	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
)

type repeatedStrings []string

func (values *repeatedStrings) String() string { return fmt.Sprintf("%v", []string(*values)) }
func (values *repeatedStrings) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: agentd-pluginctl inspect|register|current|list|lease|lease-server [options]")
	}
	var err error
	switch os.Args[1] {
	case "inspect":
		err = inspect(os.Args[2:])
	case "register":
		err = register(os.Args[2:])
	case "current":
		err = current(os.Args[2:])
	case "list":
		err = list(os.Args[2:])
	case "lease":
		err = lease(os.Args[2:])
	case "lease-server":
		err = leaseServer(os.Args[2:])
	default:
		err = errors.New("usage: agentd-pluginctl inspect|register|current|list|lease|lease-server [options]")
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "agentd-pluginctl:", err.Error())
			os.Exit(3)
		}
		fatal(err.Error())
	}
}

func leaseServer(arguments []string) error {
	flags := flag.NewFlagSet("lease-server", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socketGID := flags.Int("socket-gid", -1, "client group owner for the fixed Unix socket")
	agentUID := flags.Int("agent-uid", -1, "ops-agent service UID")
	administratorUID := flags.Int("administrator-uid", -1, "enrolled local administrator UID")
	botmuxUID := flags.Int("botmux-uid", -1, "dedicated BotMux UID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *socketGID < 1 || *agentUID < 1 || *administratorUID < 1 || *botmuxUID < 1 {
		return errors.New("lease-server requires positive socket, agent, administrator, and BotMux numeric identities")
	}
	registry, err := pluginregistry.Open(pluginlease.FixedRegistryRoot)
	if err != nil {
		return err
	}
	server := &pluginlease.Server{
		Path: pluginlease.FixedSocketPath, SocketGID: *socketGID, Registry: registry,
		Resolver: peercred.OSResolver{},
		Authorizer: pluginlease.Authorizer{
			AdministratorUID: uint32(*administratorUID), AgentUID: uint32(*agentUID),
			BotMuxUID: uint32(*botmuxUID), WorkloadMaxDuration: 12 * time.Minute,
			LookupUsername: pluginlease.LookupOSUsername,
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return server.ListenAndServe(ctx)
}

// lease is a fixed, non-executing bridge for runtimes that cannot call flock
// directly. The runtime passes its already-open lock file as fd 3. This short
// process validates that descriptor, attaches the shared lock to the inherited
// open file description, emits one runtime registration, and exits. The parent
// runtime retains the same open file description and therefore the lock.
func lease(arguments []string) error {
	flags := flag.NewFlagSet("lease", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	root := flags.String("root", "/var/lib/ops-agent/plugins", "content-addressed registry root")
	pluginID := flags.String("plugin-id", "", "plugin ID")
	digest := flags.String("digest", "", "expected active sha256 digest")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *pluginID == "" || *digest == "" {
		return errors.New("lease requires --plugin-id, --digest, and no positional arguments")
	}
	registry, err := pluginregistry.Open(*root)
	if err != nil {
		return err
	}
	inherited := os.NewFile(3, "plugin-invocation-lease")
	if inherited == nil {
		return errors.New("lease requires the registry lock file on inherited fd 3")
	}
	defer inherited.Close()
	return writeInheritedLeaseRecord(registry, *pluginID, *digest, inherited, os.Stdout)
}

func writeInheritedLeaseRecord(
	registry *pluginregistry.Registry,
	pluginID, digest string,
	inherited *os.File,
	output io.Writer,
) error {
	registration, err := registry.PinRuntimeCurrentOnInheritedFile(pluginID, digest, inherited)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(output).Encode(registration); err != nil {
		// No parent may act on a failed handshake, so undo the inherited OFD
		// lock before returning an error.
		_ = syscall.Flock(int(inherited.Fd()), syscall.LOCK_UN)
		return err
	}
	return nil
}

func inspect(arguments []string) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	root := flags.String("root", "/var/lib/ops-agent/plugins", "content-addressed registry root")
	source := flags.String("source", "", "source plugin directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *source == "" {
		return errors.New("inspect requires --source and no positional arguments")
	}
	registry, err := pluginregistry.Open(*root)
	if err != nil {
		return err
	}
	inspection, err := registry.InspectSource(*source)
	if err != nil {
		return err
	}
	return writeJSON(inspection)
}

func register(arguments []string) error {
	if os.Geteuid() != 0 {
		return errors.New("register must run as root after an external human approval")
	}
	flags := flag.NewFlagSet("register", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	root := flags.String("root", "/var/lib/ops-agent/plugins", "content-addressed registry root")
	source := flags.String("source", "", "source plugin directory")
	pluginID := flags.String("plugin-id", "", "approved plugin ID")
	kind := flags.String("kind", "", "approved kind: adapter or workload")
	digest := flags.String("digest", "", "approved sha256 digest")
	approvedBy := flags.String("approved-by", "", "model-external approver identity")
	var scopes repeatedStrings
	flags.Var(&scopes, "scope", "approved requested scope (repeatable, manifest order)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *source == "" || *pluginID == "" || *digest == "" || *approvedBy == "" {
		return errors.New("register requires source, identity, digest, scopes, and approver")
	}
	var pluginKind pluginregistry.Kind
	switch *kind {
	case string(pluginregistry.KindAdapter):
		pluginKind = pluginregistry.KindAdapter
	case string(pluginregistry.KindWorkload):
		pluginKind = pluginregistry.KindWorkload
	default:
		return errors.New("register kind must be adapter or workload")
	}
	registry, err := pluginregistry.Open(*root)
	if err != nil {
		return err
	}
	registration, err := registry.Register(*source, pluginregistry.Grant{
		PluginID: *pluginID, Kind: pluginKind, Digest: *digest,
		RequestedScopes: []string(scopes), ApprovedBy: *approvedBy, ApprovedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return writeJSON(registration)
}

func current(arguments []string) error {
	flags := flag.NewFlagSet("current", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	root := flags.String("root", "/var/lib/ops-agent/plugins", "content-addressed registry root")
	pluginID := flags.String("plugin-id", "", "plugin ID")
	runtimeView := flags.Bool("runtime", false, "include the revalidated immutable runtime path and entrypoint")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *pluginID == "" {
		return errors.New("current requires --plugin-id and no positional arguments")
	}
	registry, err := pluginregistry.Open(*root)
	if err != nil {
		return err
	}
	if *runtimeView {
		registration, runtimeErr := registry.RuntimeCurrent(*pluginID)
		if runtimeErr != nil {
			return runtimeErr
		}
		return writeJSON(registration)
	}
	registration, err := registry.Current(*pluginID)
	if err != nil {
		return err
	}
	return writeJSON(registration)
}

func list(arguments []string) error {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	root := flags.String("root", "/var/lib/ops-agent/plugins", "content-addressed registry root")
	kind := flags.String("kind", "", "active plugin kind: adapter or workload")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("list accepts no positional arguments")
	}
	var pluginKind pluginregistry.Kind
	switch *kind {
	case string(pluginregistry.KindAdapter):
		pluginKind = pluginregistry.KindAdapter
	case string(pluginregistry.KindWorkload):
		pluginKind = pluginregistry.KindWorkload
	default:
		return errors.New("list kind must be adapter or workload")
	}
	registry, err := pluginregistry.Open(*root)
	if err != nil {
		return err
	}
	registrations, err := registry.ListRuntime(pluginKind)
	if err != nil {
		return err
	}
	return writeJSON(registrations)
}

func writeJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "agentd-pluginctl:", message)
	os.Exit(1)
}
