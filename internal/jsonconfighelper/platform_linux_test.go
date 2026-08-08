//go:build linux

package jsonconfighelper

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type linuxFixture struct {
	home       string
	configDir  string
	configPath string
	stageRoot  string
}

func newLinuxFixture(t *testing.T, payload []byte) linuxFixture {
	t.Helper()
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		t.Skip("secure helper intentionally refuses root test processes")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configDir := filepath.Join(home, ".config")
	stageRoot := filepath.Join(root, "stage")
	for _, path := range []string{home, configDir, stageRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(configDir, "bots.json")
	writeFixtureDocument(t, configPath, payload)
	return linuxFixture{home: home, configDir: configDir, configPath: configPath, stageRoot: stageRoot}
}

func writeFixtureDocument(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixtureInspectOptions(fixture linuxFixture) inspectOptions {
	return inspectOptions{
		Home: fixture.home, Relative: ".config/bots.json", SelectorKey: "appID",
		SelectorValue: "cli_one", Field: "model",
	}
}

func fixtureMutateOptions(fixture linuxFixture, output string, value mutateValue) mutateOptions {
	return mutateOptions{
		inspectOptions: fixtureInspectOptions(fixture),
		StageRoot:      fixture.stageRoot,
		Output:         output,
		Value:          value,
	}
}

func TestLinuxInspectRejectsSymlinkModeSpecialDuplicateAndWrongSelector(t *testing.T) {
	before := []byte(`[{"appID":"cli_one","model":"old","unknown":{"preserved":true}}]`)
	fixture := newLinuxFixture(t, before)
	options := fixtureInspectOptions(fixture)
	proof, err := inspectPlatform(options)
	if err != nil {
		t.Fatalf("inspect valid fixture: %v", err)
	}
	if proof.Source.SHA256 != digestPayload(before) || proof.Selected.StringValue == nil || *proof.Selected.StringValue != "old" {
		t.Fatalf("unexpected inspect proof: %#v", proof)
	}

	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(fixture.configDir, "link.json")
		if err := os.Symlink(fixture.configPath, link); err != nil {
			t.Fatal(err)
		}
		changed := options
		changed.Relative = ".config/link.json"
		if _, err := inspectPlatform(changed); err == nil {
			t.Fatal("symlink config was accepted")
		}
	})

	t.Run("mode", func(t *testing.T) {
		if err := os.Chmod(fixture.configPath, 0o644); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(fixture.configPath, 0o600)
		if _, err := inspectPlatform(options); err == nil {
			t.Fatal("group/world-readable config was accepted")
		}
	})

	t.Run("special", func(t *testing.T) {
		fifo := filepath.Join(fixture.configDir, "fifo.json")
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		changed := options
		changed.Relative = ".config/fifo.json"
		if _, err := inspectPlatform(changed); err == nil {
			t.Fatal("FIFO config was accepted")
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		duplicate := filepath.Join(fixture.configDir, "duplicate.json")
		writeFixtureDocument(t, duplicate, []byte(`[{"appID":"cli_one","model":"one","model":"two"}]`))
		changed := options
		changed.Relative = ".config/duplicate.json"
		if _, err := inspectPlatform(changed); err == nil {
			t.Fatal("duplicate JSON key was accepted")
		}
	})

	t.Run("selector", func(t *testing.T) {
		changed := options
		changed.SelectorValue = "missing"
		if _, err := inspectPlatform(changed); err == nil {
			t.Fatal("missing selector was accepted")
		}
	})
}

func TestLinuxRunEmitsOneBoundedStrictInspectProof(t *testing.T) {
	payload := []byte(`[{"appID":"cli_one","model":"old","secretUnknown":"not-emitted"}]`)
	fixture := newLinuxFixture(t, payload)
	arguments := []string{
		"inspect", "--home", fixture.home, "--relative", ".config/bots.json",
		"--selector-key", "appID", "--selector-value", "cli_one", "--field", "model",
	}
	var output bytes.Buffer
	if err := Run(arguments, &output); err != nil {
		t.Fatalf("run inspect: %v", err)
	}
	if output.Len() > 4096 || strings.Contains(output.String(), "secretUnknown") || strings.Contains(output.String(), "not-emitted") {
		t.Fatalf("inspect emitted unbounded or unknown config data: %s", output.String())
	}
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	var proof inspectProof
	if err := decoder.Decode(&proof); err != nil {
		t.Fatalf("decode strict proof: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("proof has trailing JSON: %v", err)
	}
	if proof.Source.SHA256 != digestPayload(payload) || proof.Selected.StringValue == nil || *proof.Selected.StringValue != "old" {
		t.Fatalf("unexpected proof: %#v", proof)
	}
}

func TestLinuxInspectDirectoryEmitsOnlyStableIdentityMetadata(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "allowed", "workspace")
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(directory), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}

	proof, err := inspectDirectoryPlatform(inspectDirectoryOptions{Root: root, Path: directory})
	if err != nil {
		t.Fatalf("inspect valid directory: %v", err)
	}
	if proof.Version != 1 || proof.Operation != "inspect-directory" ||
		proof.ResidualRisk != "pathname_may_be_replaced_after_verification" ||
		proof.Root.Dev == 0 || proof.Root.Ino == 0 || proof.Directory.Dev == 0 || proof.Directory.Ino == 0 ||
		proof.Directory.Mode != 0o750 || proof.Directory.UID != uint32(os.Geteuid()) {
		t.Fatalf("unexpected inspect-directory proof: %#v", proof)
	}

	var output bytes.Buffer
	if err := Run([]string{"inspect-directory", "--root", root, "--path", directory}, &output); err != nil {
		t.Fatalf("run inspect-directory: %v", err)
	}
	if output.Len() > 1024 || strings.Contains(output.String(), root) || strings.Contains(output.String(), directory) ||
		strings.Contains(output.String(), "allowed") || strings.Contains(output.String(), "workspace") {
		t.Fatalf("inspect-directory proof leaked a path or was unbounded: %s", output.String())
	}
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	var decoded inspectDirectoryProof
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode strict inspect-directory proof: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("inspect-directory proof has trailing JSON: %v", err)
	}
	if decoded != proof {
		t.Fatalf("run and direct proofs differ: %#v %#v", decoded, proof)
	}

	equal, err := inspectDirectoryPlatform(inspectDirectoryOptions{Root: directory, Path: directory})
	if err != nil || equal.Root != equal.Directory {
		t.Fatalf("root-equal directory inspection failed: %#v %v", equal, err)
	}
	filesystemRoot, err := inspectDirectoryPlatform(inspectDirectoryOptions{Root: "/", Path: "/"})
	if err != nil || filesystemRoot.Root != filesystemRoot.Directory {
		t.Fatalf("read-open non-current-owner root was rejected: %#v %v", filesystemRoot, err)
	}
}

func TestLinuxInspectDirectoryRejectsSymlinksEscapeFilesAndUnreadableDirectories(t *testing.T) {
	t.Run("intermediate symlink", func(t *testing.T) {
		root := t.TempDir()
		realDirectory := filepath.Join(root, "real", "workspace")
		if err := os.MkdirAll(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectDirectoryPlatform(inspectDirectoryOptions{
			Root: root, Path: filepath.Join(root, "link", "workspace"),
		}); err == nil {
			t.Fatal("intermediate symlink was accepted")
		}
	})

	t.Run("final symlink", func(t *testing.T) {
		root := t.TempDir()
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "link")
		if err := os.Symlink(realDirectory, link); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectDirectoryPlatform(inspectDirectoryOptions{Root: root, Path: link}); err == nil {
			t.Fatal("final symlink was accepted")
		}
	})

	t.Run("symlink root", func(t *testing.T) {
		container := t.TempDir()
		realRoot := filepath.Join(container, "real")
		directory := filepath.Join(realRoot, "workspace")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		linkRoot := filepath.Join(container, "root-link")
		if err := os.Symlink(realRoot, linkRoot); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectDirectoryPlatform(inspectDirectoryOptions{
			Root: linkRoot, Path: filepath.Join(linkRoot, "workspace"),
		}); err == nil {
			t.Fatal("symlink root was accepted")
		}
	})

	t.Run("regular file", func(t *testing.T) {
		root := t.TempDir()
		file := filepath.Join(root, "file")
		if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectDirectoryPlatform(inspectDirectoryOptions{Root: root, Path: file}); err == nil {
			t.Fatal("regular file was accepted")
		}
	})

	t.Run("lexical escape", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(filepath.Dir(root), "outside")
		if _, err := inspectDirectoryPlatform(inspectDirectoryOptions{Root: root, Path: outside}); err == nil {
			t.Fatal("path outside its root was accepted")
		}
	})

	t.Run("read-open denied", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, "execute-only")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o100); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(directory, 0o700)
		if _, err := inspectDirectoryPlatform(inspectDirectoryOptions{Root: root, Path: directory}); err == nil {
			t.Fatal("directory without read-open access was accepted")
		}
	})
}

func TestLinuxInspectDirectoryRejectsRootAndSelectedPathSwaps(t *testing.T) {
	t.Run("root pathname swap", func(t *testing.T) {
		container := t.TempDir()
		root := filepath.Join(container, "root")
		replacement := filepath.Join(container, "replacement")
		for _, base := range []string{root, replacement} {
			if err := os.MkdirAll(filepath.Join(base, "workspace"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		hooks := productionInspectDirectoryHooks()
		hooks.afterInitialOpen = func() {
			if err := os.Rename(root, filepath.Join(container, "old-root")); err != nil {
				t.Errorf("move initial root: %v", err)
				return
			}
			if err := os.Rename(replacement, root); err != nil {
				t.Errorf("install replacement root: %v", err)
			}
		}
		if _, err := inspectDirectoryWithHooks(inspectDirectoryOptions{
			Root: root, Path: filepath.Join(root, "workspace"),
		}, hooks); err == nil {
			t.Fatal("root pathname swap was accepted")
		}
	})

	t.Run("selected pathname swap", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, "workspace")
		replacement := filepath.Join(root, "replacement")
		for _, path := range []string{directory, replacement} {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		hooks := productionInspectDirectoryHooks()
		hooks.afterInitialOpen = func() {
			if err := os.Rename(directory, filepath.Join(root, "old-workspace")); err != nil {
				t.Errorf("move initial selected directory: %v", err)
				return
			}
			if err := os.Rename(replacement, directory); err != nil {
				t.Errorf("install replacement selected directory: %v", err)
			}
		}
		if _, err := inspectDirectoryWithHooks(inspectDirectoryOptions{Root: root, Path: directory}, hooks); err == nil {
			t.Fatal("selected pathname swap was accepted")
		}
	})
}

func TestLinuxOwnerValidatorsRejectAnotherUID(t *testing.T) {
	uid := uint32(os.Geteuid())
	directory := unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: uid + 1}
	if err := validateDirectory(directory, uid, false); err == nil {
		t.Fatal("directory owned by another UID was accepted")
	}
	regular := unix.Stat_t{Mode: unix.S_IFREG | 0o600, Uid: uid + 1, Nlink: 1, Size: 2}
	if err := validateRegularFile(regular, uid); err == nil {
		t.Fatal("regular file owned by another UID was accepted")
	}
}

func TestLinuxSnapshotIsExclusiveStrictAndDurable(t *testing.T) {
	before := []byte(`[{"appID":"cli_one","model":"old","unknown":{"preserved":true}}]`)
	fixture := newLinuxFixture(t, before)
	output := filepath.Join(fixture.stageRoot, "before.json")
	options := snapshotOptions{
		inspectOptions: fixtureInspectOptions(fixture), StageRoot: fixture.stageRoot, Output: output,
	}
	proof, err := snapshotPlatform(options)
	if err != nil {
		t.Fatalf("snapshot valid fixture: %v", err)
	}
	if proof.Source.SHA256 != digestPayload(before) || proof.Snapshot.SHA256 != digestPayload(before) {
		t.Fatalf("snapshot proof did not bind exact bytes: %#v", proof)
	}
	payload, err := os.ReadFile(output)
	if err != nil || string(payload) != string(before) {
		t.Fatalf("snapshot did not preserve exact unknown bytes: %q, %v", payload, err)
	}
	if _, err := snapshotPlatform(options); err == nil {
		t.Fatal("snapshot overwrote an existing output")
	}

	t.Run("stage root mode", func(t *testing.T) {
		if err := os.Chmod(fixture.stageRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(fixture.stageRoot, 0o700)
		changed := options
		changed.Output = filepath.Join(fixture.stageRoot, "unsafe.json")
		if _, err := snapshotPlatform(changed); err == nil {
			t.Fatal("non-0700 stage root was accepted")
		}
	})

	t.Run("file fsync failure", func(t *testing.T) {
		changed := options
		changed.Output = filepath.Join(fixture.stageRoot, "fsync-failure.json")
		hooks := productionLinuxHooks()
		hooks.fsync = func(int) error { return errors.New("injected fsync failure") }
		if _, err := snapshotWithHooks(changed, hooks); err == nil {
			t.Fatal("snapshot ignored file fsync failure")
		}
		if _, err := os.Lstat(changed.Output); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed snapshot left an output: %v", err)
		}
	})
}

func TestLinuxMutateIsExclusiveTypedDurableAndProofBounded(t *testing.T) {
	before := []byte(`[
		{"appID":"cli_one","model":"old","unknown":{"secret":"must-not-appear-in-proof","nested":[1,true,null]}},
		{"appID":"cli_two","model":"untouched"}
	]`)
	fixture := newLinuxFixture(t, before)
	outputPath := filepath.Join(fixture.stageRoot, "after.json")
	newModel := "new/model"
	options := fixtureMutateOptions(fixture, outputPath, mutateValue{Kind: "string", StringValue: &newModel})
	proof, err := mutatePlatform(options)
	if err != nil {
		t.Fatalf("mutate valid fixture: %v", err)
	}
	if proof.Version != 1 || proof.Operation != "mutate" || !proof.WholeDocumentRewrite ||
		proof.Source.SHA256 != digestPayload(before) || proof.BeforeDigest != proof.Source.SHA256 ||
		proof.AfterDigest != proof.Output.SHA256 || proof.Before.StringValue == nil || *proof.Before.StringValue != "old" ||
		proof.After.StringValue == nil || *proof.After.StringValue != newModel {
		t.Fatalf("unexpected mutate proof: %#v", proof)
	}
	if proof.Source.SHA256 == proof.Output.SHA256 {
		t.Fatal("mutation did not produce distinct before/after digests")
	}
	assertFileBytes(t, fixture.configPath, before)
	outputPayload, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	outputDocument, err := parseStrictDocument(outputPayload)
	if err != nil {
		t.Fatalf("parse mutation output: %v", err)
	}
	selected, err := outputDocument.selectValue("appID", "cli_one", "model")
	if err != nil || selected.StringValue == nil || *selected.StringValue != newModel {
		t.Fatalf("unexpected staged selected value: %#v %v", selected, err)
	}
	second, err := outputDocument.selectValue("appID", "cli_two", "model")
	if err != nil || second.StringValue == nil || *second.StringValue != "untouched" {
		t.Fatalf("non-selected object changed: %#v %v", second, err)
	}
	selectedObject, err := outputDocument.selectObject("appID", "cli_one")
	if err != nil || selectedObject["unknown"] == nil {
		t.Fatalf("unknown semantic value was not preserved: %#v %v", selectedObject, err)
	}
	stat, err := os.Stat(outputPath)
	if err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatalf("mutation output mode is not 0600: %v %v", stat, err)
	}
	encoded, err := json.Marshal(proof)
	if err != nil || len(encoded) > 4096 || bytes.Contains(encoded, []byte("must-not-appear-in-proof")) ||
		bytes.Contains(encoded, []byte(`"unknown"`)) {
		t.Fatalf("mutation proof leaked unknown config or was unbounded: %s %v", encoded, err)
	}

	if _, err := mutatePlatform(options); err == nil {
		t.Fatal("mutate overwrote an existing output")
	}
	assertFileBytes(t, outputPath, outputPayload)
}

func TestLinuxRunEmitsOneStrictMutateProofWithoutUnknownConfig(t *testing.T) {
	payload := []byte(`[{"appID":"cli_one","model":"old","secretUnknown":"not-emitted"}]`)
	fixture := newLinuxFixture(t, payload)
	arguments := []string{
		"mutate", "--home", fixture.home, "--relative", ".config/bots.json",
		"--selector-key", "appID", "--selector-value", "cli_one", "--field", "model",
		"--stage-root", fixture.stageRoot, "--output", filepath.Join(fixture.stageRoot, "after.json"),
		"--value-kind", "string", "--string-value", "new",
	}
	var output bytes.Buffer
	if err := Run(arguments, &output); err != nil {
		t.Fatalf("run mutate: %v", err)
	}
	if output.Len() > 4096 || strings.Contains(output.String(), "secretUnknown") || strings.Contains(output.String(), "not-emitted") {
		t.Fatalf("mutate emitted unknown config data: %s", output.String())
	}
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	var proof mutateProof
	if err := decoder.Decode(&proof); err != nil {
		t.Fatalf("decode strict mutate proof: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("mutate proof has trailing JSON: %v", err)
	}
	if !proof.WholeDocumentRewrite || proof.BeforeDigest != digestPayload(payload) || proof.AfterDigest == proof.BeforeDigest {
		t.Fatalf("mutate proof did not bind the rewrite: %#v", proof)
	}
}

func TestLinuxMutateRejectsStageAndSourceRacesAndCleansOwnedOutput(t *testing.T) {
	before := []byte(`[{"appID":"cli_one","model":"old"}]`)
	newModel := "new"

	t.Run("directory fsync failure", func(t *testing.T) {
		fixture := newLinuxFixture(t, before)
		outputPath := filepath.Join(fixture.stageRoot, "after.json")
		options := fixtureMutateOptions(fixture, outputPath, mutateValue{Kind: "string", StringValue: &newModel})
		hooks := productionLinuxHooks()
		calls := 0
		hooks.fsync = func(fd int) error {
			calls++
			if calls == 2 { // staged file, then its containing directory
				return errors.New("injected directory fsync failure")
			}
			return unix.Fsync(fd)
		}
		if _, err := mutateWithHooks(options, hooks); err == nil {
			t.Fatal("mutate ignored directory fsync failure")
		}
		if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed mutation left an owned output: %v", err)
		}
	})

	t.Run("source changes during output fsync", func(t *testing.T) {
		fixture := newLinuxFixture(t, before)
		outputPath := filepath.Join(fixture.stageRoot, "after.json")
		options := fixtureMutateOptions(fixture, outputPath, mutateValue{Kind: "string", StringValue: &newModel})
		raced := []byte(`[{"appID":"cli_one","model":"raced"}]`)
		hooks := productionLinuxHooks()
		calls := 0
		hooks.fsync = func(fd int) error {
			calls++
			if calls == 1 {
				if err := os.WriteFile(fixture.configPath, raced, 0o600); err != nil {
					t.Errorf("inject source race: %v", err)
				}
			}
			return unix.Fsync(fd)
		}
		if _, err := mutateWithHooks(options, hooks); err == nil || !strings.Contains(err.Error(), "source changed") {
			t.Fatalf("source race was not rejected: %v", err)
		}
		if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source-raced mutation left an owned output: %v", err)
		}
		assertFileBytes(t, fixture.configPath, raced)
	})

	t.Run("preexisting symlink output", func(t *testing.T) {
		fixture := newLinuxFixture(t, before)
		victim := filepath.Join(fixture.stageRoot, "victim.json")
		writeFixtureDocument(t, victim, []byte(`[{"safe":true}]`))
		outputPath := filepath.Join(fixture.stageRoot, "after.json")
		if err := os.Symlink(victim, outputPath); err != nil {
			t.Fatal(err)
		}
		options := fixtureMutateOptions(fixture, outputPath, mutateValue{Kind: "string", StringValue: &newModel})
		if _, err := mutatePlatform(options); err == nil {
			t.Fatal("mutate replaced a preexisting symlink output")
		}
		assertFileBytes(t, victim, []byte(`[{"safe":true}]`))
	})
}

func TestLinuxCommitRollbackAndIdempotency(t *testing.T) {
	before := []byte(`[{"appID":"cli_one","model":"old","unknown":{"preserved":true}}]`)
	after := []byte(`[{"appID":"cli_one","model":"new","unknown":{"preserved":true}}]`)
	fixture := newLinuxFixture(t, before)
	afterPath := filepath.Join(fixture.stageRoot, "after.json")
	beforePath := filepath.Join(fixture.stageRoot, "before.json")
	writeFixtureDocument(t, afterPath, after)
	writeFixtureDocument(t, beforePath, before)
	options := commitOptions{
		Home: fixture.home, Relative: ".config/bots.json", StageRoot: fixture.stageRoot, Staged: afterPath,
		ExpectedBefore: digestPayload(before), ExpectedAfter: digestPayload(after), Operation: "commit",
	}
	proof, err := commitPlatform(options)
	if err != nil || proof.Outcome != "committed" || proof.Current == nil || proof.Current.SHA256 != digestPayload(after) {
		t.Fatalf("commit failed: %#v, %v", proof, err)
	}
	assertFileBytes(t, fixture.configPath, after)
	assertNoExchangeTemporary(t, fixture.configDir)

	idempotent, err := commitPlatform(options)
	if err != nil || idempotent.Outcome != "already_after" || idempotent.MutationAttempted {
		t.Fatalf("idempotent commit failed: %#v, %v", idempotent, err)
	}

	rollback := commitOptions{
		Home: fixture.home, Relative: ".config/bots.json", StageRoot: fixture.stageRoot, Staged: beforePath,
		ExpectedBefore: digestPayload(after), ExpectedAfter: digestPayload(before), Operation: "rollback",
	}
	rolledBack, err := commitPlatform(rollback)
	if err != nil || rolledBack.Outcome != "committed" || rolledBack.Operation != "rollback" {
		t.Fatalf("rollback failed: %#v, %v", rolledBack, err)
	}
	assertFileBytes(t, fixture.configPath, before)
}

func TestLinuxCommitRacingWriterIsExchangedBack(t *testing.T) {
	before := []byte(`[{"appID":"cli_one","model":"old"}]`)
	after := []byte(`[{"appID":"cli_one","model":"new"}]`)
	raced := []byte(`[{"appID":"cli_one","model":"raced"}]`)
	fixture := newLinuxFixture(t, before)
	stagedPath := filepath.Join(fixture.stageRoot, "after.json")
	writeFixtureDocument(t, stagedPath, after)
	options := commitOptions{
		Home: fixture.home, Relative: ".config/bots.json", StageRoot: fixture.stageRoot, Staged: stagedPath,
		ExpectedBefore: digestPayload(before), ExpectedAfter: digestPayload(after), Operation: "commit",
	}
	hooks := productionLinuxHooks()
	hooks.beforeExchange = func() {
		if err := os.WriteFile(fixture.configPath, raced, 0o600); err != nil {
			t.Errorf("inject race: %v", err)
		}
	}
	proof, err := commitWithHooks(options, hooks)
	if err == nil || proof.Outcome != "refused_restored" || !proof.MutationAttempted || !proof.ExchangeRestored ||
		proof.ResidualState != "exchange_restored_at_verification" || proof.Current == nil ||
		proof.Current.SHA256 != digestPayload(raced) {
		t.Fatalf("racing writer was not reported as a restored refusal: %#v, %v", proof, err)
	}
	assertFileBytes(t, fixture.configPath, raced)
	assertNoExchangeTemporary(t, fixture.configDir)
}

func TestLinuxCommitRacingRenameIsExchangedBack(t *testing.T) {
	before := []byte(`[{"appID":"cli_one","model":"old"}]`)
	after := []byte(`[{"appID":"cli_one","model":"new"}]`)
	replacement := []byte(`[{"appID":"cli_one","model":"replacement"}]`)
	fixture := newLinuxFixture(t, before)
	stagedPath := filepath.Join(fixture.stageRoot, "after.json")
	replacementPath := filepath.Join(fixture.configDir, "replacement.json")
	writeFixtureDocument(t, stagedPath, after)
	writeFixtureDocument(t, replacementPath, replacement)
	options := commitOptions{
		Home: fixture.home, Relative: ".config/bots.json", StageRoot: fixture.stageRoot, Staged: stagedPath,
		ExpectedBefore: digestPayload(before), ExpectedAfter: digestPayload(after), Operation: "commit",
	}
	hooks := productionLinuxHooks()
	hooks.beforeExchange = func() {
		if err := os.Rename(replacementPath, fixture.configPath); err != nil {
			t.Errorf("inject rename race: %v", err)
		}
	}
	proof, err := commitWithHooks(options, hooks)
	if err == nil || proof.Outcome != "refused_restored" || !proof.ExchangeRestored ||
		proof.Current == nil || proof.Current.SHA256 != digestPayload(replacement) {
		t.Fatalf("racing rename was not exchanged back: %#v, %v", proof, err)
	}
	assertFileBytes(t, fixture.configPath, replacement)
	assertNoExchangeTemporary(t, fixture.configDir)
}

func TestLinuxCommitPostExchangeFsyncFailureIsUncertain(t *testing.T) {
	before := []byte(`[{"appID":"cli_one","model":"old"}]`)
	after := []byte(`[{"appID":"cli_one","model":"new"}]`)
	fixture := newLinuxFixture(t, before)
	stagedPath := filepath.Join(fixture.stageRoot, "after.json")
	writeFixtureDocument(t, stagedPath, after)
	options := commitOptions{
		Home: fixture.home, Relative: ".config/bots.json", StageRoot: fixture.stageRoot, Staged: stagedPath,
		ExpectedBefore: digestPayload(before), ExpectedAfter: digestPayload(after), Operation: "commit",
	}
	hooks := productionLinuxHooks()
	calls := 0
	hooks.fsync = func(fd int) error {
		calls++
		if calls == 3 { // temporary file, pre-exchange directory, post-exchange directory
			return errors.New("injected post-exchange fsync failure")
		}
		return unix.Fsync(fd)
	}
	proof, err := commitWithHooks(options, hooks)
	if err == nil || proof.Outcome != "outcome_uncertain" || !proof.MutationAttempted || proof.ResidualState != "unknown" {
		t.Fatalf("post-exchange fsync failure was not uncertain: %#v, %v", proof, err)
	}
}

func assertFileBytes(t *testing.T, path string, expected []byte) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil || string(payload) != string(expected) {
		t.Fatalf("unexpected file payload: %q, %v", payload, err)
	}
}

func assertNoExchangeTemporary(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".agentd-json-config-") {
			t.Fatalf("unexpected exchange temporary remains: %s", entry.Name())
		}
	}
}
