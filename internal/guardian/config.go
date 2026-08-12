package guardian

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	configVersion       = 1
	maximumConfigBytes  = 16 * 1024
	maximumRecordBytes  = 4 * 1024
	minimumCheckPeriod  = 100 * time.Millisecond
	maximumCheckPeriod  = time.Minute
	minimumTimeout      = time.Second
	maximumTimeout      = 10 * time.Minute
	maximumTermGrace    = 30 * time.Second
	maximumOperationRun = 5 * time.Second
	maximumClockSkew    = 30 * time.Second
)

type Config struct {
	HeartbeatPath      string
	ExpectedUID        uint32
	ExpectedExecutable string
	ExpectedCgroup     string
	HeartbeatTimeout   time.Duration
	CheckInterval      time.Duration
	OperationTimeout   time.Duration
	StartupGrace       time.Duration
	TermGrace          time.Duration
	MaxClockSkew       time.Duration
}

type configJSON struct {
	Version            int    `json:"version"`
	HeartbeatPath      string `json:"heartbeatPath"`
	ExpectedUID        uint32 `json:"expectedUid"`
	ExpectedExecutable string `json:"expectedExecutable"`
	ExpectedCgroup     string `json:"expectedCgroup"`
	HeartbeatTimeout   string `json:"heartbeatTimeout"`
	CheckInterval      string `json:"checkInterval"`
	OperationTimeout   string `json:"operationTimeout"`
	StartupGrace       string `json:"startupGrace"`
	TermGrace          string `json:"termGrace"`
	MaxClockSkew       string `json:"maxClockSkew"`
}

func LoadConfig(configPath string) (Config, error) {
	if !cleanAbsolutePath(configPath) {
		return Config{}, fmt.Errorf("config path must be a clean absolute path")
	}
	payload, err := readBoundedRegularFile(context.Background(), configPath, maximumConfigBytes)
	if err != nil {
		return Config{}, err
	}
	config, err := ParseConfig(payload)
	if err != nil {
		return Config{}, err
	}
	resolvedExecutable, err := filepath.EvalSymlinks(config.ExpectedExecutable)
	if err != nil {
		return Config{}, fmt.Errorf("resolve expected executable: %w", err)
	}
	if !cleanAbsolutePath(resolvedExecutable) {
		return Config{}, fmt.Errorf("resolved expected executable is invalid")
	}
	config.ExpectedExecutable = resolvedExecutable
	return config, nil
}

func ParseConfig(payload []byte) (Config, error) {
	var input configJSON
	if err := decodeStrictJSON(payload, &input); err != nil {
		return Config{}, fmt.Errorf("invalid guardian config: %w", err)
	}
	if input.Version != configVersion {
		return Config{}, fmt.Errorf("unsupported guardian config version %d", input.Version)
	}
	heartbeatTimeout, err := parseDuration("heartbeatTimeout", input.HeartbeatTimeout, minimumTimeout, maximumTimeout)
	if err != nil {
		return Config{}, err
	}
	checkInterval, err := parseDuration("checkInterval", input.CheckInterval, minimumCheckPeriod, maximumCheckPeriod)
	if err != nil {
		return Config{}, err
	}
	operationTimeout, err := parseDuration("operationTimeout", input.OperationTimeout, minimumCheckPeriod, maximumOperationRun)
	if err != nil {
		return Config{}, err
	}
	startupGrace, err := parseDuration("startupGrace", input.StartupGrace, minimumTimeout, maximumTimeout)
	if err != nil {
		return Config{}, err
	}
	termGrace, err := parseDuration("termGrace", input.TermGrace, minimumCheckPeriod, maximumTermGrace)
	if err != nil {
		return Config{}, err
	}
	clockSkew, err := parseDuration("maxClockSkew", input.MaxClockSkew, 0, maximumClockSkew)
	if err != nil {
		return Config{}, err
	}
	config := Config{
		HeartbeatPath: input.HeartbeatPath, ExpectedUID: input.ExpectedUID,
		ExpectedExecutable: input.ExpectedExecutable, ExpectedCgroup: input.ExpectedCgroup,
		HeartbeatTimeout: heartbeatTimeout, CheckInterval: checkInterval,
		OperationTimeout: operationTimeout, StartupGrace: startupGrace,
		TermGrace: termGrace, MaxClockSkew: clockSkew,
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if !cleanAbsolutePath(c.HeartbeatPath) {
		return fmt.Errorf("heartbeatPath must be a clean absolute path")
	}
	if c.ExpectedUID == 0 {
		return fmt.Errorf("expectedUid must identify a non-root account")
	}
	if !cleanAbsolutePath(c.ExpectedExecutable) || strings.HasSuffix(c.ExpectedExecutable, " (deleted)") {
		return fmt.Errorf("expectedExecutable must be a clean, live absolute path")
	}
	if !validCgroup(c.ExpectedCgroup) {
		return fmt.Errorf("expectedCgroup must be a clean, non-root cgroup path")
	}
	if c.HeartbeatTimeout < minimumTimeout || c.HeartbeatTimeout > maximumTimeout ||
		c.CheckInterval < minimumCheckPeriod || c.CheckInterval > maximumCheckPeriod ||
		c.OperationTimeout < minimumCheckPeriod || c.OperationTimeout > maximumOperationRun ||
		c.StartupGrace < minimumTimeout || c.StartupGrace > maximumTimeout ||
		c.TermGrace < minimumCheckPeriod || c.TermGrace > maximumTermGrace ||
		c.MaxClockSkew < 0 || c.MaxClockSkew > maximumClockSkew {
		return fmt.Errorf("guardian config contains an out-of-range duration")
	}
	return nil
}

func (c Config) ValidateRuntime() error {
	if c.ExpectedUID != uint32(os.Geteuid()) {
		return fmt.Errorf("guardian UID %d does not match expected agentd UID %d", os.Geteuid(), c.ExpectedUID)
	}
	return nil
}

func parseDuration(name, value string, minimum, maximum time.Duration) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s is invalid: %w", name, err)
	}
	if duration < minimum || duration > maximum {
		return 0, fmt.Errorf("%s must be between %s and %s", name, minimum, maximum)
	}
	return duration, nil
}

func cleanAbsolutePath(value string) bool {
	return value != "" && !strings.ContainsRune(value, '\x00') && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func validCgroup(value string) bool {
	return len(value) > 1 && len(value) <= 4096 && strings.HasPrefix(value, "/") &&
		!strings.ContainsRune(value, '\x00') && path.Clean(value) == value
}
