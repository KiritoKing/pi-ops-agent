package guardian

import (
	"fmt"
	"strconv"
	"strings"
)

func parseProcUID(payload string) (uint32, error) {
	for _, line := range strings.Split(payload, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0] == "Uid:" {
			values := make([]uint64, 4)
			for index := range values {
				value, err := strconv.ParseUint(fields[index+1], 10, 32)
				if err != nil {
					return 0, fmt.Errorf("parse process UID: %w", err)
				}
				values[index] = value
			}
			if values[0] != values[1] || values[0] != values[2] || values[0] != values[3] {
				return 0, fmt.Errorf("process has differing real, effective, saved, or filesystem UIDs")
			}
			return uint32(values[0]), nil
		}
	}
	return 0, fmt.Errorf("process status has no strict Uid field")
}

func parseProcCgroup(payload string) (string, error) {
	var cgroup string
	for _, line := range strings.Split(payload, "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" || !validCgroup(parts[2]) || cgroup != "" {
			return "", fmt.Errorf("process does not have one strict cgroup v2 membership")
		}
		cgroup = parts[2]
	}
	if cgroup == "" {
		return "", fmt.Errorf("process has no cgroup v2 membership")
	}
	return cgroup, nil
}

func parseProcStartTime(payload string, expectedPID int) (uint64, error) {
	open := strings.IndexByte(payload, '(')
	close := strings.LastIndex(payload, ")")
	if open <= 0 || close <= open || close+2 >= len(payload) {
		return 0, fmt.Errorf("malformed process stat record")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(payload[:open]))
	if err != nil || pid != expectedPID {
		return 0, fmt.Errorf("process stat PID mismatch")
	}
	fields := strings.Fields(payload[close+2:])
	// The suffix starts at field 3 (state); process starttime is field 22.
	if len(fields) <= 19 {
		return 0, fmt.Errorf("process stat record is truncated")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return 0, fmt.Errorf("process stat has invalid starttime")
	}
	return startTime, nil
}
