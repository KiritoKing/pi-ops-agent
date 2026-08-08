package guardian

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseProcUIDRequiresAllUIDsToMatch(t *testing.T) {
	uid, err := parseProcUID("Name:\tagentd\nUid:\t1001\t1001\t1001\t1001\n")
	if err != nil || uid != 1001 {
		t.Fatalf("unexpected UID result uid=%d err=%v", uid, err)
	}
	if _, err := parseProcUID("Uid:\t1001\t1001\t0\t1001\n"); err == nil {
		t.Fatal("accepted process with saved root UID")
	}
}

func TestParseProcCgroupRequiresOneUnifiedMembership(t *testing.T) {
	cgroup, err := parseProcCgroup("0::/system.slice/ops-agentd.service\n")
	if err != nil || cgroup != "/system.slice/ops-agentd.service" {
		t.Fatalf("unexpected cgroup=%q err=%v", cgroup, err)
	}
	for _, payload := range []string{
		"2:cpu:/system.slice/ops-agentd.service\n",
		"0::/system.slice/ops-agentd.service\n0::/other\n",
		"0::/../other\n",
	} {
		if _, err := parseProcCgroup(payload); err == nil {
			t.Fatalf("accepted invalid cgroup payload %q", payload)
		}
	}
}

func TestParseProcStartTimeHandlesSpacesAndParentheses(t *testing.T) {
	fields := make([]string, 20)
	for index := range fields {
		fields[index] = fmt.Sprintf("%d", index+3)
	}
	fields[0] = "S"
	fields[19] = "998877"
	payload := "4321 (agentd worker (main)) " + strings.Join(fields, " ")
	startTime, err := parseProcStartTime(payload, 4321)
	if err != nil || startTime != 998877 {
		t.Fatalf("unexpected starttime=%d err=%v", startTime, err)
	}
	if _, err := parseProcStartTime(payload, 4322); err == nil {
		t.Fatal("accepted mismatched stat PID")
	}
}
