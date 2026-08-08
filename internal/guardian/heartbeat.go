package guardian

import (
	"context"
	"fmt"
	"time"
)

type HeartbeatRecord struct {
	Version        int    `json:"version"`
	Status         string `json:"status"`
	PID            int    `json:"pid"`
	UID            uint32 `json:"uid"`
	Executable     string `json:"executable"`
	Cgroup         string `json:"cgroup"`
	StartTimeTicks uint64 `json:"startTimeTicks"`
	Sequence       uint64 `json:"sequence"`
	ObservedAt     string `json:"observedAt"`
	observedTime   time.Time
}

type HeartbeatSource interface {
	Read(context.Context) (HeartbeatRecord, error)
}

type FileHeartbeatSource struct {
	Path string
}

func (s FileHeartbeatSource) Read(ctx context.Context) (HeartbeatRecord, error) {
	payload, err := readBoundedRegularFile(ctx, s.Path, maximumRecordBytes)
	if err != nil {
		return HeartbeatRecord{}, err
	}
	return ParseHeartbeat(payload)
}

func ParseHeartbeat(payload []byte) (HeartbeatRecord, error) {
	var record HeartbeatRecord
	if err := decodeStrictJSON(payload, &record); err != nil {
		return HeartbeatRecord{}, fmt.Errorf("invalid heartbeat record: %w", err)
	}
	if record.Version != configVersion || record.Status != "healthy" {
		return HeartbeatRecord{}, fmt.Errorf("heartbeat has an invalid version or status")
	}
	if record.PID <= 1 || record.UID == 0 || record.StartTimeTicks == 0 || record.Sequence == 0 {
		return HeartbeatRecord{}, fmt.Errorf("heartbeat has an invalid process identity")
	}
	if !cleanAbsolutePath(record.Executable) || !validCgroup(record.Cgroup) {
		return HeartbeatRecord{}, fmt.Errorf("heartbeat has an invalid executable or cgroup")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, record.ObservedAt)
	if err != nil || record.ObservedAt != observedAt.UTC().Format(time.RFC3339Nano) {
		return HeartbeatRecord{}, fmt.Errorf("heartbeat observedAt must be canonical UTC RFC3339Nano")
	}
	record.observedTime = observedAt
	return record, nil
}

func (r HeartbeatRecord) Identity() ProcessIdentity {
	return ProcessIdentity{
		PID: r.PID, UID: r.UID, Executable: r.Executable,
		Cgroup: r.Cgroup, StartTimeTicks: r.StartTimeTicks,
	}
}

func (r HeartbeatRecord) IsFresh(now time.Time, timeout, skew time.Duration) bool {
	if r.observedTime.IsZero() {
		parsed, err := time.Parse(time.RFC3339Nano, r.ObservedAt)
		if err != nil {
			return false
		}
		r.observedTime = parsed
	}
	if r.observedTime.After(now.Add(skew)) {
		return false
	}
	return now.Sub(r.observedTime) <= timeout
}

func (r HeartbeatRecord) SameGeneration(other HeartbeatRecord) bool {
	return r.Version == other.Version && r.Status == other.Status && r.PID == other.PID &&
		r.UID == other.UID && r.Executable == other.Executable && r.Cgroup == other.Cgroup &&
		r.StartTimeTicks == other.StartTimeTicks && r.Sequence == other.Sequence && r.ObservedAt == other.ObservedAt
}
