package audit

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

type Entry struct {
	AuditID      string      `json:"auditId"`
	Timestamp    string      `json:"timestamp"`
	PreviousHash string      `json:"previousHash"`
	Hash         string      `json:"hash"`
	Event        interface{} `json:"event"`
}

type hashBody struct {
	AuditID      string      `json:"auditId"`
	Timestamp    string      `json:"timestamp"`
	PreviousHash string      `json:"previousHash"`
	Event        interface{} `json:"event"`
}

type Log struct {
	mu           sync.Mutex
	path         string
	previousHash string
	now          func() time.Time
}

func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	log := &Log{path: path, previousHash: zeroHash, now: time.Now}
	if err := log.verifyExisting(); err != nil {
		return nil, err
	}
	return log, nil
}

func (l *Log) Append(event interface{}) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	auditID, err := randomID("audit")
	if err != nil {
		return "", err
	}
	body := hashBody{
		AuditID: auditID, Timestamp: l.now().UTC().Format(time.RFC3339Nano),
		PreviousHash: l.previousHash, Event: event,
	}
	hash, err := calculateHash(body)
	if err != nil {
		return "", err
	}
	entry := Entry{AuditID: body.AuditID, Timestamp: body.Timestamp, PreviousHash: body.PreviousHash, Hash: hash, Event: event}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	l.previousHash = hash
	return auditID, nil
}

func (l *Log) verifyExisting() error {
	file, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	previous := zeroHash
	line := 0
	for scanner.Scan() {
		line++
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return fmt.Errorf("audit line %d: %w", line, err)
		}
		if entry.PreviousHash != previous {
			return fmt.Errorf("audit line %d: previous hash mismatch", line)
		}
		expected, err := calculateHash(hashBody{AuditID: entry.AuditID, Timestamp: entry.Timestamp, PreviousHash: entry.PreviousHash, Event: entry.Event})
		if err != nil {
			return err
		}
		if entry.Hash != expected {
			return fmt.Errorf("audit line %d: hash mismatch", line)
		}
		previous = entry.Hash
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	l.previousHash = previous
	return nil
}

func calculateHash(body hashBody) (string, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}

func randomID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(value), nil
}
