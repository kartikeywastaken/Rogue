// Package storage saves authenticated, encrypted mission checkpoints.
package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"rogue/internal/comms"
	"rogue/internal/evidence"
	"rogue/internal/llm"
	"rogue/internal/mission"
	"rogue/internal/operator"
	"rogue/internal/opsec"
	"rogue/internal/target"
)

const maxCheckpointBytes = 32 * 1024 * 1024

var validID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}$`)

type Checkpoint struct {
	Version   int
	UpdatedAt time.Time
	Mission   mission.Mission
	Evidence  evidence.Snapshot
	Comms     comms.Snapshot
	Targets   target.Snapshot
	Spending  llm.Spending
	Operators []operator.Agent
	OPSEC     opsec.Snapshot
}

type Store struct {
	mu         sync.Mutex
	directory  string
	encryption cipher.AEAD
}

func Open(directory string) (*Store, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("state directory must be a real directory")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, err
	}
	store := &Store{directory: directory}
	err = store.locked(func() error {
		path := filepath.Join(directory, "state.key")
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return err
			}
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, writeError := file.Write(key)
			syncError := file.Sync()
			closeError := file.Close()
			if err := errors.Join(writeError, syncError, closeError); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("state.key must be a private regular file (mode 0600)")
		}
		key, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(key) != 32 {
			return errors.New("invalid state encryption key")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		store.encryption, err = cipher.NewGCM(block)
		return err
	})
	return store, err
}

// A process lock protects saves and pruning across multiple Rogue processes.
func (store *Store) locked(action func() error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	path := filepath.Join(store.directory, ".lock")
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("invalid state lock file")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return action()
}

func (store *Store) Save(checkpoint Checkpoint) error {
	if !validID.MatchString(checkpoint.Mission.ID) {
		return errors.New("invalid mission ID for checkpoint")
	}
	checkpoint.Version = 1
	checkpoint.UpdatedAt = time.Now().UTC()
	if err := validate(checkpoint); err != nil {
		return err
	}
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	if len(data) > maxCheckpointBytes {
		return errors.New("mission checkpoint exceeds storage limit")
	}
	return store.locked(func() error {
		nonce := make([]byte, store.encryption.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		// The mission ID is authenticated too: renaming a file cannot change its owner.
		sealed := store.encryption.Seal(nil, nonce, data, []byte(checkpoint.Mission.ID))
		payload := append(append([]byte("RG01"), nonce...), sealed...)
		file, err := os.CreateTemp(store.directory, ".checkpoint-*")
		if err != nil {
			return err
		}
		name := file.Name()
		defer os.Remove(name)
		if err := file.Chmod(0600); err != nil {
			file.Close()
			return err
		}
		if _, err := file.Write(payload); err != nil {
			file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(name, filepath.Join(store.directory, checkpoint.Mission.ID+".state")); err != nil {
			return err
		}
		directory, err := os.Open(store.directory)
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	})
}

func (store *Store) load(id string) (Checkpoint, error) {
	var checkpoint Checkpoint
	if !validID.MatchString(id) {
		return checkpoint, errors.New("invalid mission ID")
	}
	path := filepath.Join(store.directory, id+".state")
	info, err := os.Lstat(path)
	if err != nil {
		return checkpoint, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxCheckpointBytes+1024 {
		return checkpoint, errors.New("invalid or oversized checkpoint file")
	}
	file, err := os.Open(path)
	if err != nil {
		return checkpoint, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maxCheckpointBytes+1025))
	if err != nil {
		return checkpoint, err
	}
	nonceSize := store.encryption.NonceSize()
	if len(payload) < 4+nonceSize || string(payload[:4]) != "RG01" {
		return checkpoint, errors.New("unknown checkpoint format")
	}
	data, err := store.encryption.Open(nil, payload[4:4+nonceSize], payload[4+nonceSize:], []byte(id))
	if err != nil {
		return checkpoint, errors.New("checkpoint authentication failed")
	}
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return checkpoint, err
	}
	if checkpoint.Mission.ID != id {
		return checkpoint, errors.New("checkpoint mission mismatch")
	}
	return checkpoint, validate(checkpoint)
}

func (store *Store) Load(id string) (Checkpoint, error) {
	var checkpoint Checkpoint
	err := store.locked(func() error { var err error; checkpoint, err = store.load(id); return err })
	return checkpoint, err
}

func validate(checkpoint Checkpoint) error {
	id := checkpoint.Mission.ID
	if checkpoint.Version != 1 || checkpoint.Evidence.MissionID != id || checkpoint.Comms.MissionID != id || checkpoint.Targets.MissionID != id {
		return errors.New("checkpoint version or mission boundaries are invalid")
	}
	if _, err := mission.Restore(checkpoint.Mission, false); err != nil {
		return err
	}
	if _, err := evidence.Restore(checkpoint.Evidence); err != nil {
		return err
	}
	if _, err := comms.Restore(checkpoint.Comms); err != nil {
		return err
	}
	if _, err := target.Restore(checkpoint.Targets); err != nil {
		return err
	}
	tasks := make(map[string]mission.Task)
	for _, task := range checkpoint.Mission.Tasks {
		tasks[task.ID] = task
	}
	observations := make(map[string]bool)
	for _, observation := range checkpoint.Evidence.Observations {
		owner, exists := tasks[observation.TaskID]
		if !exists || owner.OperatorID != observation.OperatorID {
			return errors.New("observation references an unknown task")
		}
		observations[observation.ID] = true
	}
	for _, message := range checkpoint.Comms.History {
		for _, reference := range message.EvidenceIDs {
			if !observations[reference] {
				return errors.New("message references unknown evidence")
			}
		}
	}
	for _, host := range checkpoint.Targets.Hosts {
		for _, reference := range host.Observations {
			if !observations[reference] {
				return errors.New("target references unknown evidence")
			}
		}
	}
	for _, reference := range checkpoint.Targets.References {
		for _, id := range reference.Evidence {
			if !observations[id] {
				return errors.New("CVE reference points to unknown evidence")
			}
		}
	}
	return nil
}

func (store *Store) List() ([]mission.Mission, error) {
	missions := make([]mission.Mission, 0)
	err := store.locked(func() error {
		entries, err := os.ReadDir(store.directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".state") {
				continue
			}
			checkpoint, err := store.load(strings.TrimSuffix(entry.Name(), ".state"))
			if err != nil {
				return fmt.Errorf("load %s: %w", entry.Name(), err)
			}
			missions = append(missions, checkpoint.Mission)
		}
		return nil
	})
	sort.Slice(missions, func(left, right int) bool { return missions[left].CreatedAt.After(missions[right].CreatedAt) })
	return missions, err
}

// Only terminal missions are eligible for retention cleanup. An active mission
// must never disappear merely because a long scan crosses the retention window.
func (store *Store) Prune(age time.Duration, keep int) (int, error) {
	if age <= 0 || keep < 1 {
		return 0, errors.New("retention age and count must be positive")
	}
	removed := 0
	err := store.locked(func() error {
		entries, err := os.ReadDir(store.directory)
		if err != nil {
			return err
		}
		var records []Checkpoint
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".state") {
				continue
			}
			checkpoint, err := store.load(strings.TrimSuffix(entry.Name(), ".state"))
			if err != nil {
				return err
			}
			status := checkpoint.Mission.Status
			if status == mission.Completed || status == mission.Failed || status == mission.Aborted {
				records = append(records, checkpoint)
			}
		}
		sort.Slice(records, func(left, right int) bool { return records[left].UpdatedAt.After(records[right].UpdatedAt) })
		for index, record := range records {
			if index < keep && time.Since(record.UpdatedAt) < age {
				continue
			}
			if err := os.Remove(filepath.Join(store.directory, record.Mission.ID+".state")); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}
