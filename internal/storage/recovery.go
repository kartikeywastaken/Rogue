package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"rogue/internal/comms"
	"rogue/internal/mission"
)

var ErrBusy = errors.New("mission is owned by a running process")

// The OS releases this lease if a process crashes. A second process can inspect
// saved missions without mistaking another live process's work for a crash.
func (store *Store) Acquire(id string) (func(), error) {
	if !validID.MatchString(id) {
		return nil, errors.New("invalid mission lease ID")
	}
	path := filepath.Join(store.directory, ".run-"+id)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("invalid mission lease")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	var once sync.Once
	release := func() { once.Do(func() { syscall.Flock(int(file.Fd()), syscall.LOCK_UN); file.Close() }) }
	return release, nil
}

func (store *Store) Recover() (int, error) {
	missions, err := store.List()
	if err != nil {
		return 0, err
	}
	recovered := 0
	for _, saved := range missions {
		if saved.Status != mission.Active && saved.Status != mission.Paused && saved.Status != mission.Planning {
			continue
		}
		release, err := store.Acquire(saved.ID)
		if errors.Is(err, ErrBusy) {
			continue
		}
		if err != nil {
			return recovered, err
		}
		err = func() error {
			checkpoint, err := store.Load(saved.ID)
			if err != nil {
				return err
			}
			// Re-read after taking ownership: another process may have finished since List.
			status := checkpoint.Mission.Status
			if status != mission.Active && status != mission.Paused && status != mission.Planning {
				return nil
			}
			control, err := mission.Restore(checkpoint.Mission, true)
			if err != nil {
				return err
			}
			channel, err := comms.Restore(checkpoint.Comms)
			if err != nil {
				return err
			}
			if !checkpoint.Comms.Closed {
				if _, err := channel.Publish(comms.Message{From: "control", Topic: "mission.recovered", Content: control.Snapshot().Reason}); err != nil {
					return err
				}
			}
			channel.Close()
			checkpoint.Mission = control.Snapshot()
			checkpoint.Comms = channel.Snapshot()
			if err := store.Save(checkpoint); err != nil {
				return err
			}
			recovered++
			return nil
		}()
		release()
		if err != nil {
			return recovered, fmt.Errorf("recover mission %s: %w", saved.ID, err)
		}
	}
	return recovered, nil
}
