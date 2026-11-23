package comms

import (
	"errors"
	"sort"
)

type Snapshot struct {
	MissionID string
	Members   []string
	History   []Message
	Closed    bool
}

func (channel *Channel) Snapshot() Snapshot {
	channel.mu.RLock()
	defer channel.mu.RUnlock()
	snapshot := Snapshot{MissionID: channel.missionID, Closed: channel.closed}
	for member := range channel.members {
		snapshot.Members = append(snapshot.Members, member)
	}
	sort.Strings(snapshot.Members)
	for _, message := range channel.history {
		snapshot.History = append(snapshot.History, clone(message))
	}
	return snapshot
}
func Restore(snapshot Snapshot) (*Channel, error) {
	if snapshot.MissionID == "" {
		return nil, errors.New("comms: saved mission missing")
	}
	channel := New(snapshot.MissionID, snapshot.Members...)
	ids := map[string]bool{}
	for index, message := range snapshot.History {
		if message.ID == "" || ids[message.ID] || message.MissionID != snapshot.MissionID || message.Sequence != uint64(index+1) {
			return nil, errors.New("comms: invalid saved message sequence")
		}
		if _, err := channel.Publish(message); err != nil {
			return nil, err
		}
		channel.history[index] = clone(message)
		ids[message.ID] = true
	}
	if snapshot.Closed {
		channel.Close()
	}
	return channel, nil
}
