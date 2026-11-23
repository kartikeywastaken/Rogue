// Package comms provides mission-scoped, ordered inter-operator messaging.
package comms

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"rogue/internal/domain"
)

var ErrBackpressure = errors.New("comms: subscriber full; message not published")

type Message struct {
	ID          string
	MissionID   string
	Sequence    uint64
	From        string
	To          []string // empty broadcasts to all registered members except the sender
	Topic       string
	Content     string
	EvidenceIDs []string
	Data        json.RawMessage
	CreatedAt   time.Time
}

type subscriber struct {
	member string
	ch     chan Message
}

// Channel retains authoritative history for a mission. Delivery is all-or-none:
// a slow subscriber causes an explicit error, never silent loss or a blocked producer.
type Channel struct {
	mu        sync.RWMutex
	missionID string
	members   map[string]bool
	subs      map[string]subscriber
	history   []Message
	closed    bool
}

func New(missionID string, members ...string) *Channel {
	c := &Channel{missionID: missionID, members: map[string]bool{}, subs: map[string]subscriber{}}
	for _, m := range members {
		if m != "" {
			c.members[m] = true
		}
	}
	return c
}

func (c *Channel) Join(member string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || member == "" {
		return errors.New("comms: closed channel or empty member")
	}
	c.members[member] = true
	return nil
}

func clone(m Message) Message {
	m.To = slices.Clone(m.To)
	m.EvidenceIDs = slices.Clone(m.EvidenceIDs)
	m.Data = slices.Clone(m.Data)
	return m
}

func addressed(m Message, member string) bool {
	return m.From != member && (len(m.To) == 0 || slices.Contains(m.To, member))
}

func (c *Channel) Publish(m Message) (Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Message{}, errors.New("comms: channel closed")
	}
	if !c.members[m.From] || m.Topic == "" {
		return Message{}, errors.New("comms: unknown sender or empty topic")
	}
	if m.MissionID != "" && m.MissionID != c.missionID {
		return Message{}, errors.New("comms: mission mismatch")
	}
	for _, recipient := range m.To {
		if !c.members[recipient] {
			return Message{}, fmt.Errorf("comms: unknown recipient %q", recipient)
		}
	}
	if len(m.Data) > 0 && !json.Valid(m.Data) {
		return Message{}, errors.New("comms: invalid JSON payload")
	}
	for _, sub := range c.subs {
		if addressed(m, sub.member) && len(sub.ch) == cap(sub.ch) {
			return Message{}, ErrBackpressure
		}
	}
	m = clone(m)
	m.ID = domain.ID()
	m.MissionID = c.missionID
	m.Sequence = uint64(len(c.history) + 1)
	m.CreatedAt = time.Now().UTC()
	c.history = append(c.history, m)
	for _, sub := range c.subs {
		if addressed(m, sub.member) {
			sub.ch <- clone(m)
		}
	}
	return clone(m), nil
}

func (c *Channel) Subscribe(member string, buffer int) (<-chan Message, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.members[member] || buffer < 1 {
		return nil, nil, errors.New("comms: invalid subscription")
	}
	id := domain.ID()
	ch := make(chan Message, buffer)
	c.subs[id] = subscriber{member: member, ch: ch}
	cancel := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if s, ok := c.subs[id]; ok {
			delete(c.subs, id)
			close(s.ch)
		}
	}
	return ch, cancel, nil
}

// History with an empty recipient is the controller's full event history.
func (c *Channel) History(recipient string) []Message {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []Message
	if recipient != "" && !c.members[recipient] {
		return out
	}
	for _, m := range c.history {
		if recipient == "" || m.From == recipient || addressed(m, recipient) {
			out = append(out, clone(m))
		}
	}
	return out
}

func (c *Channel) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for id, s := range c.subs {
		close(s.ch)
		delete(c.subs, id)
	}
}
