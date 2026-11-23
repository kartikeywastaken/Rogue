package comms

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestRoutingBackpressureAndOwnership(t *testing.T) {
	c := New("m", "control", "a", "b")
	a, ca, err := c.Subscribe("a", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer ca()
	b, cb, err := c.Subscribe("b", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cb()
	refs := []string{"obs"}
	if _, err := c.Publish(Message{From: "control", To: []string{"a"}, Topic: "task", EvidenceIDs: refs}); err != nil {
		t.Fatal(err)
	}
	refs[0] = "mutated"
	if _, err := c.Publish(Message{From: "control", Topic: "broadcast"}); !errors.Is(err, ErrBackpressure) {
		t.Fatal("slow consumer not reported", err)
	}
	if len(c.History("")) != 1 {
		t.Fatal("failed broadcast committed to history")
	}
	select {
	case <-b:
		t.Fatal("partial broadcast delivery")
	default:
	}
	m := <-a
	if m.EvidenceIDs[0] != "obs" {
		t.Fatal("input alias")
	}
	m.EvidenceIDs[0] = "changed"
	if c.History("a")[0].EvidenceIDs[0] != "obs" {
		t.Fatal("delivery alias")
	}
	if _, err := c.Publish(Message{From: "control", Topic: "broadcast"}); err != nil {
		t.Fatal(err)
	}
	if (<-a).Sequence != 2 || (<-b).Sequence != 2 {
		t.Fatal("message order")
	}
	if _, err := c.Publish(Message{From: "a", To: []string{"unknown"}, Topic: "bad"}); err == nil {
		t.Fatal("unknown recipient accepted")
	}
	if _, err := c.Publish(Message{From: "a", MissionID: "other", Topic: "bad"}); err == nil {
		t.Fatal("cross-mission publish")
	}
	c.Close()
	ca()
	cb()
	c.Close()
	if _, ok := <-a; ok {
		t.Fatal("subscription not closed")
	}
	if _, err := c.Publish(Message{From: "a", Topic: "late"}); err == nil {
		t.Fatal("publish after close")
	}
}
func TestConcurrentPublishHasTotalOrder(t *testing.T) {
	c := New("m", "control")
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			if _, err := c.Publish(Message{From: "control", Topic: "event", Content: fmt.Sprint(i)}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	h := c.History("")
	if len(h) != 50 {
		t.Fatal(len(h))
	}
	for i, m := range h {
		if m.Sequence != uint64(i+1) {
			t.Fatal("unordered history")
		}
	}
}
