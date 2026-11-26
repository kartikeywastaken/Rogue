package opsec

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestProfilesAndRoEPresets(t *testing.T) {
	defer SetProfile("loud") // restore default

	if !SetProfile("silent") {
		t.Fatal("failed to activate silent profile")
	}
	if got := ActiveProfileSnapshot(); got.Name != "silent" || !got.BlendTraffic || got.PauseAfter != 2 {
		t.Fatalf("unexpected silent snapshot: %+v", got)
	}
	if !SetRoE("strict") {
		t.Fatal("failed to activate strict RoE")
	}
	roe := ActiveRoESnapshot()
	if roe.Name != "strict" || !roe.RequireApproval || roe.Mode != "default" {
		t.Fatalf("unexpected strict RoE: %+v", roe)
	}
	if SetProfile("nonexistent") {
		t.Fatal("accepted unknown OPSEC profile")
	}

	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
	ApplyBlendHeaders(req)
	if req.Header.Get("User-Agent") == "" || req.Header.Get("User-Agent") == "ROGUE-Research/1.0" {
		t.Fatalf("expected blended browser User-Agent, got %q", req.Header.Get("User-Agent"))
	}
}

func TestJitterRespectsCancellationAndConcurrency(t *testing.T) {
	defer SetProfile("loud")
	SetProfile("silent")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := Sleep(ctx); err == nil {
		t.Fatal("expected deadline error from Sleep under 2-8s silent jitter")
	}

	SetProfile("loud")
	if d := JitterDelay(context.Background()); d != 0 {
		t.Fatalf("expected zero jitter in loud mode, got %v", d)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				SetProfile("covert")
			} else {
				SetProfile("loud")
			}
			_ = RandomUserAgent()
			_ = ActiveProfileSnapshot()
		}(i)
	}
	wg.Wait()
}
