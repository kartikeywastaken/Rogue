package evidence

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"rogue/internal/domain"
)

func observation() Observation {
	return Observation{MissionID: "m", TaskID: "t", OperatorID: "op", ToolCallID: domain.ID(), Tool: "header_analysis", Target: "http://localhost", Input: json.RawMessage(`{"url":"http://localhost"}`), Output: json.RawMessage(`{"success":true}`), Success: true}
}
func TestFindingProvenanceDedupAndCopies(t *testing.T) {
	v := New("m")
	input := observation()
	o, err := v.Record(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Input[0] = 'x'
	o.Output[0] = 'x'
	f := domain.Finding{MissionID: "m", Title: "Missing CSP", Severity: domain.SevInfo, TargetID: "http://localhost", OperatorID: "op", Evidence: []string{"invented"}}
	if _, err := v.AddFinding(f); err == nil {
		t.Fatal("accepted invented evidence")
	}
	f.Evidence = []string{o.ID}
	stored, err := v.AddFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	f.Evidence[0] = "mutated"
	stored.Evidence[0] = "mutated"
	f.Evidence = []string{o.ID}
	f.Title = "  MISSING   CSP "
	if _, err := v.AddFinding(f); err != nil {
		t.Fatal(err)
	}
	if len(v.Findings()) != 1 || v.Findings()[0].Evidence[0] != o.ID {
		t.Fatal("dedup or aliasing failure")
	}
	if !json.Valid(v.Observations()[0].Input) || !json.Valid(v.Observations()[0].Output) {
		t.Fatal("observation aliases caller")
	}
	bad := observation()
	bad.MissionID = "other"
	if _, err := v.Record(bad); err == nil {
		t.Fatal("accepted cross-mission observation")
	}
	failed := observation()
	failed.Success = false
	no, err := v.Record(failed)
	if err != nil {
		t.Fatal(err)
	}
	f.Evidence = []string{no.ID}
	if _, err := v.AddFinding(f); err == nil {
		t.Fatal("failed execution backs a finding")
	}
}
func TestCredentialsAreRedacted(t *testing.T) {
	v := New("m")
	got, err := v.AddCredential(domain.Credential{MissionID: "m", Type: "token", Value: "do-not-export"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "" || !got.SecretCaptured {
		t.Fatal("secret leaked from insertion")
	}
	data, _ := json.Marshal(v.Credentials())
	if strings.Contains(string(data), "do-not-export") {
		t.Fatal("secret leaked to export")
	}
}
func TestConcurrentRecords(t *testing.T) {
	v := New("m")
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if _, err := v.Record(observation()); err != nil {
				t.Error(err)
			}
			_ = v.Observations()
		})
	}
	wg.Wait()
	if len(v.Observations()) != 50 {
		t.Fatal("lost observations")
	}
}
