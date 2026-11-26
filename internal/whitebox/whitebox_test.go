package whitebox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWhiteboxAnalyzeRedactsSecretsAndParsesDependencies(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module demo\n\ngo 1.24\n\nrequire (\n\tgithub.com/example/dep v1.2.3\n)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"express":"^4.19.0"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	fakeAWSKey := "AKIAIOSFODNN7EXAMPLE"
	goSrc := "package main\nfunc q(u string) string {\n\tconst key = \"" + fakeAWSKey + "\"\n\treturn \"SELECT * FROM users WHERE id=\" + u\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(goSrc), 0600); err != nil {
		t.Fatal(err)
	}

	rep, err := Analyze(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FilesScanned != 3 {
		t.Fatalf("expected 3 scanned files, got %d", rep.FilesScanned)
	}
	if len(rep.Dependencies) != 2 {
		t.Fatalf("expected 2 parsed dependencies, got %+v", rep.Dependencies)
	}
	if len(rep.Secrets) == 0 {
		t.Fatal("expected secret finding")
	}
	for _, s := range rep.Secrets {
		if strings.Contains(s.Snippet, fakeAWSKey) {
			t.Fatalf("raw secret value leaked in snippet: %q", s.Snippet)
		}
		if s.Fingerprint == "" || !strings.Contains(s.Snippet, "[REDACTED:") {
			t.Fatalf("expected redacted fingerprint in secret finding: %+v", s)
		}
	}
	if len(rep.SASTFindings) == 0 {
		t.Fatal("expected SQL concat SAST finding")
	}
}
