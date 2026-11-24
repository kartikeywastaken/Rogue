package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keyEnv(p string) string { return map[string]string{"openai": "OPENAI_API_KEY", "groq": "GROQ_API_KEY"}[p] }

func TestSaveLoadRoundTripIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "credentials.json")
	f := File{}.WithKey("openai", "gpt-x", "sk-test-123456789")
	if err := Save(path, f); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file mode %o, want 600", perm)
	}
	if dir, _ := os.Stat(filepath.Dir(path)); dir.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o, want 700", dir.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil || got.Key("openai") != "sk-test-123456789" || got.Model != "gpt-x" {
		t.Fatal(got, err)
	}
	// Switching provider keeps the other key; an empty key never erases one.
	got = got.WithKey("groq", "llama", "gsk-abc").WithKey("openai", "gpt-y", "")
	if got.Key("groq") != "gsk-abc" || got.Key("openai") != "sk-test-123456789" || got.Provider != "openai" {
		t.Fatal(got)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".credentials-*"))
	if len(matches) != 0 {
		t.Fatal("temp file left behind", matches)
	}
}

func TestLoadRefusesInsecureOrMissing(t *testing.T) {
	dir := t.TempDir()
	if f, err := Load(filepath.Join(dir, "absent.json")); err != nil || f.Provider != "" {
		t.Fatal("missing file should be empty, not an error", err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte(`{"keys":{"openai":"sk"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatal("world-readable key file accepted", err)
	}
	link := filepath.Join(dir, "link.json")
	os.Chmod(path, 0o600)
	os.Symlink(path, link)
	if _, err := Load(link); err == nil {
		t.Fatal("symlinked key file accepted")
	}
	if p, err := Path(func(string) string { return "off" }); err != nil || p != "" {
		t.Fatal("off should disable", p, err)
	}
	if err := Save("", File{}); err == nil {
		t.Fatal("save with saving disabled succeeded")
	}
}

func TestEnvironmentBeatsSavedValues(t *testing.T) {
	f := File{Provider: "openai", Model: "saved-model", Keys: map[string]string{"openai": "saved-key", "groq": "saved-groq"}}
	env := map[string]string{"OPENAI_API_KEY": "env-key"}
	get := f.Getenv(func(k string) string { return env[k] }, keyEnv)
	if get("OPENAI_API_KEY") != "env-key" || get("ROGUE_PROVIDER") != "openai" || get("ROGUE_MODEL") != "saved-model" || get("GROQ_API_KEY") != "saved-groq" {
		t.Fatal("overlay precedence wrong")
	}
	// A saved model is dropped when the environment picks another provider.
	env["ROGUE_PROVIDER"] = "groq"
	if get("ROGUE_MODEL") != "" {
		t.Fatal("saved openai model leaked into a groq config")
	}
	over := Override(map[string]string{"ROGUE_MODEL": "typed", "OPENAI_API_KEY": ""}, func(k string) string { return env[k] })
	if over("ROGUE_MODEL") != "typed" || over("OPENAI_API_KEY") != "env-key" {
		t.Fatal("override precedence wrong")
	}
	if m := Mask("sk-or-v1-abcdefgh1234"); m != "sk-…1234" || strings.Contains(m, "abcdefgh") {
		t.Fatal(m)
	}
}
