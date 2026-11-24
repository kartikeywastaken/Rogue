// Package credentials persists provider API keys entered in the terminal UI so
// users do not have to export environment variables. Keys live in a single
// owner-only (0600) JSON file in the user's config directory, never in the
// project tree, and real environment variables always take precedence.
package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// PathEnv overrides the credentials file location. Set it to "off" to disable
// saved credentials entirely (useful in CI and tests).
const PathEnv = "ROGUE_CREDENTIALS_FILE"

// File is the on-disk shape. Keys are stored per provider so switching
// providers does not discard a key the user already entered.
type File struct {
	Provider string            `json:"provider,omitempty"`
	Model    string            `json:"model,omitempty"`
	Keys     map[string]string `json:"keys,omitempty"`
}

// Path returns the credentials file location, or "" when disabled.
func Path(getenv func(string) string) (string, error) {
	if p := strings.TrimSpace(getenv(PathEnv)); p != "" {
		if strings.EqualFold(p, "off") {
			return "", nil
		}
		return filepath.Abs(p)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rogue", "credentials.json"), nil
}

// Load reads the file at path. A missing file is not an error. Like ssh with
// private keys, a file readable by group or others is refused rather than used.
func Load(path string) (File, error) {
	var f File
	if path == "" {
		return f, nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if !info.Mode().IsRegular() {
		return f, fmt.Errorf("credentials file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return f, fmt.Errorf("credentials file %s is accessible by other users; run: chmod 600 %q", path, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("credentials file %s is corrupt: %w", path, err)
	}
	return f, nil
}

// Save writes f atomically with owner-only permissions: the data goes to a
// temp file in the same directory, is synced, then renamed over the target,
// so a crash never leaves a half-written key file behind.
func Save(path string, f File) error {
	if path == "" {
		return errors.New("saved credentials are disabled (" + PathEnv + "=off)")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp") // created 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Key returns the saved key for provider, if any.
func (f File) Key(provider string) string { return f.Keys[provider] }

// WithKey records provider, model, and (when non-empty) key.
func (f File) WithKey(provider, model, key string) File {
	keys := make(map[string]string, len(f.Keys)+1)
	for k, v := range f.Keys {
		keys[k] = v
	}
	if key != "" {
		keys[provider] = key
	}
	f.Provider, f.Model, f.Keys = provider, model, keys
	return f
}

// Getenv layers saved values beneath base: any variable base sets wins, and
// saved values only fill the gaps. keyEnv maps a provider to its key variable.
func (f File) Getenv(base func(string) string, keyEnv func(provider string) string) func(string) string {
	saved := map[string]string{"ROGUE_PROVIDER": f.Provider, "ROGUE_MODEL": f.Model}
	for provider, key := range f.Keys {
		if name := keyEnv(provider); name != "" {
			saved[name] = key
		}
	}
	get := Overlay(saved, base)
	return func(name string) string {
		// A saved model only makes sense with the provider it was saved for.
		if name == "ROGUE_MODEL" && !strings.EqualFold(strings.TrimSpace(get("ROGUE_PROVIDER")), f.Provider) {
			return base(name)
		}
		return get(name)
	}
}

// Overlay returns a getenv where base wins and fill only supplies variables
// base leaves empty. Use Override when the new values must win.
func Overlay(fill map[string]string, base func(string) string) func(string) string {
	return func(name string) string {
		if v := base(name); strings.TrimSpace(v) != "" {
			return v
		}
		return fill[name]
	}
}

// Override returns a getenv where non-empty values in top win over base.
func Override(top map[string]string, base func(string) string) func(string) string {
	return func(name string) string {
		if v := top[name]; strings.TrimSpace(v) != "" {
			return v
		}
		return base(name)
	}
}

// Mask shows only enough of a key to recognise it: "sk-…a1b2".
func Mask(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 8 {
		return strings.Repeat("•", len(key))
	}
	return key[:3] + "…" + key[len(key)-4:]
}
