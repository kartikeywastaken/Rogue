package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
)

const anthropicVersion = "2026-10-21"

// Limits on an untrusted catalog response.
const (
	maxCatalogBytes = 16 << 20 // OpenRouter's full catalog is a few MiB
	maxModelIDLen   = 200
	maxModels       = 5000
)

// catalogEntry covers the shapes providers use. Capability fields are optional:
// OpenRouter reports supported_parameters, Mistral reports capabilities.
type catalogEntry struct {
	ID                  string   `json:"id"`
	SupportedParameters []string `json:"supported_parameters"`
	Capabilities        *struct {
		FunctionCalling *bool `json:"function_calling"`
	} `json:"capabilities"`
}

// toolsKnownUnsupported reports whether the provider explicitly says this model
// cannot call tools. Unknown capability is not a reason to hide a model.
func (e catalogEntry) toolsKnownUnsupported() bool {
	if e.SupportedParameters != nil && !slices.Contains(e.SupportedParameters, "tools") {
		return true
	}
	return e.Capabilities != nil && e.Capabilities.FunctionCalling != nil && !*e.Capabilities.FunctionCalling
}

// ListModels fetches the provider's model catalog (GET {base}/models). It is
// free (no tokens), but the response is untrusted input: size, count and ID
// contents are bounded, and IDs containing control characters are dropped so a
// hostile endpoint cannot inject terminal escape sequences into the UI.
func ListModels(ctx context.Context, config Config, client *http.Client) ([]string, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	endpoint := strings.TrimRight(config.BaseURL, "/") + "/models"
	if config.Provider == "anthropic" {
		endpoint += "?limit=1000"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if config.APIKey != "" {
		if config.Provider == "anthropic" {
			req.Header.Set("x-api-key", config.APIKey)
			req.Header.Set("anthropic-version", anthropicVersion)
		} else {
			req.Header.Set("Authorization", "Bearer "+config.APIKey)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s models request: %w", config.Provider, redactErr(err, config.APIKey))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		message := strings.TrimSpace(redact(string(b), config.APIKey))
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			message = "the provider rejected this API key"
		case http.StatusNotFound:
			message = "this endpoint has no model catalog"
		}
		return nil, &HTTPError{Provider: config.Provider, Status: resp.StatusCode, Message: printable(message, 200)}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCatalogBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s models: %w", config.Provider, err)
	}
	if len(data) > maxCatalogBytes {
		return nil, errors.New("model catalog is too large")
	}
	entries, err := parseCatalog(data)
	if err != nil {
		return nil, fmt.Errorf("%s models: %w", config.Provider, err)
	}
	return catalogIDs(config.Provider, entries), nil
}

// parseCatalog accepts {"data":[...]} (OpenAI style) or a bare array (Together).
func parseCatalog(data []byte) ([]catalogEntry, error) {
	var wrapped struct {
		Data []catalogEntry `json:"data"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Data != nil {
		return wrapped.Data, nil
	}
	var bare []catalogEntry
	if err := json.Unmarshal(data, &bare); err != nil {
		return nil, errors.New("unrecognised model catalog format")
	}
	return bare, nil
}

func catalogIDs(provider string, entries []catalogEntry) []string {
	seen := map[string]bool{}
	var ids []string
	for _, e := range entries {
		id := strings.TrimSpace(e.ID)
		if provider == "gemini" {
			id = strings.TrimPrefix(id, "models/") // catalog says models/x, chat wants x
		}
		if id == "" || len(id) > maxModelIDLen || !safeID(id) || seen[id] || e.toolsKnownUnsupported() {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
		if len(ids) == maxModels {
			break
		}
	}
	slices.Sort(ids)
	return ids
}

func safeID(id string) bool {
	for _, r := range id {
		if unicode.IsControl(r) || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// printable strips control characters from untrusted text and bounds it.
func printable(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit]) + "…" // cut on rune boundaries, never mid-UTF-8
	}
	return s
}

func redact(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "[redacted]")
}

func redactErr(err error, key string) error {
	if key == "" || !strings.Contains(err.Error(), key) {
		return err
	}
	return errors.New(redact(err.Error(), key))
}
