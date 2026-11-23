package arsenal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"rogue/internal/target"
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type CVE = target.Reference

type CVEClient struct {
	Client      *http.Client
	APIKey      string
	BaseURL     string
	mu          sync.Mutex
	nextRequest time.Time
	cache       map[string]cveCache
}

type cveCache struct {
	records []CVE
	expires time.Time
}

func (client *CVEClient) wait(ctx context.Context) error {
	client.mu.Lock()
	delay := time.Until(client.nextRequest)
	if delay < 0 {
		delay = 0
	}
	interval := 6 * time.Second
	if client.APIKey != "" {
		interval = 600 * time.Millisecond
	}
	client.nextRequest = time.Now().Add(delay + interval)
	client.mu.Unlock()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (client *CVEClient) Lookup(ctx context.Context, id, keyword string) ([]CVE, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	keyword = strings.TrimSpace(keyword)
	if (id == "") == (keyword == "") {
		return nil, errors.New("provide exactly one of cve_id or keyword")
	}
	if id != "" && !cvePattern.MatchString(id) {
		return nil, errors.New("invalid CVE identifier")
	}
	if keyword != "" && (len(keyword) < 3 || len(keyword) > 160) {
		return nil, errors.New("CVE keyword must contain 3 to 160 characters")
	}
	key := id + "/" + keyword
	client.mu.Lock()
	cached, exists := client.cache[key]
	client.mu.Unlock()
	if exists && time.Now().Before(cached.expires) {
		return copyCVEs(cached.records), nil
	}
	base := client.BaseURL
	if base == "" {
		base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	endpoint, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	values := endpoint.Query()
	values.Set("resultsPerPage", "5")
	if id != "" {
		values.Set("cveId", id)
	} else {
		values.Set("keywordSearch", keyword)
	}
	endpoint.RawQuery = values.Encode()
	if err := client.wait(ctx); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "ROGUE/1.0 CVE reference lookup")
	if client.APIKey != "" {
		request.Header.Set("apiKey", client.APIKey)
	}
	transport := client.Client
	if transport == nil {
		transport = &http.Client{Timeout: 20 * time.Second}
	}
	// The intelligence endpoint is fixed; never forward its API key on redirects.
	copyClient := *transport
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD lookup returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 2*1024*1024 {
		return nil, errors.New("NVD response exceeded capture limit")
	}
	records, err := parseCVEs(data)
	if err != nil {
		return nil, err
	}
	client.mu.Lock()
	if client.cache == nil || len(client.cache) >= 128 {
		client.cache = make(map[string]cveCache)
	}
	client.cache[key] = cveCache{records: copyCVEs(records), expires: time.Now().Add(time.Hour)}
	client.mu.Unlock()
	return records, nil
}

func copyCVEs(records []CVE) []CVE {
	result := append([]CVE(nil), records...)
	for index := range result {
		result[index].References = append([]string(nil), result[index].References...)
	}
	return result
}

func parseCVEs(data []byte) ([]CVE, error) {
	var response struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Status       string `json:"vulnStatus"`
				Published    string `json:"published"`
				Modified     string `json:"lastModified"`
				Descriptions []struct {
					Language string `json:"lang"`
					Value    string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					Data struct {
						Score    float64 `json:"baseScore"`
						Severity string  `json:"baseSeverity"`
					} `json:"cvssData"`
					Severity string `json:"baseSeverity"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("invalid NVD response: %w", err)
	}
	if response.Vulnerabilities == nil {
		return nil, errors.New("NVD response is missing its vulnerability list")
	}
	var records []CVE
	for _, item := range response.Vulnerabilities {
		data := item.CVE
		if !cvePattern.MatchString(data.ID) {
			return nil, errors.New("NVD response contains an invalid CVE identifier")
		}
		record := CVE{ID: data.ID, Status: data.Status, Published: data.Published, Modified: data.Modified, Source: "NVD"}
		for _, description := range data.Descriptions {
			if description.Language == "en" {
				record.Description = description.Value
				break
			}
		}
		for _, version := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if metrics := data.Metrics[version]; len(metrics) > 0 {
				record.Score = metrics[0].Data.Score
				record.Severity = metrics[0].Data.Severity
				if record.Severity == "" {
					record.Severity = metrics[0].Severity
				}
				break
			}
		}
		for _, reference := range data.References {
			if len(record.References) < 5 {
				record.References = append(record.References, reference.URL)
			}
		}
		records = append(records, record)
	}
	return records, nil
}

func RegisterCVETool(registry *Registry, client *CVEClient) {
	if client == nil {
		client = &CVEClient{}
	}
	registry.Register(&Tool{
		Name: "cve_lookup", Category: "recon",
		Description: "Look up public NVD CVE records by CVE ID or product keyword. Matches are vulnerability candidates, not proof that any assessed target is affected. This contacts NVD, not the assessment target.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"cve_id":  map[string]any{"type": "string", "description": "Exact identifier, such as CVE-2021-44228"},
			"keyword": map[string]any{"type": "string", "description": "Product/version search phrase; use only when cve_id is omitted"},
		}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var arguments struct {
				ID      string `json:"cve_id"`
				Keyword string `json:"keyword"`
			}
			if err := json.Unmarshal(raw, &arguments); err != nil {
				return nil, err
			}
			records, err := client.Lookup(ctx, arguments.ID, arguments.Keyword)
			if err != nil {
				return nil, err
			}
			return &Result{Success: true, Data: map[string]any{"records": records, "assessment": "reference information only; target applicability is unverified"}, Summary: fmt.Sprintf("NVD returned %d candidate records", len(records))}, nil
		},
	})
}
