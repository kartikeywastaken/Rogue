// Package target keeps the observed picture of each host in a mission.
package target

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"rogue/internal/domain"
	"rogue/internal/evidence"
)

type Service struct {
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol"`
	Name       string   `json:"name"`
	Product    string   `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	CPE        []string `json:"cpe,omitempty"`
	Evidence   []string `json:"evidence"`
	Method     string   `json:"method,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
}

type Conflict struct {
	Port                                     int
	Field, Previous, Observed, ObservationID string
	Decision                                 string
	ReviewedAt                               time.Time
}

type Host struct {
	ID, MissionID, Name string
	Addresses           []string
	Services            []Service
	Findings            []string
	Observations        []string
	Conflicts           []Conflict
	UpdatedAt           time.Time
}

type Snapshot struct {
	MissionID  string
	Hosts      []Host
	References []Reference
}

// A CVE record describes a published vulnerability, not an affected host. Keep
// this catalog separate from target findings until an operator verifies a match.
type Reference struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Published   string   `json:"published"`
	Modified    string   `json:"modified"`
	Score       float64  `json:"score"`
	Severity    string   `json:"severity"`
	References  []string `json:"references"`
	Source      string   `json:"source"`
	Evidence    []string `json:"evidence,omitempty"`
}

// Environment owns its data. A caller receives copies so it cannot accidentally
// change what another operator sees while preparing a report.
type Environment struct {
	mu         sync.RWMutex
	missionID  string
	hosts      map[string]Host
	references map[string]Reference
}

func New(missionID string) *Environment {
	return &Environment{missionID: missionID, hosts: make(map[string]Host), references: make(map[string]Reference)}
}

func copyHost(host Host) Host {
	host.Addresses = slices.Clone(host.Addresses)
	host.Findings = slices.Clone(host.Findings)
	host.Observations = slices.Clone(host.Observations)
	host.Conflicts = slices.Clone(host.Conflicts)
	host.Services = slices.Clone(host.Services)
	for index := range host.Services {
		host.Services[index].CPE = slices.Clone(host.Services[index].CPE)
		host.Services[index].Evidence = slices.Clone(host.Services[index].Evidence)
	}
	return host
}

func hostName(address string) string {
	if parsed, err := url.Parse(address); err == nil && parsed.Hostname() != "" {
		address = parsed.Hostname()
	}
	return strings.TrimSuffix(strings.ToLower(strings.Trim(address, "[]")), ".")
}

func addReference(references []string, value string) []string {
	if value != "" && !slices.Contains(references, value) {
		references = append(references, value)
	}
	return references
}

// Apply accepts recorded observations rather than model prose. A failed request
// is retained in the vault, but it cannot invent a service or vulnerability here.
func (environment *Environment) Apply(observation evidence.Observation, findings []domain.Finding) error {
	if observation.MissionID != environment.missionID || observation.ID == "" {
		return errors.New("target observation has missing or cross-mission provenance")
	}
	if !observation.Success {
		return nil
	}
	if observation.Tool == "cve_lookup" {
		return environment.addReferences(observation)
	}
	if observation.Target == "" {
		return nil
	}
	name := hostName(observation.Target)
	if name == "" {
		return errors.New("target name is empty")
	}
	var result struct {
		Data struct {
			Address   string            `json:"address"`
			Records   []string          `json:"records"`
			OpenPorts []int             `json:"open_ports"`
			Services  []Service         `json:"services"`
			Headers   map[string]string `json:"headers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(observation.Output, &result); err != nil {
		return fmt.Errorf("read target observation: %w", err)
	}

	environment.mu.Lock()
	defer environment.mu.Unlock()
	host, found := environment.hosts[name]
	if found {
		host = copyHost(host)
	}
	if !found {
		digest := sha256.Sum256([]byte(environment.missionID + "/" + name))
		host = Host{ID: fmt.Sprintf("%x", digest[:8]), MissionID: environment.missionID, Name: name}
	}
	host.Observations = addReference(host.Observations, observation.ID)
	if net.ParseIP(result.Data.Address) != nil {
		host.Addresses = addReference(host.Addresses, result.Data.Address)
	}
	for _, address := range result.Data.Records {
		if net.ParseIP(address) != nil {
			host.Addresses = addReference(host.Addresses, address)
		}
	}
	services := result.Data.Services
	for _, port := range result.Data.OpenPorts {
		services = append(services, Service{Port: port, Protocol: "tcp"})
	}
	if parsed, err := url.Parse(observation.Target); err == nil && parsed.Hostname() != "" {
		port := 80
		if parsed.Scheme == "https" {
			port = 443
		}
		if parsed.Port() != "" {
			port, err = strconv.Atoi(parsed.Port())
		}
		if err != nil || port < 1 || port > 65535 {
			return errors.New("invalid observed service port")
		}
		service := Service{Port: port, Protocol: "tcp", Name: parsed.Scheme}
		for key, value := range result.Data.Headers {
			if strings.EqualFold(key, "Server") {
				service.Product = value
			}
		}
		services = append(services, service)
	}
	for _, service := range services {
		if service.Port < 1 || service.Port > 65535 || service.Protocol == "" {
			continue
		}
		index := slices.IndexFunc(host.Services, func(saved Service) bool {
			return saved.Port == service.Port && saved.Protocol == service.Protocol
		})
		if index < 0 {
			service.Evidence = []string{observation.ID}
			host.Services = append(host.Services, service)
			continue
		}
		saved := &host.Services[index]
		if service.Method != "" && (saved.Method == "" || service.Method == "probed") {
			saved.Method = service.Method
			saved.Confidence = service.Confidence
		}
		saved.Evidence = addReference(saved.Evidence, observation.ID)
		for _, field := range []struct {
			name     string
			previous *string
			observed string
		}{
			{"name", &saved.Name, service.Name}, {"product", &saved.Product, service.Product}, {"version", &saved.Version, service.Version},
		} {
			if field.observed == "" {
				continue
			}
			if *field.previous != "" && *field.previous != field.observed {
				// Keep both accounts for review instead of silently trusting the latest one.
				host.Conflicts = append(host.Conflicts, Conflict{Port: service.Port, Field: field.name, Previous: *field.previous, Observed: field.observed, ObservationID: observation.ID})
			} else {
				*field.previous = field.observed
			}
		}
		for _, cpe := range service.CPE {
			saved.CPE = addReference(saved.CPE, cpe)
		}
	}
	for _, finding := range findings {
		if finding.MissionID != environment.missionID || hostName(finding.TargetID) != name || !slices.Contains(finding.Evidence, observation.ID) {
			return errors.New("finding does not belong to the observed target")
		}
		host.Findings = addReference(host.Findings, finding.ID)
	}
	host.UpdatedAt = time.Now().UTC()
	sort.Slice(host.Services, func(left, right int) bool { return host.Services[left].Port < host.Services[right].Port })
	environment.hosts[name] = copyHost(host)
	return nil
}

func (environment *Environment) Snapshot() Snapshot {
	environment.mu.RLock()
	defer environment.mu.RUnlock()
	snapshot := Snapshot{MissionID: environment.missionID}
	for _, host := range environment.hosts {
		snapshot.Hosts = append(snapshot.Hosts, copyHost(host))
	}
	for _, reference := range environment.references {
		snapshot.References = append(snapshot.References, copyReference(reference))
	}
	sort.Slice(snapshot.References, func(left, right int) bool { return snapshot.References[left].ID < snapshot.References[right].ID })
	sort.Slice(snapshot.Hosts, func(left, right int) bool { return snapshot.Hosts[left].Name < snapshot.Hosts[right].Name })
	return snapshot
}

func Restore(snapshot Snapshot) (*Environment, error) {
	if snapshot.MissionID == "" {
		return nil, errors.New("saved target mission is missing")
	}
	environment := New(snapshot.MissionID)
	for _, host := range snapshot.Hosts {
		if host.MissionID != snapshot.MissionID || host.ID == "" || host.Name == "" {
			return nil, errors.New("invalid saved target")
		}
		if _, exists := environment.hosts[host.Name]; exists {
			return nil, errors.New("duplicate saved target")
		}
		environment.hosts[host.Name] = copyHost(host)
	}
	for _, reference := range snapshot.References {
		if reference.ID == "" || len(reference.Evidence) == 0 {
			return nil, errors.New("saved CVE reference has no provenance")
		}
		if _, exists := environment.references[reference.ID]; exists {
			return nil, errors.New("duplicate saved CVE reference")
		}
		environment.references[reference.ID] = copyReference(reference)
	}
	return environment, nil
}

func copyReference(reference Reference) Reference {
	reference.References = slices.Clone(reference.References)
	reference.Evidence = slices.Clone(reference.Evidence)
	return reference
}

func (environment *Environment) addReferences(observation evidence.Observation) error {
	var result struct {
		Data struct {
			Records []Reference `json:"records"`
		} `json:"data"`
	}
	if err := json.Unmarshal(observation.Output, &result); err != nil {
		return err
	}
	environment.mu.Lock()
	defer environment.mu.Unlock()
	for _, reference := range result.Data.Records {
		if reference.ID == "" {
			return errors.New("CVE reference is missing its identifier")
		}
		previous := environment.references[reference.ID]
		reference.Evidence = addReference(previous.Evidence, observation.ID)
		environment.references[reference.ID] = copyReference(reference)
	}
	return nil
}

// ReviewConflict records a human choice while retaining both observations.
// Accepting one version is a review decision, not proof of exploitability.
func (environment *Environment) ReviewConflict(name, observationID, field string, acceptObserved bool) error {
	environment.mu.Lock()
	defer environment.mu.Unlock()
	host, exists := environment.hosts[hostName(name)]
	if !exists {
		return errors.New("target does not exist")
	}
	host = copyHost(host)
	index := slices.IndexFunc(host.Conflicts, func(conflict Conflict) bool {
		return conflict.ObservationID == observationID && conflict.Field == field && conflict.Decision == ""
	})
	if index < 0 {
		return errors.New("unresolved target conflict does not exist")
	}
	conflict := &host.Conflicts[index]
	conflict.Decision = "keep_previous"
	if acceptObserved {
		conflict.Decision = "accept_observed"
		for serviceIndex := range host.Services {
			service := &host.Services[serviceIndex]
			if service.Port != conflict.Port {
				continue
			}
			switch conflict.Field {
			case "name":
				service.Name = conflict.Observed
			case "product":
				service.Product = conflict.Observed
			case "version":
				service.Version = conflict.Observed
			default:
				return errors.New("unknown service conflict field")
			}
		}
	}
	conflict.ReviewedAt = time.Now().UTC()
	host.UpdatedAt = conflict.ReviewedAt
	environment.hosts[host.Name] = host
	return nil
}
