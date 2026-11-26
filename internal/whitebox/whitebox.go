// Package whitebox provides read-only static source analysis and dependency
// decomposition for white-box security assessments. It never executes target code
// and redacts detected secret values with SHA-256 fingerprints.
package whitebox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxWhiteboxFileBytes = 2 * 1024 * 1024 // 2 MiB per source file

// SASTFinding is a single static-analysis finding.
type SASTFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	CWE      string `json:"cwe,omitempty"`
	Snippet  string `json:"snippet"`
}

// SecretFinding records a credential or private key pattern detected in source.
// Raw values are withheld and replaced by an 8-byte SHA-256 hex fingerprint.
type SecretFinding struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint"`
	Snippet     string `json:"snippet"`
}

// Dependency records one declared package parsed from a manifest file.
type Dependency struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	File      string `json:"file"`
}

// Report is the full output of a white-box repository analysis run.
type Report struct {
	RepoPath       string          `json:"repo_path"`
	FilesScanned   int             `json:"files_scanned"`
	LanguageCounts map[string]int  `json:"language_counts"`
	Secrets        []SecretFinding `json:"secrets"`
	SASTFindings   []SASTFinding   `json:"sast_findings"`
	Dependencies   []Dependency    `json:"dependencies"`
	Error          string          `json:"error,omitempty"`
}

var secretPatterns = []struct {
	kind    string
	pattern *regexp.Regexp
}{
	{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github_classic", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{"github_fine_grained", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{50,255}\b`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{35}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,255}\b`)},
	{"stripe_secret", regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{20,255}\b`)},
	{"openai_key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,255}\b`)},
	{"jwt_token", regexp.MustCompile(`\beyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\b`)},
	{"database_uri", regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@[^\s"']+`)},
	{"private_key_header", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)},
	{"assigned_secret", regexp.MustCompile(`(?i)(?:aws_secret_access_key|api_secret|client_secret|secret_key|password|passwd)["' ]*[:=]["' ][A-Za-z0-9/+_=.-]{8,255}["']`)},
}

var sastRules = []struct {
	rule     string
	severity string
	cwe      string
	pattern  *regexp.Regexp
}{
	{"sql_string_concat", "high", "CWE-89", regexp.MustCompile(`(?i)(select|insert|update|delete)\s+.*\+\s*("|'|\w)`)},
	{"eval_exec", "high", "CWE-95", regexp.MustCompile(`\beval\s*\(|\bexec\s*\(|\bsystem\s*\(`)},
	{"command_injection", "high", "CWE-78", regexp.MustCompile(`exec\.Command\s*\(.*\+|os\.system\s*\(|subprocess\.(run|Popen|call).*shell\s*=\s*True`)},
	{"tls_insecure_skip", "medium", "CWE-295", regexp.MustCompile(`InsecureSkipVerify\s*:\s*true|verify\s*=\s*False`)},
	{"hardcoded_credential", "medium", "CWE-798", regexp.MustCompile(`(?i)(password|passwd|secret|api_key)\s*[:=]\s*["'][^"']{8,}["']`)},
	{"md5_sha1_insecure", "low", "CWE-328", regexp.MustCompile(`(?i)(md5\.New|sha1\.New|hashlib\.(md5|sha1)|createHash\(['"](md5|sha1)['"]\))`)},
	{"open_redirect", "medium", "CWE-601", regexp.MustCompile(`(?i)http\.Redirect.*r\.(URL\.Query|FormValue)`)},
	{"path_traversal", "medium", "CWE-22", regexp.MustCompile(`filepath\.(Join|Clean)\s*\(.*r\.(FormValue|URL\.Query)`)},
	{"yaml_untrusted_load", "high", "CWE-502", regexp.MustCompile(`yaml\.load\s*\([^)]*\)|pickle\.loads\s*\(`)},
	{"innerhtml_sink", "medium", "CWE-79", regexp.MustCompile(`\.innerHTML\s*=|dangerouslySetInnerHTML`)},
}

var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, ".idea": true, ".vscode": true, ".rogue": true,
}

var textExtensions = map[string]string{
	".go": "go", ".py": "python", ".js": "javascript", ".ts": "typescript",
	".tsx": "typescript", ".jsx": "javascript", ".java": "java", ".rb": "ruby",
	".php": "php", ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".h": "c",
	".rs": "rust", ".sh": "shell", ".bash": "shell", ".yaml": "yaml", ".yml": "yaml",
	".json": "json", ".env": "env", ".toml": "toml", ".ini": "ini",
	".cfg": "config", ".conf": "config", ".xml": "xml", ".tf": "terraform",
	".hcl": "hcl", ".sql": "sql", ".kt": "kotlin", ".sol": "solidity", ".mod": "gomod",
}

// Analyze walks repoPath and produces dependency inventory, redacted secrets,
// and SAST findings. Read-only and bounded per file.
func Analyze(ctx context.Context, repoPath string) (Report, error) {
	report := Report{
		RepoPath:       repoPath,
		LanguageCounts: make(map[string]int),
	}

	cleanRoot := filepath.Clean(repoPath)
	info, err := os.Stat(cleanRoot)
	if err != nil {
		return report, fmt.Errorf("whitebox: cannot access repo path: %w", err)
	}
	if !info.IsDir() {
		return report, fmt.Errorf("whitebox: repo_path must be a directory")
	}

	err = filepath.WalkDir(cleanRoot, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		finfo, serr := d.Info()
		if serr != nil || !finfo.Mode().IsRegular() || finfo.Size() > maxWhiteboxFileBytes {
			return nil
		}
		base := d.Name()
		ext := strings.ToLower(filepath.Ext(base))
		lang, isText := textExtensions[ext]
		if !isText && base != "Dockerfile" && base != "Makefile" && base != "requirements.txt" && base != "Gemfile" {
			return nil
		}
		if lang == "" {
			lang = strings.ToLower(base)
		}

		contentBytes, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(cleanRoot, path)
		if err != nil {
			rel = path
		}
		content := string(contentBytes)
		report.FilesScanned++
		report.LanguageCounts[lang]++
		scanFile(rel, content, &report)
		parseManifestDependencies(rel, base, content, &report)
		return nil
	})
	if err != nil && err != ctx.Err() {
		report.Error = err.Error()
	}
	return report, nil
}

func scanFile(relPath, content string, report *Report) {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lineNo := i + 1
		for _, sp := range secretPatterns {
			locs := sp.pattern.FindAllStringIndex(line, 4)
			for _, loc := range locs {
				rawMatch := line[loc[0]:loc[1]]
				digest := sha256.Sum256([]byte(rawMatch))
				fp := hex.EncodeToString(digest[:8])
				redactedLine := line[:loc[0]] + "[REDACTED:" + fp + "]" + line[loc[1]:]
				report.Secrets = append(report.Secrets, SecretFinding{
					File:        relPath,
					Line:        lineNo,
					Kind:        sp.kind,
					Fingerprint: fp,
					Snippet:     truncate(strings.TrimSpace(redactedLine), 180),
				})
			}
		}

		snippet := truncate(strings.TrimSpace(line), 180)
		for _, sr := range sastRules {
			if sr.pattern.MatchString(line) {
				report.SASTFindings = append(report.SASTFindings, SASTFinding{
					File:     relPath,
					Line:     lineNo,
					Rule:     sr.rule,
					Severity: sr.severity,
					CWE:      sr.cwe,
					Snippet:  snippet,
				})
			}
		}
	}
}

func parseManifestDependencies(relPath, base, content string, report *Report) {
	switch base {
	case "go.mod":
		inRequire := false
		for _, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.HasPrefix(trimmed, "require (") {
				inRequire = true
				continue
			}
			if inRequire && trimmed == ")" {
				inRequire = false
				continue
			}
			if strings.HasPrefix(trimmed, "require ") {
				trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "require "))
			} else if !inRequire {
				continue
			}
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				report.Dependencies = append(report.Dependencies, Dependency{
					Ecosystem: "go", Name: fields[0], Version: fields[1], File: relPath,
				})
			}
		}
	case "package.json":
		var pkg struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal([]byte(content), &pkg) == nil {
			for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
				names := make([]string, 0, len(m))
				for n := range m {
					names = append(names, n)
				}
				sort.Strings(names)
				for _, n := range names {
					report.Dependencies = append(report.Dependencies, Dependency{
						Ecosystem: "npm", Name: n, Version: m[n], File: relPath,
					})
				}
			}
		}
	case "requirements.txt":
		for _, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
				continue
			}
			name, ver := trimmed, "*"
			for _, sep := range []string{"==", ">=", "<=", "~=", "!="} {
				if idx := strings.Index(trimmed, sep); idx > 0 {
					name = strings.TrimSpace(trimmed[:idx])
					ver = strings.TrimSpace(trimmed[idx:])
					break
				}
			}
			report.Dependencies = append(report.Dependencies, Dependency{
				Ecosystem: "pypi", Name: name, Version: ver, File: relPath,
			})
		}
	case "Cargo.toml":
		inDeps := false
		for _, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") {
				inDeps = trimmed == "[dependencies]" || trimmed == "[dev-dependencies]"
				continue
			}
			if !inDeps || trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if k, v, ok := strings.Cut(trimmed, "="); ok {
				report.Dependencies = append(report.Dependencies, Dependency{
					Ecosystem: "cargo",
					Name:      strings.TrimSpace(k),
					Version:   strings.Trim(strings.TrimSpace(v), `"`),
					File:      relPath,
				})
			}
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
