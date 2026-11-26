// Package whitebox provides static source analysis for white-box assessments.
// It walks a local repository tree, scans for secrets, and applies SAST
// patterns for common vulnerability classes. It never executes code.
package whitebox

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SASTFinding is a single static-analysis result.
type SASTFinding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Snippet string `json:"snippet"`
}

// SecretFinding is a credential or key detected in source.
type SecretFinding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Kind    string `json:"kind"`
	Snippet string `json:"snippet"`
}

// Report is the full output of a white-box analysis run.
type Report struct {
	RepoPath     string        `json:"repo_path"`
	FilesScanned int           `json:"files_scanned"`
	Secrets      []SecretFinding `json:"secrets"`
	SASTFindings []SASTFinding `json:"sast_findings"`
	Error        string        `json:"error,omitempty"`
}

// secretPatterns are compiled once at package init.
var secretPatterns = []struct {
	kind    string
	pattern *regexp.Regexp
}{
	{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"aws_secret_key", regexp.MustCompile(`(?i)(aws_secret|aws_key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}`)},
	{"generic_api_key", regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[:=]\s*["']?[A-Za-z0-9\-_]{20,}`)},
	{"generic_secret", regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']`)},
	{"private_key_header", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{"github_token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}`)},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}`)},
	{"stripe_key", regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`)},
	{"jwt_token", regexp.MustCompile(`eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*`)},
}

// sastRules are static analysis patterns.
var sastRules = []struct {
	rule    string
	pattern *regexp.Regexp
}{
	{"sql_string_concat", regexp.MustCompile(`(?i)(select|insert|update|delete|from|where)\s+.*\+\s*("|'|\w)`)},
	{"eval_exec", regexp.MustCompile(`\beval\s*\(|\bexec\s*\(|\bsystem\s*\(`)},
	{"hardcoded_credential", regexp.MustCompile(`(?i)(password|passwd|secret|api_key)\s*=\s*"[^"]{6,}"`)},
	{"md5_insecure", regexp.MustCompile(`(?i)(md5|sha1)\s*\(`)},
	{"tls_insecure_skip", regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`)},
	{"command_injection", regexp.MustCompile(`exec\.Command\s*\(.*\+`)},
	{"open_redirect", regexp.MustCompile(`(?i)http\.Redirect.*r\.URL\.(Query|FormValue)`)},
	{"path_traversal", regexp.MustCompile(`filepath\.(Join|Clean)\s*\(.*r\.(FormValue|URL\.Query)`)},
	{"deserialise_yaml", regexp.MustCompile(`yaml\.Unmarshal\s*\(`)},
	{"fmt_sscanf_user_input", regexp.MustCompile(`fmt\.Sscanf\s*\(`)},
}

// skipDirs are directories we skip entirely during the walk.
var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, ".idea": true, ".vscode": true,
}

// textExtensions are file extensions treated as text for scanning.
var textExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".java": true, ".rb": true,
	".php": true, ".cs": true, ".c": true, ".cpp": true, ".h": true, ".rs": true,
	".sh": true, ".bash": true, ".yaml": true, ".yml": true, ".json": true,
	".env": true, ".toml": true, ".ini": true, ".cfg": true, ".conf": true,
	".xml": true, ".tf": true, ".hcl": true, ".sql": true, ".kt": true,
}

// Analyze walks repoPath and returns a Report of secrets and SAST findings.
// It is read-only and safe to run against any local directory.
func Analyze(ctx context.Context, repoPath string) (Report, error) {
	report := Report{RepoPath: repoPath}

	info, err := os.Stat(repoPath)
	if err != nil {
		return report, fmt.Errorf("whitebox: cannot access repo path: %w", err)
	}
	if !info.IsDir() {
		return report, fmt.Errorf("whitebox: repo_path must be a directory")
	}

	err = filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil // skip unreadable
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
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !textExtensions[ext] {
			return nil
		}
		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil
		}
		// Keep rel path for readability
		rel, _ := filepath.Rel(repoPath, path)
		scanFile(rel, string(content), &report)
		report.FilesScanned++
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
		snippet := truncate(strings.TrimSpace(line), 200)

		// Secret scan
		for _, sp := range secretPatterns {
			if sp.pattern.MatchString(line) {
				report.Secrets = append(report.Secrets, SecretFinding{
					File:    relPath,
					Line:    lineNo,
					Kind:    sp.kind,
					Snippet: snippet,
				})
			}
		}

		// SAST scan
		for _, sr := range sastRules {
			if sr.pattern.MatchString(line) {
				report.SASTFindings = append(report.SASTFindings, SASTFinding{
					File:    relPath,
					Line:    lineNo,
					Rule:    sr.rule,
					Snippet: snippet,
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
