package arsenal

// multidomain.go — Pure-Go multi-domain analysis tools (Phase 3):
//   - binary_triage: ELF / PE / Mach-O inspection via stdlib debug/* + entropy
//   - crypto_analyze: multi-encoding decoder, single-byte XOR crib analysis, JWT alg=none check
//   - solidity_audit: static smart-contract vulnerability pattern scanner

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// RegisterMultiDomainTools adds pure-Go binary triage, crypto analysis, and
// Solidity auditing tools to the registry.
func RegisterMultiDomainTools(registry *Registry) {
	registry.Register(&Tool{
		Name:        "binary_triage",
		Category:    "util",
		Description: "Static binary triage for ELF, PE, and Mach-O files: architecture, sections, Shannon entropy, imports, security mitigations (NX/PIE/RELRO/canary), and printable indicator strings.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "absolute path to a local binary file (up to 64 MiB)"},
		}, "required": []string{"path"}},
		Execute: executeBinaryTriage,
	})

	registry.Register(&Tool{
		Name:        "crypto_analyze",
		Category:    "util",
		Description: "Analyze encoded or obfuscated text locally: detects and decodes hex, Base64/Base64URL, URL encoding, ROT13, printable single-byte XOR candidates, and unverified JWT header flags.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"data": map[string]any{"type": "string", "description": "encoded string, ciphertext hex, or token to analyze (max 64 KiB)"},
		}, "required": []string{"data"}},
		Execute: executeCryptoAnalyze,
	})

	registry.Register(&Tool{
		Name:        "solidity_audit",
		Category:    "util",
		Description: "Static regex audit of Solidity source for common vulnerability patterns (reentrancy, tx.origin, delegatecall, unchecked calls, selfdestruct). Operates on a local file or inline source. Analysis only.",
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string", "description": "path to .sol file"},
			"code": map[string]any{"type": "string", "description": "inline Solidity source"},
		}},
		Execute: executeSolidityAudit,
	})
}

// ── Binary triage ─────────────────────────────────────────────────────────────

const maxBinaryInspectBytes = 64 * 1024 * 1024

func regularFileCheck(fp string, maxSize int64) (string, os.FileInfo, error) {
	if fp == "" {
		return "", nil, errors.New("path is required")
	}
	if strings.HasPrefix(fp, "-") {
		return "", nil, errors.New("path must not begin with '-'")
	}
	clean := filepath.Clean(fp)
	info, err := os.Stat(clean)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, errors.New("path must reference a regular file")
	}
	if maxSize > 0 && info.Size() > maxSize {
		return "", nil, fmt.Errorf("file size %d exceeds limit %d", info.Size(), maxSize)
	}
	return clean, info, nil
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return math.Round(entropy*1000) / 1000
}

type sectionInfo struct {
	Name    string  `json:"name"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy"`
}

func executeBinaryTriage(ctx context.Context, raw json.RawMessage) (*Result, error) {
	var a struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	clean, info, err := regularFileCheck(a.Path, maxBinaryInspectBytes)
	if err != nil {
		return fail(fmt.Errorf("binary_triage: %w", err))
	}
	f, err := os.Open(clean)
	if err != nil {
		return fail(err)
	}
	defer f.Close()

	sample := make([]byte, min(int(info.Size()), 2*1024*1024))
	n, _ := io.ReadFull(f, sample)
	sample = sample[:n]
	_, _ = f.Seek(0, io.SeekStart)

	out := map[string]any{
		"path":            clean,
		"size_bytes":      info.Size(),
		"overall_entropy": shannonEntropy(sample),
		"packed_hint":     shannonEntropy(sample) > 7.2,
	}

	if ef, err := elf.NewFile(f); err == nil {
		defer ef.Close()
		out["format"] = "ELF"
		out["arch"] = ef.Machine.String()
		out["type"] = ef.Type.String()
		out["entry"] = fmt.Sprintf("0x%x", ef.Entry)
		var sections []sectionInfo
		nx, relro, pie, canary := true, false, ef.Type == elf.ET_DYN, false
		for _, p := range ef.Progs {
			if p.Type == elf.PT_GNU_STACK && (p.Flags&elf.PF_X) != 0 {
				nx = false
			}
			if p.Type == elf.PT_GNU_RELRO {
				relro = true
			}
		}
		for _, s := range ef.Sections {
			if len(sections) < 32 {
				b, _ := s.Data()
				if len(b) > 512*1024 {
					b = b[:512*1024]
				}
				sections = append(sections, sectionInfo{Name: s.Name, Size: s.Size, Entropy: shannonEntropy(b)})
			}
		}
		libs, _ := ef.ImportedLibraries()
		syms, _ := ef.ImportedSymbols()
		var impNames []string
		for _, sym := range syms {
			if sym.Name == "__stack_chk_fail" {
				canary = true
			}
			if len(impNames) < 50 {
				impNames = append(impNames, sym.Name)
			}
		}
		out["sections"] = sections
		out["libraries"] = libs
		out["imported_symbols_sample"] = impNames
		out["mitigations"] = map[string]bool{"nx": nx, "pie": pie, "relro": relro, "stack_canary": canary}
		out["interesting_strings"] = extractInterestingStrings(sample, 25)
		return &Result{
			Success: true,
			Summary: fmt.Sprintf("ELF %s (%s): %d sections, %d libs, entropy %.2f", ef.Machine, ef.Type, len(ef.Sections), len(libs), out["overall_entropy"]),
			Data:    out,
		}, nil
	}

	_, _ = f.Seek(0, io.SeekStart)
	if pf, err := pe.NewFile(f); err == nil {
		defer pf.Close()
		out["format"] = "PE"
		out["machine"] = fmt.Sprintf("0x%x", pf.Machine)
		var sections []sectionInfo
		for _, s := range pf.Sections {
			if len(sections) < 32 {
				b, _ := s.Data()
				if len(b) > 512*1024 {
					b = b[:512*1024]
				}
				sections = append(sections, sectionInfo{Name: s.Name, Size: uint64(s.Size), Entropy: shannonEntropy(b)})
			}
		}
		libs, _ := pf.ImportedLibraries()
		out["sections"] = sections
		out["libraries"] = libs
		out["interesting_strings"] = extractInterestingStrings(sample, 25)
		return &Result{
			Success: true,
			Summary: fmt.Sprintf("PE binary: %d sections, %d imported DLLs, entropy %.2f", len(pf.Sections), len(libs), out["overall_entropy"]),
			Data:    out,
		}, nil
	}

	_, _ = f.Seek(0, io.SeekStart)
	if mf, err := macho.NewFile(f); err == nil {
		defer mf.Close()
		out["format"] = "Mach-O"
		out["cpu"] = mf.Cpu.String()
		out["type"] = mf.Type.String()
		var sections []sectionInfo
		for _, s := range mf.Sections {
			if len(sections) < 32 {
				b, _ := s.Data()
				if len(b) > 512*1024 {
					b = b[:512*1024]
				}
				sections = append(sections, sectionInfo{Name: s.Seg + "." + s.Name, Size: s.Size, Entropy: shannonEntropy(b)})
			}
		}
		libs, _ := mf.ImportedLibraries()
		out["sections"] = sections
		out["libraries"] = libs
		out["interesting_strings"] = extractInterestingStrings(sample, 25)
		return &Result{
			Success: true,
			Summary: fmt.Sprintf("Mach-O %s: %d sections, %d dylibs, entropy %.2f", mf.Cpu, len(mf.Sections), len(libs), out["overall_entropy"]),
			Data:    out,
		}, nil
	}

	out["format"] = "Unknown/Data"
	out["interesting_strings"] = extractInterestingStrings(sample, 25)
	return &Result{
		Success: true,
		Summary: fmt.Sprintf("Non-ELF/PE/Mach-O file (%d bytes), entropy %.2f", info.Size(), out["overall_entropy"]),
		Data:    out,
	}, nil
}

func extractInterestingStrings(data []byte, limit int) []string {
	var results []string
	seen := make(map[string]bool)
	var cur []byte
	flush := func() {
		if len(cur) >= 6 {
			s := string(cur)
			lower := strings.ToLower(s)
			if strings.Contains(s, "://") || strings.Contains(s, "/") || strings.Contains(lower, "flag") ||
				strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "key") ||
				strings.Contains(s, "%s") {
				if len(s) > 120 {
					s = s[:120]
				}
				if !seen[s] && len(results) < limit {
					seen[s] = true
					results = append(results, s)
				}
			}
		}
		cur = cur[:0]
	}
	for _, b := range data {
		if b >= 32 && b < 127 {
			cur = append(cur, b)
		} else {
			flush()
		}
	}
	flush()
	return results
}

// ── Crypto analyze ────────────────────────────────────────────────────────────

func executeCryptoAnalyze(ctx context.Context, raw json.RawMessage) (*Result, error) {
	var a struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	if len(a.Data) == 0 || len(a.Data) > 65536 {
		return fail(errors.New("crypto_analyze: data must be 1–65536 bytes"))
	}
	trimmed := strings.TrimSpace(a.Data)
	findings := map[string]any{
		"input_bytes": len(a.Data),
		"entropy":     shannonEntropy([]byte(a.Data)),
	}

	// Hex
	if rawHex, err := hex.DecodeString(trimmed); err == nil && len(rawHex) > 0 {
		findings["hex_decoded"] = printablePreview(rawHex, 256)
		if xorHits := topSingleByteXOR(rawHex); len(xorHits) > 0 {
			findings["xor_candidates"] = xorHits
		}
	}
	// Base64 / Base64URL
	for _, item := range []struct {
		name string
		enc  *base64.Encoding
	}{
		{"base64", base64.StdEncoding},
		{"base64_raw", base64.RawStdEncoding},
		{"base64url", base64.RawURLEncoding},
	} {
		if dec, err := item.enc.DecodeString(trimmed); err == nil && len(dec) > 0 {
			findings[item.name+"_decoded"] = printablePreview(dec, 256)
		}
	}
	// URL decode
	if u, err := url.QueryUnescape(trimmed); err == nil && u != trimmed {
		findings["url_decoded"] = truncatePreview(u, 256)
	}
	// ROT13
	findings["rot13"] = truncatePreview(rot13(trimmed), 256)

	// JWT inspection (unverified)
	if parts := strings.Split(trimmed, "."); len(parts) == 3 {
		if hb, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
			var hdr map[string]any
			if json.Unmarshal(hb, &hdr) == nil {
				findings["jwt_header"] = hdr
				if alg, _ := hdr["alg"].(string); strings.EqualFold(alg, "none") {
					findings["jwt_warning"] = "JWT specifies alg=none"
				}
			}
		}
	}

	return &Result{
		Success: true,
		Summary: fmt.Sprintf("Crypto/encoding analysis completed (%d bytes input)", len(a.Data)),
		Data:    findings,
	}, nil
}

func printablePreview(b []byte, maxLen int) string {
	var clean bytes.Buffer
	for i, ch := range b {
		if i >= maxLen {
			break
		}
		if ch >= 32 && ch < 127 {
			clean.WriteByte(ch)
		} else {
			clean.WriteByte('.')
		}
	}
	return clean.String()
}

func truncatePreview(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func rot13(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune('a' + (r-'a'+13)%26)
		case r >= 'A' && r <= 'Z':
			b.WriteRune('A' + (r-'A'+13)%26)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

type xorCandidate struct {
	Key     string `json:"key_hex"`
	Score   int    `json:"printable_score"`
	Preview string `json:"preview"`
}

func topSingleByteXOR(cipher []byte) []xorCandidate {
	if len(cipher) > 1024 {
		cipher = cipher[:1024]
	}
	var cands []xorCandidate
	for k := 1; k < 256; k++ {
		score := 0
		decoded := make([]byte, len(cipher))
		for i, b := range cipher {
			ch := b ^ byte(k)
			decoded[i] = ch
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == ' ' || ch == '{' || ch == '}' || ch == '_' {
				score++
			}
		}
		if len(cipher) > 0 && score*100/len(cipher) >= 85 {
			cands = append(cands, xorCandidate{
				Key:     fmt.Sprintf("0x%02x", k),
				Score:   score * 100 / len(cipher),
				Preview: printablePreview(decoded, 128),
			})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].Score > cands[j].Score })
	if len(cands) > 3 {
		cands = cands[:3]
	}
	return cands
}

// ── Solidity audit ────────────────────────────────────────────────────────────

type solidityFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	Line     int    `json:"line"`
	Snippet  string `json:"snippet"`
}

var solidityRules = []struct {
	name     string
	severity string
	pattern  *regexp.Regexp
	detail   string
}{
	{"reentrancy", "high", regexp.MustCompile(`(?i)\.call\s*\{`), "Potential reentrancy: external call with value/gas"},
	{"tx_origin_auth", "high", regexp.MustCompile(`\btx\.origin\b`), "tx.origin used for authentication — use msg.sender instead"},
	{"delegatecall", "high", regexp.MustCompile(`\.delegatecall\s*\(`), "delegatecall with target contract — verify storage layout & access control"},
	{"selfdestruct", "high", regexp.MustCompile(`\bselfdestruct\b|\bsuicide\b`), "selfdestruct present — verify access control and deprecation risks"},
	{"unchecked_call", "medium", regexp.MustCompile(`\.call\s*\(`), "Low-level .call() — return value must be checked"},
	{"block_timestamp", "low", regexp.MustCompile(`\bblock\.timestamp\b`), "block.timestamp dependence: miners/validators can influence slightly"},
	{"assembly", "medium", regexp.MustCompile(`\bassembly\b\s*\{`), "Inline Yul/assembly — requires manual safety audit"},
	{"hardcoded_addr", "info", regexp.MustCompile(`0x[0-9a-fA-F]{40}`), "Hardcoded Ethereum address — verify deployment target"},
	{"overflow_check", "low", regexp.MustCompile(`\bunchecked\b\s*\{`), "unchecked block disables arithmetic overflow protection"},
}

func executeSolidityAudit(ctx context.Context, raw json.RawMessage) (*Result, error) {
	var a struct {
		Path string `json:"path"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	var src string
	switch {
	case a.Path != "":
		clean, _, err := regularFileCheck(a.Path, 2*1024*1024)
		if err != nil {
			return fail(fmt.Errorf("solidity_audit: %w", err))
		}
		b, err := os.ReadFile(clean)
		if err != nil {
			return fail(err)
		}
		src = string(b)
	case a.Code != "":
		if len(a.Code) > 512*1024 {
			return fail(errors.New("solidity_audit: inline code exceeds 512 KiB"))
		}
		src = a.Code
	default:
		return fail(errors.New("solidity_audit: provide path or code"))
	}

	lines := strings.Split(src, "\n")
	var findings []solidityFinding
	for _, rule := range solidityRules {
		for i, line := range lines {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if rule.pattern.MatchString(line) {
				snippet := strings.TrimFunc(line, unicode.IsSpace)
				if len(snippet) > 120 {
					snippet = snippet[:120] + "..."
				}
				findings = append(findings, solidityFinding{
					Rule:     rule.name,
					Severity: rule.severity,
					Detail:   rule.detail,
					Line:     i + 1,
					Snippet:  snippet,
				})
			}
		}
	}
	return &Result{
		Success: true,
		Summary: fmt.Sprintf("Solidity static analysis completed: %d pattern matches", len(findings)),
		Data: map[string]any{
			"total_findings": len(findings),
			"findings":       findings,
			"note":           "Static pattern analysis only — does not confirm exploitability. Manual review required.",
		},
	}, nil
}
