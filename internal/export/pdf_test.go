package export

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"rogue/internal/domain"
	"rogue/internal/engine"
	"rogue/internal/evidence"
	"rogue/internal/mission"
)

func TestPDFPaginatedStreamsAndCrossReferences(t *testing.T) {
	report := engine.Report{Mission: mission.Mission{ID: "pdf-fixture", Objective: "Local assessment (fixture) \\ report", Status: mission.Completed}, Evidence: evidence.PublicSnapshot{Findings: []domain.Finding{{Title: "SQL injection", Severity: domain.SevHigh, Description: strings.Repeat("Long evidence with parentheses (quoted) and slash \\; ", 80), TargetID: "127.0.0.1", Evidence: []string{"observation-1"}, CVSS: 8.1, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", CWE: "CWE-89", CVE: []string{"CVE-2026-0001"}, Remediation: "Use parameterized queries"}}}}
	data, err := ExportPDF(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-1.4")) || !bytes.HasSuffix(data, []byte("%%EOF\n")) {
		t.Fatal("invalid PDF envelope")
	}
	xrefMatch := regexp.MustCompile(`startxref\n(\d+)`).FindSubmatch(data)
	if len(xrefMatch) != 2 {
		t.Fatal("missing xref")
	}
	offset, _ := strconv.Atoi(string(xrefMatch[1]))
	if !bytes.HasPrefix(data[offset:], []byte("xref\n")) {
		t.Fatal("xref offset is wrong")
	}
	entries := regexp.MustCompile(`(?m)^(\d{10}) 00000 n `).FindAllSubmatch(data, -1)
	for i, entry := range entries {
		pos, _ := strconv.Atoi(string(entry[1]))
		if !bytes.HasPrefix(data[pos:], fmt.Appendf(nil, "%d 0 obj\n", i+1)) {
			t.Fatalf("bad object offset %d", i+1)
		}
	}
	var content strings.Builder
	streams := regexp.MustCompile(`(?s)<< /Length (\d+) /Filter /FlateDecode >>\nstream\n`).FindAllIndex(data, -1)
	if len(streams) < 2 {
		t.Fatal("long findings were not paginated")
	}
	for _, span := range streams {
		end := bytes.Index(data[span[1]:], []byte("\nendstream"))
		reader, err := zlib.NewReader(bytes.NewReader(data[span[1] : span[1]+end]))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		content.Write(plain)
	}
	for _, want := range []string{"SQL injection", "CWE-89", "CVSS:3.1", "CVE-2026-0001", "Remediation", "Severity distribution", "Observation index", "Spending", "Limitations", "Page 2"} {
		if !strings.Contains(content.String(), want) {
			t.Errorf("PDF missing %q", want)
		}
	}
	if path := os.Getenv("ROGUE_PDF_PREVIEW"); path != "" {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
