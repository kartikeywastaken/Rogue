package export

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"unicode"

	"rogue/internal/engine"
)

// ExportPDF writes a paginated PDF 1.4 using embedded content streams and the
// standard Courier font, keeping report export portable and dependency-free.
func ExportPDF(report engine.Report) ([]byte, error) {
	text := report.Markdown()
	text += "\n## Spending\n" + fmt.Sprintf("Input: %d tokens | Output: %d tokens | Reserved: %d tokens\n", report.Spending.InputTokens, report.Spending.OutputTokens, report.Spending.ReservedTokens)
	if report.Spending.PricingConfigured {
		text += fmt.Sprintf("Cost: $%.4f | Reserved: $%.4f\n", report.Spending.Dollars, report.Spending.ReservedDollars)
	} else {
		text += "Pricing unavailable\n"
	}
	text += "\n## Severity distribution\n"
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		count := 0
		for _, f := range report.Evidence.Findings {
			if string(f.Severity) == severity {
				count++
			}
		}
		text += fmt.Sprintf("%s: %d\n", severity, count)
	}
	text = strings.NewReplacer(" · ", " | ", "→", "->", "✓", "ok", "✗", "failed").Replace(text)
	// Base-14 fonts cannot encode arbitrary Unicode. Explicit transliteration
	// avoids invalid glyphs while JSON exports retain the original text.
	text = strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t':
			return ' '
		case r >= 32 && r <= 126:
			return r
		case unicode.IsSpace(r):
			return ' '
		case strings.ContainsRune("–—−", r):
			return '-'
		default:
			return '?'
		}
	}, text)
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		for len(line) > 88 {
			cut := strings.LastIndexByte(line[:88], ' ')
			if cut < 24 {
				cut = 88
			}
			lines = append(lines, line[:cut])
			line = strings.TrimLeft(line[cut:], " ")
		}
		lines = append(lines, line)
	}
	const pageLines = 49
	pages := max(1, (len(lines)+pageLines-1)/pageLines)
	objects := make([][]byte, 3+pages*2)
	objects[0] = []byte("<< /Type /Catalog /Pages 2 0 R >>")
	var kids []string
	for i := range pages {
		kids = append(kids, fmt.Sprintf("%d 0 R", 4+i*2))
	}
	objects[1] = fmt.Appendf(nil, "<< /Type /Pages /Count %d /Kids [%s] >>", pages, strings.Join(kids, " "))
	objects[2] = []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
	escape := strings.NewReplacer("\\", "\\\\", "(", "\\(", ")", "\\)")
	for page := range pages {
		pageID := 4 + page*2
		streamID := pageID + 1
		objects[pageID-1] = fmt.Appendf(nil, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", streamID)
		var stream bytes.Buffer
		fmt.Fprint(&stream, "0.08 0.035 0.065 rg 0 0 595 842 re f\n0.90 0.28 0.30 rg BT /F1 13 Tf 42 800 Td (ROGUE / ASSESSMENT REPORT) Tj ET\n0.93 0.88 0.88 rg BT /F1 9 Tf 42 770 Td 14 TL\n")
		for _, line := range lines[page*pageLines : min(len(lines), (page+1)*pageLines)] {
			fmt.Fprintf(&stream, "(%s) Tj T*\n", escape.Replace(line))
		}
		fmt.Fprintf(&stream, "ET\n0.60 0.50 0.56 rg BT /F1 9 Tf 42 38 Td (Page %d / %d) Tj ET\n", page+1, pages)
		var compressed bytes.Buffer
		writer := zlib.NewWriter(&compressed)
		if _, err := writer.Write(stream.Bytes()); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		objects[streamID-1] = fmt.Appendf(nil, "<< /Length %d /Filter /FlateDecode >>\nstream\n", compressed.Len())
		objects[streamID-1] = append(objects[streamID-1], compressed.Bytes()...)
		objects[streamID-1] = append(objects[streamID-1], []byte("\nendstream")...)
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n", i+1)
		out.Write(obj)
		out.WriteString("\nendobj\n")
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes(), nil
}
