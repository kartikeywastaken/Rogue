package tui

import (
	"fmt"
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

// The ROGUE wordmark: a Latin R followed by Greek and Cyrillic look-alikes,
// drawn in the ANSI Shadow style (solid █ strokes with a double-line shadow
// cast one cell down and right).
//
// Glyphs are block masks, one '#' per terminal column. Rows are:
// 2 accent rows, 5 cap rows, 1 descender row. The shadow is computed, never
// hand-drawn, so any new glyph gets a correct shadow for free.

var glyphs = map[rune][]string{
	'R': { // Latin R, block-for-block from ANSI Shadow
		"", "",
		"######",
		"##...##",
		"######",
		"##...##",
		"##...##",
		"",
	},
	'Θ': { // Greek theta
		"", "",
		".######",
		"##....##",
		"########",
		"##....##",
		".######",
		"",
	},
	'Ԍ': { // Cyrillic Komi sje: the only G in either alphabet
		"", "",
		".######",
		"##",
		"##...###",
		"##....##",
		".######",
		"",
	},
	'Ц': { // Cyrillic tse, tail below the line
		"", "",
		"##....##",
		"##....##",
		"##....##",
		"##....##",
		"##########",
		"........##",
	},
	'Σ': { // Greek sigma
		"", "",
		"#######",
		"###",
		".###",
		"###",
		"#######",
		"",
	},
	'Ф': { // Cyrillic ef
		"", "",
		"...##",
		".######",
		"##.##.##",
		".######",
		"...##",
		"",
	},
	'Б': { // Cyrillic be
		"", "",
		"########",
		"##",
		"#######",
		"##....##",
		"#######",
		"",
	},
	'Џ': { // Cyrillic dzhe, tail in the middle
		"", "",
		"##....##",
		"##....##",
		"##....##",
		"##....##",
		"########",
		"...##",
	},
	'Ξ': { // Greek xi
		"", "",
		"########",
		"",
		".######",
		"",
		"########",
		"",
	},
	'Ё': { // Cyrillic yo
		".##..##",
		"",
		"#######",
		"##",
		"#####",
		"##",
		"#######",
		"",
	},
}

const glyphRows = 8

// mask lays the word out as block cells, gap columns apart, trimming rows that
// no letter uses.
func mask(word string, gap int) [][]bool {
	px := make([][]bool, glyphRows)
	for i, r := range []rune(word) {
		g := glyphs[r]
		w := 0
		for _, row := range g {
			w = max(w, len(row))
		}
		for y := 0; y < glyphRows; y++ {
			if i > 0 {
				px[y] = append(px[y], make([]bool, gap)...)
			}
			row := g[y] + strings.Repeat(".", w-len(g[y]))
			for _, c := range row {
				px[y] = append(px[y], c == '#')
			}
		}
	}
	used := func(y int) bool {
		for _, on := range px[y] {
			if on {
				return true
			}
		}
		return false
	}
	for len(px) > 0 && !used(0) {
		px = px[1:]
	}
	for len(px) > 0 && !used(len(px)-1) {
		px = px[:len(px)-1]
	}
	return px
}

// shadowed renders a block mask ANSI Shadow style. Each block cell casts a
// unit outline offset one cell down and right; outlines are XORed edge by edge
// so shared edges cancel, then every uncovered cell draws the double-line
// joint matching its remaining edges. Returns block and shadow layers per row.
func shadowed(px [][]bool) (blocks, shadow []string) {
	h, w := len(px)+1, len(px[0])+1
	type pt struct{ x, y int }
	type edge struct{ a, b pt }
	edges := map[edge]bool{}
	toggle := func(a, b pt) {
		if b.x < a.x || b.y < a.y {
			a, b = b, a
		}
		e := edge{a, b}
		edges[e] = !edges[e]
	}
	for y, row := range px {
		for x, on := range row {
			if !on {
				continue
			}
			// unit loop with corners (x,y) (x+1,y) (x+1,y+1) (x,y+1)
			toggle(pt{x, y}, pt{x + 1, y})
			toggle(pt{x + 1, y}, pt{x + 1, y + 1})
			toggle(pt{x, y + 1}, pt{x + 1, y + 1})
			toggle(pt{x, y}, pt{x, y + 1})
		}
	}
	has := func(a, b pt) bool {
		if b.x < a.x || b.y < a.y {
			a, b = b, a
		}
		return edges[edge{a, b}]
	}
	joint := map[[4]bool]rune{ // up, down, left, right
		{false, false, true, true}: '═', {true, true, false, false}: '║',
		{false, true, false, true}: '╔', {false, true, true, false}: '╗',
		{true, false, false, true}: '╚', {true, false, true, false}: '╝',
		{true, false, true, true}: '╩', {false, true, true, true}: '╦',
		{true, true, false, true}: '╠', {true, true, true, false}: '╣',
		{true, true, true, true}: '╬',
		{false, false, true, false}: '═', {false, false, false, true}: '═',
		{true, false, false, false}: '║', {false, true, false, false}: '║',
	}
	for y := 0; y < h; y++ {
		var b, s strings.Builder
		for x := 0; x < w; x++ {
			if at(px, x, y) {
				b.WriteRune('█')
				s.WriteRune(' ')
				continue
			}
			p := pt{x, y}
			k := [4]bool{has(p, pt{x, y - 1}), has(p, pt{x, y + 1}), has(p, pt{x - 1, y}), has(p, pt{x + 1, y})}
			b.WriteRune(' ')
			if r, ok := joint[k]; ok {
				s.WriteRune(r)
			} else {
				s.WriteRune(' ')
			}
		}
		blocks = append(blocks, b.String())
		shadow = append(shadow, s.String())
	}
	return blocks, shadow
}

func at(px [][]bool, x, y int) bool {
	return y >= 0 && y < len(px) && x >= 0 && x < len(px[y]) && px[y][x]
}

func hexRGB(h string) (r, g, b float64) {
	var ri, gi, bi int
	fmt.Sscanf(strings.TrimPrefix(h, "#"), "%02x%02x%02x", &ri, &gi, &bi)
	return float64(ri), float64(gi), float64(bi)
}

// ramp returns n colors interpolated along the given hex stops.
func ramp(n int, stops ...string) []color.Color {
	out := make([]color.Color, n)
	for i := range out {
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		seg := t * float64(len(stops)-1)
		k := min(int(seg), len(stops)-2)
		f := seg - float64(k)
		r1, g1, b1 := hexRGB(stops[k])
		r2, g2, b2 := hexRGB(stops[k+1])
		out[i] = lipgloss.Color(fmt.Sprintf("#%02X%02X%02X",
			int(r1+(r2-r1)*f), int(g1+(g2-g1)*f), int(b1+(b2-b1)*f)))
	}
	return out
}

type wordmarkStyle struct {
	word string
	note string
}

var wordmarks = []wordmarkStyle{
	{"RΘԌЦΣ", "R latin · Θ Σ greek · Ԍ Ц cyrillic"},
	{"RФБЏΞ", "R latin · Ф Б Џ cyrillic · Ξ greek"},
	{"RΘԌЏЁ", "R latin · Θ greek · Ԍ Џ Ё cyrillic"},
}

var colShadow = lipgloss.Color("#7A1F2B")

// renderWordmark draws the word in ANSI Shadow, falling back to the real
// glyphs in the terminal's own font when it won't fit.
func renderWordmark(word string, w, h int) string {
	blocks, shadow := shadowed(mask(word, 2))
	if len([]rune(blocks[0])) > w-4 || len(blocks)+10 > h {
		return stLogo.Render(word)
	}
	cols := ramp(len(blocks), "#FF8A80", "#FF5A5F", "#C81E3A")
	sh := fg(colShadow)
	out := make([]string, len(blocks))
	for y := range blocks {
		bs, ss := []rune(blocks[y]), []rune(shadow[y])
		var b strings.Builder
		block := fg(cols[y])
		// group runs of the same layer so each row is a handful of styled spans
		for x := 0; x < len(bs); {
			isBlock := bs[x] == '█'
			j := x
			var run strings.Builder
			for j < len(bs) && (bs[j] == '█') == isBlock {
				if isBlock {
					run.WriteRune('█')
				} else {
					run.WriteRune(ss[j])
				}
				j++
			}
			if isBlock {
				b.WriteString(block.Render(run.String()))
			} else {
				b.WriteString(sh.Render(run.String()))
			}
			x = j
		}
		out[y] = b.String()
	}
	return strings.Join(out, "\n")
}
