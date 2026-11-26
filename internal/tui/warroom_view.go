package tui

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"rogue/internal/arsenal"
	"rogue/internal/domain"
	"rogue/internal/target"
)

var warTabs = []string{"Ops", "Operators", "Targets", "Vault", "Arsenal", "OPSEC & Bench"}
var killPhases = []string{"recon", "weaponize", "deliver", "exploit", "install", "c2", "actions"}

func panelBox(title, body string, w, h int) string {
	if w < 4 || h < 3 {
		return fitArea(body, w, h)
	}
	inside := fitArea(stLogo.Render(title)+"\n"+body, w-4, h-2)
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colBorderDim).Padding(0, 1).Render(inside)
}

func fitArea(s string, w, h int) string {
	if w <= 0 || h <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	for len(lines) < h {
		lines = append(lines, "")
	}
	for i, line := range lines {
		line = ansi.Truncate(line, w, "…")
		lines[i] = line + strings.Repeat(" ", max(0, w-lipgloss.Width(line)))
	}
	return strings.Join(lines, "\n")
}

func selectedRow(text string, selected bool, w int) string {
	text = ansi.Truncate(text, max(1, w-2), "…")
	if selected {
		return lipgloss.NewStyle().Foreground(colLogo).Background(colSelected).Bold(true).Width(w).Render("› " + text)
	}
	return "  " + text
}

func (m Model) viewWarRoom() string {
	if m.picker {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.renderList())
	}
	if m.war.modal != "" {
		return m.viewWarModal()
	}
	w, h := max(1, m.width-4), m.height
	if h < 10 || w < 32 {
		return fitArea(stLogo.Render("◆ ROGUE · WAR ROOM")+"\n"+stMuted.Render("Increase terminal size to inspect")+"\n"+stDim.Render("esc session · ctrl+w toggle"), m.width, m.height)
	}
	s := m.war.snapshot
	id, status, phase := s.MissionID, string(s.Status), string(s.Phase)
	if id == "" {
		id = "no mission"
		status = "idle"
		phase = "—"
	}
	profile := s.OPSECProfile
	if profile == "" {
		profile = m.war.profile
	}
	if profile == "" {
		profile = "covert"
	}
	line1 := stLogo.Render("◆ ROGUE  /  WAR ROOM") + stMuted.Render("   "+id+" · "+status+" · "+phase+" · "+m.mode.String())
	if w < 100 {
		line1 = stLogo.Render("◆ WAR ROOM") + stMuted.Render("  "+id+" · "+status+" · "+phase+" · "+m.mode.String())
	}
	tokens := s.Spending.InputTokens + s.Spending.OutputTokens
	limit, costLimit := 0, 0.0
	if svc := m.services(); svc != nil {
		limit, costLimit = svc.TokenLimit, svc.CostLimit
	}
	if s.TokenLimit > 0 {
		limit = s.TokenLimit
	}
	if s.CostLimit > 0 {
		costLimit = s.CostLimit
	}
	budget := fmt.Sprintf("%d tokens", tokens)
	if limit > 0 {
		budget += fmt.Sprintf(" / %d", limit)
	}
	cost := "pricing unavailable"
	if s.Spending.PricingConfigured {
		cost = fmt.Sprintf("$%.4f", s.Spending.Dollars)
		if costLimit > 0 {
			cost += fmt.Sprintf(" / $%.2f", costLimit)
		}
	}
	line2 := stMuted.Render(fmt.Sprintf("%s · detections %d %s · %s · %s", profile, s.Detections, meter(s.Detections, s.OPSEC.Policy.AbortAfter, 6), budget, cost))
	if w < 116 {
		tokenText := fmt.Sprintf("tok %d", tokens)
		if limit > 0 {
			tokenText += fmt.Sprintf("/%d", limit)
		}
		costText := "$ unpriced"
		if s.Spending.PricingConfigured {
			costText = fmt.Sprintf("$%.4f", s.Spending.Dollars)
			if costLimit > 0 {
				costText += fmt.Sprintf("/$%.2f", costLimit)
			}
		}
		line2 = stMuted.Render(fmt.Sprintf("%s · det %d %s · %s · %s", profile, s.Detections, meter(s.Detections, s.OPSEC.Policy.AbortAfter, 4), tokenText, costText))
	}
	var tabs []string
	for i, t := range warTabs {
		label := fmt.Sprintf("%d %s", i+1, t)
		if m.width < 80 {
			label = fmt.Sprintf("%d %s", i+1, strings.Fields(t)[0])
		}
		style := stDim
		if i == m.war.tab {
			style = stLogo
		}
		tabs = append(tabs, style.Render(label))
	}
	tabLine := strings.Join(tabs, "  ")
	if lipgloss.Width(tabLine) > w {
		tabLine = stLogo.Render(fmt.Sprintf("[%d/6] %s", m.war.tab+1, warTabs[m.war.tab])) + stDim.Render(" · tab next")
	}
	footer := m.warHint()
	if m.war.err != "" {
		footer = stRed.Render(safeText(m.war.err))
	} else if m.flash != "" {
		footer = stPrompt.Render(safeText(m.flash))
	} else if m.war.busy {
		footer = stYellow.Render("working · x cancel")
	}
	contentH := max(3, h-6)
	var content string
	if m.width >= 120 {
		leftW := m.warInputWidth()
		rightW := max(1, w-leftW-1)
		input := m.inputBox()
		inputH := lipgloss.Height(input)
		feedH := max(1, contentH-inputH-4)
		ops := m.killChain(leftW-4) + "\n" + m.warFeed(leftW-4, feedH)
		left := panelBox("LIVE OPS", ops, leftW, max(3, contentH-inputH)) + "\n" + fitArea(input, leftW, inputH)
		content = lipgloss.JoinHorizontal(lipgloss.Top, fitArea(left, leftW, contentH), " ", panelBox(warTabs[m.war.tab], m.warPanel(rightW-4, contentH-3), rightW, contentH))
	} else {
		inputH := 0
		input := ""
		if m.war.composing {
			input = m.inputBox()
			inputH = lipgloss.Height(input) + 1
		}
		content = panelBox(warTabs[m.war.tab], m.warPanel(w-4, contentH-inputH-3), w, max(3, contentH-inputH))
		if inputH > 0 {
			content += "\n" + input
		}
	}
	rows := []string{fitArea(line1, w, 1), fitArea(line2, w, 1), fitArea(tabLine, w, 1), fitArea(content, w, contentH), fitArea(footer, w, 1), fitArea(stDim.Render("ctrl+w / esc session · 1–6 tabs · i message · space pause/resume"), w, 1)}
	body := strings.Join(rows, "\n")
	lines := strings.Split(body, "\n")
	for i := range lines {
		lines[i] = "  " + lines[i]
	}
	return strings.Join(lines, "\n")
}

func meter(value, limit, width int) string {
	if limit <= 0 {
		return strings.Repeat("▱", width)
	}
	filled := min(width, max(0, value*width/limit))
	return strings.Repeat("▰", filled) + strings.Repeat("▱", width-filled)
}

func (m Model) killChain(w int) string {
	var items []string
	for _, p := range killPhases {
		style := stDim
		marker := ""
		if p == string(m.war.snapshot.Phase) {
			style = stLogo
			marker = "● "
		} else if slices.Contains(m.war.snapshot.Phases, domain.KillChainPhase(p)) {
			style = stGreen
		}
		items = append(items, style.Render(marker+strings.ToUpper(p)))
	}
	line := strings.Join(items, stDim.Render(" › "))
	if lipgloss.Width(line) > w { // two rows preserve all seven stages in split panes
		return strings.Join(items[:4], " › ") + "\n" + strings.Join(items[4:], " › ")
	}
	return line
}

func (m Model) warFeed(w, h int) string {
	var rows []string
	messages := m.war.snapshot.Messages
	for _, msg := range messages[max(0, len(messages)-100):] {
		rows = append(rows, stDim.Render(msg.CreatedAt.Format("15:04:05")+" ")+stPrompt.Render(msg.From+" ")+stMuted.Render(safeText(msg.Content)))
	}
	// The current transcript carries streamed prose and tool status immediately,
	// while inspector messages provide the durable operator-tagged audit feed.
	start := max(0, len(m.entries)-100)
	for _, e := range m.entries[start:] {
		text := e.text
		style := stText
		switch e.kind {
		case entTool:
			text = e.tool.Name + " " + e.tool.Input + " · " + e.tool.Output
			if e.running {
				text += " running…"
			}
			style = stCyan
		case entNotice:
			style = stMuted
		case entError:
			style = stRed
		case entUser:
			style = stPrompt
		}
		for _, line := range strings.Split(ansi.Wrap(safeText(text), max(1, w-9), ""), "\n") {
			rows = append(rows, stDim.Render(e.at.Format("15:04:05")+" ")+style.Render(line))
		}
	}
	if len(rows) == 0 {
		return stDim.Render("No activity yet · i to enter a mission")
	}
	if len(rows) > h {
		rows = rows[len(rows)-h:]
	}
	return strings.Join(rows, "\n")
}

func (m Model) warPanel(w, h int) string {
	if m.war.loading && !m.war.haveSnapshot && len(m.war.catalog) == 0 {
		return stDim.Render("Loading mission inspector…")
	}
	switch m.war.tab {
	case 0:
		rows := m.opsRows(w)
		feedH := max(1, (h-5)/2)
		return m.killChain(w) + "\n" + m.warFeed(w, feedH) + "\n" + stDim.Render("TOOL INSPECTOR · enter details") + "\n" + windowRows(rows, m.war.rows[0], max(1, h-feedH-5))
	case 1:
		return m.operatorsPanel(w, h)
	case 2:
		rows := m.targetRows()
		return m.drawRows(rows, m.war.rows[2], w, h, "No observed targets yet")
	case 3:
		findings := m.filteredFindings()
		var rows []string
		for _, f := range findings {
			rows = append(rows, severityStyle(string(f.Severity)).Render(fmt.Sprintf("%-8s %4.1f  %s", f.Severity, f.CVSS, safeText(f.Title))))
		}
		filter := m.war.severity
		if filter == "" {
			filter = "all"
		}
		return stMuted.Render(fmt.Sprintf("%d findings · %s", len(findings), filter)) + "\n" + m.drawRows(rows, m.war.rows[3], w, h-1, "No findings match this severity")
	case 4:
		var rows []string
		for _, t := range m.filteredCatalog() {
			badge := stGreen.Render("[ok]")
			if t.Availability != "available" {
				badge = stDim.Render("[missing]")
			}
			lab := ""
			if t.LabOnly {
				lab = stYellow.Render(" lab_only")
			}
			rows = append(rows, badge+" "+stText.Render(t.Name)+lab)
		}
		filter := m.war.filter
		if m.war.filtering {
			filter += "▍"
		}
		return stMuted.Render(fmt.Sprintf("%d tools · / filter %s", len(rows), safeText(filter))) + "\n" + m.drawRows(rows, m.war.rows[4], w, max(1, h-4), "No matching tools") + "\n" + m.toolDescription(w)
	case 5:
		return m.opsecPanel(w, h)
	}
	return ""
}

func windowRows(rows []string, selected, h int) string {
	if len(rows) == 0 {
		return ""
	}
	selected = min(max(0, selected), len(rows)-1)
	start := max(0, min(selected-h/2, len(rows)-h))
	return strings.Join(rows[start:min(len(rows), start+max(1, h))], "\n")
}

func (m Model) drawRows(rows []string, selected, w, h int, empty string) string {
	if len(rows) == 0 {
		return stDim.Render(empty)
	}
	selected = min(max(0, selected), len(rows)-1)
	for i, row := range rows {
		rows[i] = selectedRow(row, i == selected, w)
	}
	return windowRows(rows, selected, h)
}

func (m Model) toolEntries() []entry {
	var out []entry
	for _, e := range m.entries {
		if e.kind == entTool {
			out = append(out, e)
		}
	}
	return out
}

func (m Model) opsRows(w int) []string {
	var rows []string
	for i, e := range m.toolEntries() {
		status := "✓"
		if e.running {
			status = "…"
		} else if !e.tool.OK {
			status = "✗"
		}
		rows = append(rows, selectedRow(stCyan.Render(status+" "+safeText(e.tool.Name))+stDim.Render(" "+safeText(e.tool.Input)), i == m.war.rows[0], w))
	}
	if len(rows) == 0 {
		return []string{stDim.Render("No tool calls · i to enter a mission")}
	}
	return rows
}

func (m Model) operatorsPanel(w, h int) string {
	ops := m.war.snapshot.Operators
	if len(ops) == 0 {
		return stDim.Render("No operators assigned · start a mission")
	}
	selected := min(m.war.rows[1], len(ops)-1)
	var rows []string
	for _, o := range ops {
		rows = append(rows, fmt.Sprintf("%-10s %-9s %d/%d %s", o.Profile.Callsign, o.State, o.Completed, o.Failed, meter(int(o.Risk*100), 100, 5)))
	}
	o := ops[selected]
	task := "No current task"
	for _, t := range m.war.snapshot.Tasks {
		if t.ID == o.TaskID || t.OperatorID == o.ID {
			task = t.Title + " · " + string(t.Status)
		}
	}
	drawer := stDim.Render(strings.Repeat("─", max(1, w))) + "\n" + stLogo.Render(o.Profile.Callsign+" / dossier") + "\n" + stMuted.Render("MITRE · "+mitreTactics(o.Profile.Archetype)) + "\n" + stMuted.Render("Tools · "+strings.Join(o.Profile.ToolCats, ", ")) + "\n" + stText.Render(safeText(task))
	if o.LastError != "" {
		drawer += "\n" + stRed.Render(safeText(o.LastError))
	}
	drawerH := lipgloss.Height(drawer)
	roster := stDim.Render("Callsign   State     Done/Fail  Risk") + "\n" + m.drawRows(rows, selected, w, max(1, h-drawerH-2), "")
	return fitArea(roster, w, max(1, h-drawerH-1)) + "\n" + drawer
}

func mitreTactics(role domain.Archetype) string {
	return map[domain.Archetype]string{domain.ArchRecon: "TA0043 Reconnaissance", domain.ArchScanner: "TA0007 Discovery", domain.ArchExploiter: "TA0001 Initial Access / TA0002 Execution", domain.ArchInfiltrator: "TA0004 Privilege Escalation / TA0008 Lateral Movement", domain.ArchExfiltrator: "TA0009 Collection / TA0010 Exfiltration", domain.ArchGhost: "TA0003 Persistence / TA0005 Defense Evasion", domain.ArchCoordinator: "TA0011 Command and Control", domain.ArchAnalyst: "TA0007 Discovery / TA0040 Impact"}[role]
}

func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return stRed.Bold(true)
	case "high":
		return stLogo
	case "medium":
		return stYellow
	case "low":
		return stPrompt
	default:
		return stMuted
	}
}

type targetRow struct {
	text, key string
	toggle    bool
}

func normalizedHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		raw = u.Hostname()
	}
	return strings.TrimSuffix(strings.ToLower(raw), ".")
}

func (m Model) targetTree() []targetRow {
	var rows []targetRow
	candidates := target.CandidateMatches(m.war.snapshot.Targets)
	for _, host := range m.war.snapshot.Targets.Hosts {
		mark := "▾ "
		if m.war.collapsed[host.ID] {
			mark = "▸ "
		}
		rows = append(rows, targetRow{text: stPrompt.Render(mark + safeText(host.Name)), key: host.ID, toggle: true})
		if m.war.collapsed[host.ID] {
			continue
		}
		for _, service := range host.Services {
			key := fmt.Sprintf("%s/%d/%s", host.ID, service.Port, service.Protocol)
			mark = "▾ "
			if m.war.collapsed[key] {
				mark = "▸ "
			}
			rows = append(rows, targetRow{text: fmt.Sprintf("  %s%d/%s", mark, service.Port, service.Protocol), key: key, toggle: true})
			if !m.war.collapsed[key] {
				rows = append(rows, targetRow{text: stMuted.Render("    └ " + safeText(strings.Join([]string{service.Name, service.Product, service.Version}, " ")))})
				for _, cpe := range service.CPE {
					rows = append(rows, targetRow{text: stDim.Render("      " + safeText(cpe))})
				}
				for _, c := range candidates {
					if c.Host == host.Name && c.Product == service.Product && c.Version == service.Version {
						rows = append(rows, targetRow{text: stYellow.Render("      candidate " + safeText(c.CVE) + " · requires review")})
					}
				}
			}
		}
		for _, f := range m.war.snapshot.Findings {
			if normalizedHost(f.TargetID) == normalizedHost(host.Name) || slices.Contains(host.Findings, f.ID) {
				for _, cve := range f.CVE {
					rows = append(rows, targetRow{text: stYellow.Render("  ├ candidate " + safeText(cve))})
				}
				rows = append(rows, targetRow{text: severityStyle(string(f.Severity)).Render("  └ [" + string(f.Severity) + "] " + safeText(f.Title))})
			}
		}
	}
	if len(m.war.snapshot.Targets.References) > 0 {
		rows = append(rows, targetRow{text: stMuted.Render("Unverified CVE reference catalog")})
		for _, r := range m.war.snapshot.Targets.References {
			rows = append(rows, targetRow{text: stDim.Render("  candidate " + safeText(r.ID) + " · " + r.Severity)})
		}
	}
	return rows
}
func (m Model) targetRows() []string {
	var rows []string
	for _, r := range m.targetTree() {
		rows = append(rows, r.text)
	}
	return rows
}

func (m Model) filteredFindings() []domain.Finding {
	var out []domain.Finding
	for _, f := range m.war.snapshot.Findings {
		if m.war.severity == "" || string(f.Severity) == m.war.severity {
			out = append(out, f)
		}
	}
	return out
}
func (m Model) filteredCatalog() []arsenal.Capability {
	var out []arsenal.Capability
	q := strings.ToLower(m.war.filter)
	for _, t := range m.war.catalog {
		if strings.Contains(strings.ToLower(t.Name+" "+t.Category+" "+t.Description), q) {
			out = append(out, t)
		}
	}
	return out
}
func (m Model) toolDescription(w int) string {
	tools := m.filteredCatalog()
	if len(tools) == 0 {
		return ""
	}
	t := tools[min(m.war.rows[4], len(tools)-1)]
	return stDim.Render(ansi.Truncate(safeText(t.Description)+" · "+t.Availability, w, "…"))
}

func (m Model) opsecPanel(w, h int) string {
	p, r, t := m.war.profile, m.war.roe, m.war.team
	if p == "" {
		p = m.war.snapshot.OPSECProfile
	}
	if r == "" {
		r = m.war.snapshot.RoEPreset
	}
	if t == "" {
		t = "balanced"
	}
	lines := []string{stPrompt.Render("[p] " + p + "  [r] " + r + "  [t] " + t), stDim.Render("Preset changes apply to the next mission"), stMuted.Render(fmt.Sprintf("Detections %d · pause %d / abort %d", m.war.snapshot.Detections, m.war.snapshot.OPSEC.Policy.PauseAfter, m.war.snapshot.OPSEC.Policy.AbortAfter))}
	signals := m.war.snapshot.OPSEC.Signals
	start := max(0, len(signals)-max(1, min(4, h/4)))
	for _, signal := range signals[start:] {
		lines = append(lines, stYellow.Render(safeText(signal.Source+" · "+signal.Indicator)))
	}
	if len(signals) == 0 {
		lines = append(lines, stDim.Render("No recorded detection signals"))
	}
	lines = append(lines, "", stLogo.Render("BENCHMARK SCOREBOARD"))
	var rows []string
	for _, name := range benchmarkNames {
		state := "not run"
		if result, ok := m.war.benchmarks[name]; ok {
			state = fmt.Sprintf("%d pass / %d fail · %.0f%%", result.Passed, result.Failed, result.TotalScore*100)
		}
		if m.war.busy && name == m.war.benchName {
			state += " · running"
		}
		rows = append(rows, name+" · "+state)
	}
	lines = append(lines, m.drawRows(rows, m.war.rows[5], w, max(1, h-len(lines)), ""))
	return strings.Join(lines, "\n")
}

func (m Model) warRowCount() int {
	switch m.war.tab {
	case 0:
		return len(m.toolEntries())
	case 1:
		return len(m.war.snapshot.Operators)
	case 2:
		return len(m.targetTree())
	case 3:
		return len(m.filteredFindings())
	case 4:
		return len(m.filteredCatalog())
	case 5:
		return len(benchmarkNames)
	}
	return 0
}

func (m Model) activateWarRow() (Model, tea.Cmd) {
	s := m.services()
	switch m.war.tab {
	case 0:
		tools := m.toolEntries()
		if len(tools) == 0 {
			return m, nil
		}
		tool := tools[min(m.war.rows[0], len(tools)-1)].tool
		if s == nil || s.ToolDetails == nil {
			m.openWarPager(pretty(tool))
			return m, nil
		}
		if m.war.busy {
			return m, nil
		}
		m.war.busy = true
		m.war.jobID++
		id := m.war.jobID
		eng, mission := m.eng, m.war.snapshot.MissionID
		return m, func() tea.Msg {
			text, err := s.ToolDetails(eng, mission, tool)
			return warResultMsg{id: id, kind: "details", text: text, err: err}
		}
	case 2:
		rows := m.targetTree()
		if len(rows) == 0 {
			return m, nil
		}
		row := rows[min(m.war.rows[2], len(rows)-1)]
		if row.toggle {
			m.war.collapsed[row.key] = !m.war.collapsed[row.key]
		}
	case 3:
		findings := m.filteredFindings()
		if len(findings) > 0 {
			m.openWarPager(pretty(findings[min(m.war.rows[3], len(findings)-1)]))
		}
	case 4:
		tools := m.filteredCatalog()
		if len(tools) == 0 {
			return m, nil
		}
		tool := tools[min(m.war.rows[4], len(tools)-1)]
		if tool.Availability != "available" {
			m.war.err = tool.Availability
			return m, nil
		}
		if tool.MissionContext {
			m.war.err = "this tool requires an active operator task"
			return m, nil
		}
		m.openWarForm("quick", tool.Name+" · exact human-issued action", "{\n  \"operator\": \"scanner\",\n  \"arguments\": {}\n}")
	case 5:
		name := benchmarkNames[min(m.war.rows[5], len(benchmarkNames)-1)]
		if result, ok := m.war.benchmarks[name]; ok {
			m.openWarPager(pretty(result))
		}
	}
	return m, nil
}

func (m Model) warHint() string {
	if m.war.composing {
		return stDim.Render("↵ send · shift+enter newline · esc leave input")
	}
	switch m.war.tab {
	case 0:
		return stDim.Render("j/k select tool · enter full input/output")
	case 1:
		return stDim.Render("j/k select operator · dossier below")
	case 2:
		return stDim.Render("j/k select · enter collapse/expand")
	case 3:
		return stDim.Render("c/h/m/l/i severity · a all · enter details · e export")
	case 4:
		return stDim.Render("/ filter · j/k select · enter quick run")
	default:
		return stDim.Render("p profile · r RoE · t team · d IOCs · b run · enter result")
	}
}

func (m Model) viewWarModal() string {
	w := max(1, min(104, m.width-4))
	h := max(3, min(m.height-2, 22))
	title := m.war.modalTitle
	body := ""
	hint := "esc close"
	switch m.war.modal {
	case "pager":
		title = "INSPECTOR"
		vp := m.war.pager
		vp.SetWidth(max(1, w-4))
		vp.SetHeight(max(1, m.height-8))
		h = max(3, m.height-2)
		body = vp.View()
		hint = "↑↓ / pgup pgdn scroll · esc close"
	case "export":
		title = "EXPORT MISSION REPORT"
		var rows []string
		for i, f := range exportFormats {
			rows = append(rows, selectedRow(strings.ToUpper(f), i == m.war.choice, w-4))
		}
		body = strings.Join(rows, "\n")
		hint = "↑↓ choose · enter destination · esc close"
	default:
		body = m.war.form.View()
		hint = "enter submit · shift+enter newline · esc close"
	}
	if m.war.err != "" {
		body += "\n" + stRed.Render(safeText(m.war.err))
	}
	body += "\n" + stDim.Render(hint)
	card := panelBox(title, body, w, h)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, card)
}

func (m Model) viewApproval() string {
	req := m.war.approvals[0].request
	w := max(1, min(96, m.width-4))
	h := max(3, min(m.height-2, 20))
	body := stText.Render(safeText(req.Tool)) + "\n" + stMuted.Render("Target · "+safeText(req.Target)) + "\n" + stDim.Render("Mission · "+safeText(req.MissionID)) + "\n\n" + stText.Render(ansi.Wrap(safeText(pretty(req.Arguments)), max(1, w-4), ""))
	// Keep the decision keys visible even with a large argument object.
	lines := strings.Split(body, "\n")
	offset := min(m.war.approvalOffset, max(0, len(lines)-max(1, h-6)))
	body = fitArea(strings.Join(lines[offset:], "\n"), w-4, max(1, h-6)) + "\n" + stPrompt.Render("[y] allow once  [a] allow for mission  [n] deny") + "\n" + stDim.Render("↑↓ scroll · mission grant: these exact arguments")
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panelBox("EXACT-ACTION APPROVAL", body, w, h))
}
