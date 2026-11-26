package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"rogue/internal/bench"
	"rogue/internal/domain"
	"rogue/internal/engine"
	reportexport "rogue/internal/export"
	"rogue/internal/plugin"
	"rogue/internal/tui"
)

func tuiWarRoomServices() *tui.WarRoomServices {
	registry := newRegistry()
	svc := &tui.WarRoomServices{Catalog: registry.Catalog, Profile: "loud", RoE: "default", Team: "balanced", Lifecycle: tuiLifecycle}
	if opts, err := loadOptions(); err == nil {
		svc.TokenLimit, svc.CostLimit = opts.MaxTokens, opts.CostLimit
		if opts.OPSECProfile != "" {
			svc.Profile = opts.OPSECProfile
		}
		if opts.RoEPreset != "" {
			svc.RoE = opts.RoEPreset
		}
		if opts.Team != "" {
			svc.Team = opts.Team
		}
	}
	svc.Configure = func(eng engine.Engine, p, r, t string) (engine.Engine, error) {
		h, ok := eng.(*engine.Harness)
		if !ok {
			return nil, errors.New("preset configuration requires the mission harness")
		}
		return h.WithWarRoomPresets(p, r, t)
	}
	svc.QuickRun = func(ctx context.Context, eng engine.Engine, name string, args json.RawMessage, role domain.Archetype, mode engine.Mode) (engine.Report, error) {
		h, ok := eng.(*engine.Harness)
		if !ok {
			return engine.Report{}, errors.New("quick run requires the mission harness")
		}
		_ = tuiLifecycle("start", engine.Event{})
		_ = tuiLifecycle("event", engine.Event{Kind: engine.KindToolStart, Tool: engine.ToolCall{Name: name}})
		report, err := h.ExecuteTool(ctx, name, args, role, mode)
		_ = tuiLifecycle("event", engine.Event{Kind: engine.KindToolEnd, Tool: engine.ToolCall{Name: name, OK: err == nil}})
		kind := "complete"
		if err != nil {
			kind = "abort"
		}
		_ = tuiLifecycle(kind, engine.Event{Err: err})
		return report, err
	}
	svc.Export = func(eng engine.Engine, id, format, path string) (string, error) {
		h, ok := eng.(interface {
			Report(string) (engine.Report, error)
		})
		if !ok {
			return "", errors.New("report export unavailable")
		}
		report, err := h.Report(id)
		if err != nil {
			return "", err
		}
		var data []byte
		switch format {
		case "json":
			data, err = reportexport.ExportJSON(report)
		case "sarif":
			data, err = reportexport.ExportSARIF(report)
		case "html":
			data, err = reportexport.ExportHTML(report)
		case "markdown":
			data = []byte(report.Markdown())
		case "pdf":
			data, err = reportexport.ExportPDF(report)
		default:
			return "", errors.New("unknown report format")
		}
		if err != nil {
			return "", err
		}
		// Exclusive creation prevents a mistyped destination from replacing a file.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return "", err
		}
		_, writeErr := f.Write(data)
		err = errors.Join(writeErr, f.Close())
		if err != nil {
			return "", err
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		return absolute, Plugins.FireHook(plugin.HookReportExport, map[string]any{"mission_id": id, "format": format, "path": absolute})
	}
	svc.ToolDetails = func(eng engine.Engine, id string, tool engine.ToolCall) (string, error) {
		h, ok := eng.(interface {
			ToolTrace(string, string) (json.RawMessage, error)
		})
		if !ok || id == "" {
			data, _ := json.MarshalIndent(tool, "", "  ")
			return string(data), nil
		}
		data, err := h.ToolTrace(id, tool.ID)
		return string(data), err
	}
	svc.Benchmark = func(ctx context.Context, eng engine.Engine, name, target string, progress func(bench.SuiteResult)) (bench.SuiteResult, error) {
		h, ok := eng.(*engine.Harness)
		if !ok {
			return bench.SuiteResult{}, errors.New("benchmarks require the mission harness")
		}
		var suite bench.Suite
		switch name {
		case "cybench":
			suite = bench.CybenchSuite("")
		case "nyu-ctf":
			suite = bench.NYUCTFSuite("")
		case "xbow":
			suite = bench.XBOWSuite(target)
		case "juice-shop":
			suite = bench.JuiceShopSuite(target)
		case "local-ctf":
			suite = bench.LocalCTFSuite(target)
		default:
			return bench.SuiteResult{}, errors.New("unknown suite")
		}
		if len(suite.Cases) == 0 {
			return bench.SuiteResult{}, fmt.Errorf("%s contains no runnable cases", name)
		}
		// Remote suites describe public fixtures. Execution stays bounded by the
		// harness scope; the submitted target is used by target-based suites only.
		start := time.Now()
		result := bench.SuiteResult{Suite: suite.Name, Timestamp: start.UTC(), ByCategory: map[string]bench.CategoryScore{}}
		runner := bench.NewRunner(h).WithEvents(func(event engine.Event) { _ = tuiLifecycle("event", event) })
		var sum float64
		for _, c := range suite.Cases {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			_ = tuiLifecycle("start", engine.Event{})
			r := runner.RunCase(ctx, suite.Name, c)
			result.Results = append(result.Results, r)
			sum += r.Score
			if r.Passed {
				result.Passed++
			} else {
				result.Failed++
			}
			kind := "complete"
			var err error
			if r.Error != "" {
				kind = "abort"
				err = errors.New(r.Error)
			}
			_ = tuiLifecycle(kind, engine.Event{Err: err})
			cat := result.ByCategory[r.Category]
			cat.Cases++
			if r.Passed {
				cat.Passed++
			}
			cat.AvgScore += (r.Score - cat.AvgScore) / float64(cat.Cases)
			result.ByCategory[r.Category] = cat
			result.TotalScore = sum / float64(len(result.Results))
			result.Duration = time.Since(start)
			copyResult := result
			copyResult.Results = append([]bench.Result(nil), result.Results...)
			copyResult.ByCategory = nil
			progress(copyResult)
		}
		return result, nil
	}
	return svc
}

func tuiLifecycle(kind string, event engine.Event) error {
	data := map[string]any{"tool": event.Tool.Name, "id": event.Tool.ID, "ok": event.Tool.OK}
	var hook plugin.HookEvent
	switch kind {
	case "start":
		Metrics.Counter("missions_started").Inc()
		hook = plugin.HookMissionStart
	case "complete":
		Metrics.Counter("missions_completed").Inc()
		hook = plugin.HookMissionComplete
	case "abort":
		Metrics.Counter("missions_failed").Inc()
		hook = plugin.HookMissionAbort
		if event.Err != nil {
			data["error"] = event.Err.Error()
		}
	case "event":
		switch event.Kind {
		case engine.KindToolStart:
			Metrics.Counter("tool_calls_started").Inc()
			hook = plugin.HookToolBefore
		case engine.KindToolEnd:
			Metrics.Counter("tool_calls_finished").Inc()
			counter := "tool_calls_failed"
			if event.Tool.OK {
				counter = "tool_calls_succeeded"
			}
			Metrics.Counter(counter).Inc()
			hook = plugin.HookToolAfter
		default:
			return nil
		}
	default:
		return nil
	}
	return Plugins.FireHook(hook, data)
}
