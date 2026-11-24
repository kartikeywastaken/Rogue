// Rogue keeps its terminal interface separate from execution and storage.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
	"rogue/internal/api"
	"rogue/internal/bench"
	"rogue/internal/domain"
	"rogue/internal/engine"
	"rogue/internal/llm"
	"rogue/internal/mcp"
	"rogue/internal/tui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "rogue:", err)
		os.Exit(1)
	}
}

func run() error {
	checkProvider := flag.Bool("check-provider", false, "verify the configured model with a harmless echo tool (uses provider credits)")
	listTools := flag.Bool("list-tools", false, "show installed tool availability without calling a model")
	capabilities := flag.Bool("capabilities", false, "show actual tool capabilities and execution gates")
	listMissions := flag.Bool("list-missions", false, "list saved missions without calling a model")
	showMission := flag.String("show-mission", "", "show a saved mission's redacted report")
	reportFormat := flag.String("report-format", "json", "saved report format: json, markdown, sarif, csv, or html")
	assessment := flag.String("assess", "", "run one real assessment without opening the terminal UI")
	modeName := flag.String("assessment-mode", "default", "headless assessment mode: default, auto, plan")
	toolName := flag.String("tool", "", "execute one explicitly requested real tool without a model")
	arguments := flag.String("arguments", "{}", "JSON arguments for --tool")
	roleName := flag.String("operator", "scanner", "operator role for --tool")

	// Phase 4: CLI mission/preset/config/report operations
	exportMission := flag.String("export-mission", "", "export a mission report (use with --report-format and --output)")
	outputPath := flag.String("output", "-", "output path for --export-mission (use - for stdout)")
	deleteMission := flag.String("delete-mission", "", "delete a saved mission by ID")
	missionStatus := flag.String("mission-status", "", "show detailed status of a mission by ID")
	showConfig := flag.Bool("show-config", false, "show current ROGUE configuration summary")
	validateConfig := flag.Bool("validate-config", false, "validate current configuration and tool availability")
	toolInfo := flag.String("tool-info", "", "show detailed information about a specific tool")
	listPresets := flag.Bool("list-presets", false, "list built-in assessment presets")
	listOperators := flag.Bool("list-operators", false, "list all operator archetypes and their capabilities")
	mergeReports := flag.String("merge-reports", "", "comma-separated mission IDs to merge into one report")

	// Phase 4: HTTP API server
	serveAddr := flag.String("serve", "", "start the HTTP API server on this address (e.g. :8080)")
	apiKey := flag.String("api-key", "", "Bearer token for the HTTP API (overrides ROGUE_API_KEY)")

	// Phase 4: MCP stdio server
	mcpMode := flag.Bool("mcp", false, "start the MCP JSON-RPC 2.0 stdio server")

	// Phase 4: benchmarks
	benchSuite := flag.String("benchmark", "", "run a benchmark suite: juice-shop, dvwa, webgoat, quick")
	benchTarget := flag.String("benchmark-target", "", "target URL for the benchmark suite")

	flag.Parse()
	if *reportFormat != "json" && *reportFormat != "markdown" && *reportFormat != "sarif" && *reportFormat != "csv" && *reportFormat != "html" {
		return fmt.Errorf("report-format must be json, markdown, sarif, csv, or html")
	}
	mode, err := assessmentMode(*modeName)
	if err != nil {
		return err
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}

	// ── simple read-only flags (no harness needed) ───────────────────────────
	if *capabilities {
		return printJSON(newRegistry().Catalog())
	}
	if *listTools {
		return printJSON(newRegistry().Availability())
	}
	if *showConfig {
		return runShowConfig()
	}
	if *validateConfig {
		return runValidateConfig()
	}
	if *listPresets {
		return runListPresets()
	}
	if *listOperators {
		return runListOperators()
	}
	if *toolInfo != "" {
		return runToolInfo(newRegistry(), *toolInfo)
	}

	// ── tool execution (no model) ────────────────────────────────────────────
	if *toolName != "" {
		if *arguments == "-" {
			data, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
			if err != nil {
				return err
			}
			if len(data) > 65536 {
				return fmt.Errorf("tool arguments exceed 64 KiB")
			}
			*arguments = string(data)
		}
		harness, err := buildHarness(nil, nil, "")
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		report, failure := harness.ExecuteTool(ctx, *toolName, json.RawMessage(*arguments), domain.Archetype(*roleName), mode)
		if report.Mission.ID != "" {
			if *reportFormat == "markdown" {
				_, err = fmt.Fprint(os.Stdout, report.Markdown())
			} else {
				err = printJSON(report)
			}
		}
		return errors.Join(failure, err)
	}

	// ── mission list / show (no model) ──────────────────────────────────────
	if *listMissions || *showMission != "" || *exportMission != "" || *deleteMission != "" || *missionStatus != "" || *mergeReports != "" {
		store, err := openStore()
		if err != nil {
			return err
		}
		harness := engine.NewHarnessWithOptions(nil, nil, nil, "", engine.Options{Store: store})
		if *listMissions {
			missions, err := store.List()
			if err != nil {
				return err
			}
			return printJSON(missions)
		}
		if *showMission != "" {
			report, err := harness.Report(*showMission)
			if err != nil {
				return err
			}
			return exportReport(report, *reportFormat, "-")
		}
		if *exportMission != "" {
			report, err := harness.Report(*exportMission)
			if err != nil {
				return err
			}
			return exportReport(report, *reportFormat, *outputPath)
		}
		if *deleteMission != "" {
			return runDeleteMission(store, *deleteMission)
		}
		if *missionStatus != "" {
			return runMissionStatus(harness, *missionStatus)
		}
		if *mergeReports != "" {
			ids := splitCSV(*mergeReports)
			return runMergeReports(harness, ids, *reportFormat)
		}
	}

	// ── provider check ───────────────────────────────────────────────────────
	if *checkProvider {
		config, err := llm.LoadConfig(os.Getenv)
		if err != nil {
			return err
		}
		options, err := loadOptions()
		if err != nil {
			return err
		}
		budget, err := llm.NewBudget(llm.BudgetLimits{Tokens: options.MaxTokens, Dollars: options.CostLimit, InputPerMillion: options.InputPrice, OutputPerMillion: options.OutputPrice})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		capabilities, err := llm.Probe(llm.WithBudget(ctx, budget), config.RawClient(), config.Model)
		if err != nil {
			return err
		}
		return printJSON(capabilities)
	}

	// ── MCP stdio server ─────────────────────────────────────────────────────
	if *mcpMode {
		store, err := openStore()
		if err != nil {
			return err
		}
		harness := engine.NewHarnessWithOptions(nil, nil, nil, "", engine.Options{Store: store})
		reg := newRegistry()
		srv := mcp.New(harness, reg, store)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return srv.Run(ctx)
	}

	// ── HTTP API server ──────────────────────────────────────────────────────
	if *serveAddr != "" {
		key := *apiKey
		if key == "" {
			key = os.Getenv("ROGUE_API_KEY")
		}
		harness, err := buildHarness(nil, nil, "")
		if err != nil {
			return err
		}
		store, err := openStore()
		if err != nil {
			return err
		}
		reg := newRegistry()
		srv := api.New(harness, reg, store, key)
		fmt.Fprintf(os.Stderr, "rogue: HTTP API listening on %s\n", *serveAddr)
		return srv.ListenAndServe(*serveAddr)
	}

	// ── benchmark suite ──────────────────────────────────────────────────────
	if *benchSuite != "" {
		harness, err := buildHarness(nil, nil, "")
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		runner := bench.NewRunner(harness)
		var suite bench.Suite
		switch *benchSuite {
		case "juice-shop":
			suite = bench.JuiceShopSuite(*benchTarget)
		case "dvwa":
			suite = bench.DVWASuite(*benchTarget)
		case "webgoat":
			suite = bench.WebGoatSuite(*benchTarget)
		case "quick":
			suite = bench.QuickSuite(*benchTarget)
		default:
			return fmt.Errorf("unknown benchmark suite %q; available: juice-shop, dvwa, webgoat, quick", *benchSuite)
		}
		result := runner.Run(ctx, suite)
		if *reportFormat == "markdown" {
			_, err := fmt.Fprint(os.Stdout, bench.SuiteReport(result))
			return err
		}
		data, err := bench.SuiteReportJSON(result)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	}

	// ── build engine and dispatch to TUI or headless assessment ─────────────
	backend, err := buildEngine()
	if err != nil {
		return err
	}
	if *assessment != "" {
		return runAssessment(backend.(*engine.Harness), *assessment, mode, *reportFormat)
	}
	_, err = tea.NewProgram(tui.New(backend)).Run()
	return err
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
