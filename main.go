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
	"rogue/internal/domain"
	"rogue/internal/engine"
	"rogue/internal/llm"
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
	reportFormat := flag.String("report-format", "json", "saved report format: json or markdown")
	assessment := flag.String("assess", "", "run one real assessment without opening the terminal UI")
	modeName := flag.String("assessment-mode", "default", "headless assessment mode: default, auto, plan")
	toolName := flag.String("tool", "", "execute one explicitly requested real tool without a model")
	arguments := flag.String("arguments", "{}", "JSON arguments for --tool")
	roleName := flag.String("operator", "scanner", "operator role for --tool")
	flag.Parse()
	if *reportFormat != "json" && *reportFormat != "markdown" {
		return fmt.Errorf("report-format must be json or markdown")
	}
	mode, err := assessmentMode(*modeName)
	if err != nil {
		return err
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	if *capabilities {
		return printJSON(newRegistry().Catalog())
	}
	if *listTools {
		return printJSON(newRegistry().Availability())
	}
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
	if *listMissions || *showMission != "" {
		store, err := openStore()
		if err != nil {
			return err
		}
		if *listMissions {
			missions, err := store.List()
			if err != nil {
				return err
			}
			return printJSON(missions)
		}
		harness := engine.NewHarnessWithOptions(nil, nil, nil, "", engine.Options{Store: store})
		report, err := harness.Report(*showMission)
		if err != nil {
			return err
		}
		if *reportFormat == "markdown" {
			_, err = fmt.Fprint(os.Stdout, report.Markdown())
			return err
		}
		return printJSON(report)
	}
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
