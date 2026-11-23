// Rogue keeps its terminal interface separate from execution and storage.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
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
	listMissions := flag.Bool("list-missions", false, "list saved missions without calling a model")
	showMission := flag.String("show-mission", "", "show a saved mission's redacted report")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flag.Args())
	}
	if *listTools {
		return printJSON(newRegistry().Availability())
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
	_, err = tea.NewProgram(tui.New(backend)).Run()
	return err
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
