package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"rogue/internal/engine"
)

func assessmentMode(value string) (engine.Mode, error) {
	switch value {
	case "default":
		return engine.ModeDefault, nil
	case "auto":
		return engine.ModeAuto, nil
	case "plan":
		return engine.ModePlan, nil
	default:
		return 0, fmt.Errorf("assessment-mode must be default, auto, or plan")
	}
}

// Headless runs use the same engine and durable evidence as the TUI. Status goes
// to stderr so stdout remains a machine-readable report, including partial work
// from a failed mission. A failure still exits with a nonzero status.
func runAssessment(harness *engine.Harness, prompt string, mode engine.Mode, format string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var failure error
	done := false
	for event := range harness.Run(ctx, engine.Request{Prompt: prompt, Mode: mode}) {
		switch event.Kind {
		case engine.KindNotice:
			fmt.Fprintln(os.Stderr, event.Text)
		case engine.KindToolStart:
			fmt.Fprintf(os.Stderr, "tool started: %s [%s]\n", event.Tool.Name, event.Tool.ID)
		case engine.KindToolEnd:
			fmt.Fprintf(os.Stderr, "tool finished: %s success=%t %s\n", event.Tool.Name, event.Tool.OK, event.Tool.Output)
		case engine.KindError:
			failure = errors.Join(failure, event.Err)
		case engine.KindDone:
			done = true
		}
	}
	if failure == nil && !done {
		failure = errors.New("assessment ended without successful completion")
	}
	state := harness.LastRun()
	if state == nil {
		return failure
	}
	report, err := harness.Report(state.Control.Snapshot().ID)
	if err != nil {
		return errors.Join(failure, err)
	}
	if format == "markdown" {
		_, err = fmt.Fprint(os.Stdout, report.Markdown())
	} else {
		err = printJSON(report)
	}
	return errors.Join(failure, err)
}
