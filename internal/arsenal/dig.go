package arsenal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

func digTool(options ExternalOptions) *Tool {
	return &Tool{Name: "dig_lookup", Category: "recon", Description: "Resolve one scoped hostname with installed dig; fixed timeout and record types, no arbitrary command flags.", Available: func() error { _, err := executable("dig", options.DigPath); return err }, Parameters: stringSchema([]string{"host"}, "host", "record_type"), Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
		var args struct {
			Host       string
			RecordType string `json:"record_type"`
		}
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
		if err := checkHost(ctx, args.Host); err != nil {
			return nil, err
		}
		if strings.HasPrefix(args.Host, "-") || strings.HasPrefix(args.Host, "+") || strings.ContainsAny(args.Host, " \r\n\t") {
			return nil, errors.New("invalid DNS name")
		}
		if args.RecordType == "" {
			args.RecordType = "A"
		}
		switch args.RecordType {
		case "A", "AAAA", "MX", "NS", "TXT", "CNAME":
		default:
			return nil, errors.New("unsupported DNS record type")
		}
		path, err := executable("dig", options.DigPath)
		if err != nil {
			return nil, err
		}
		data, err := options.Runner.Run(ctx, path, []string{"+time=2", "+tries=1", "+short", args.Host, args.RecordType})
		if err != nil {
			return nil, err
		}
		var records []string
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line != "" {
				records = append(records, line)
			}
		}
		return &Result{Success: true, Summary: "dig completed; empty records do not establish domain absence", Data: map[string]any{"records": records, "record_type": args.RecordType}, Artifact: data, ArtifactType: "text/plain"}, nil
	}}
}
