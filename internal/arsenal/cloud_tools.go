package arsenal

// cloud_tools.go — registers aws_enum, gcp_enum, azure_enum, and cloud_metadata_check.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"rogue/internal/cloud"
)

// RegisterCloudTools adds cloud enumeration tools to the registry.
// All require ROGUE_CLOUD=true in the environment.
func RegisterCloudTools(registry *Registry) {
	registry.Register(&Tool{
		Name:        "aws_enum",
		Category:    "cloud",
		LabOnly:     true,
		Description: "Enumerate AWS IAM, S3, and EC2 resources via the aws CLI. Requires ROGUE_CLOUD=true and valid AWS credentials.",
		Available:   func() error { _, err := exec.LookPath("aws"); return err },
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"region": map[string]any{"type": "string", "description": "AWS region e.g. us-east-1"},
		}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Region string `json:"region"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			res, err := cloud.EnumerateAWS(ctx, a.Region)
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("AWS read-only enumeration completed (%d checks)", len(res)), Data: res}, nil
		},
	})

	registry.Register(&Tool{
		Name:        "gcp_enum",
		Category:    "cloud",
		LabOnly:     true,
		Description: "Enumerate GCP IAM, storage, and compute resources via the gcloud CLI. Requires ROGUE_CLOUD=true.",
		Available:   func() error { _, err := exec.LookPath("gcloud"); return err },
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"project": map[string]any{"type": "string", "description": "GCP project ID"},
		}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Project string `json:"project"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			res, err := cloud.EnumerateGCP(ctx, a.Project)
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("GCP read-only enumeration completed (%d checks)", len(res)), Data: res}, nil
		},
	})

	registry.Register(&Tool{
		Name:        "azure_enum",
		Category:    "cloud",
		LabOnly:     true,
		Description: "Enumerate Azure IAM, storage, and VM resources via the az CLI. Requires ROGUE_CLOUD=true.",
		Available:   func() error { _, err := exec.LookPath("az"); return err },
		Parameters: map[string]any{"type": "object", "properties": map[string]any{
			"subscription": map[string]any{"type": "string", "description": "Azure subscription ID"},
		}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			var a struct{ Subscription string `json:"subscription"` }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			res, err := cloud.EnumerateAzure(ctx, a.Subscription)
			if err != nil {
				return fail(err)
			}
			return &Result{Success: true, Summary: fmt.Sprintf("Azure read-only enumeration completed (%d checks)", len(res)), Data: res}, nil
		},
	})

	registry.Register(&Tool{
		Name:        "cloud_metadata_check",
		Category:    "cloud",
		LabOnly:     true,
		Description: "Check whether IMDSv1 (169.254.169.254) responds without IMDSv2 session tokens. Requires ROGUE_CLOUD=true. Never retrieves secrets or credentials.",
		Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
		Execute: func(ctx context.Context, raw json.RawMessage) (*Result, error) {
			res, err := cloud.CheckMetadataPosture(ctx)
			if err != nil {
				return fail(err)
			}
			summary, _ := res["posture"].(string)
			if summary == "" {
				summary, _ = res["note"].(string)
			}
			return &Result{Success: true, Summary: summary, Data: res}, nil
		},
	})
}
