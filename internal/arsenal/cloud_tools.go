package arsenal

// cloud_tools.go — registers aws_enum, gcp_enum, azure_enum tools.

import (
	"context"
	"encoding/json"
	"fmt"

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
			return ok(res), nil
		},
	})

	registry.Register(&Tool{
		Name:        "gcp_enum",
		Category:    "cloud",
		LabOnly:     true,
		Description: "Enumerate GCP IAM, storage, and compute resources via the gcloud CLI. Requires ROGUE_CLOUD=true.",
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
			return ok(res), nil
		},
	})

	registry.Register(&Tool{
		Name:        "azure_enum",
		Category:    "cloud",
		LabOnly:     true,
		Description: "Enumerate Azure IAM, storage, and VM resources via the az CLI. Requires ROGUE_CLOUD=true.",
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
			return ok(res), nil
		},
	})
}

// ensure fmt is used (whitebox_tool.go imports it via fail())
var _ = fmt.Sprintf
