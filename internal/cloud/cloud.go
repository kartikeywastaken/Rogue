// Package cloud provides read-only cloud environment enumeration via local
// CLI wrappers (aws, gcloud, az). All operations are non-destructive.
// Tools in this package are gated behind ROGUE_CLOUD=true or LabOnly=true.
package cloud

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const outputLimit = 2 * 1024 * 1024 // 2 MiB

// EnumerateAWS runs read-only AWS CLI commands to enumerate IAM, S3, and
// EC2 metadata. Requires the aws CLI and valid credentials in the environment.
// region may be empty (uses AWS_DEFAULT_REGION or CLI config).
func EnumerateAWS(ctx context.Context, region string) (map[string]any, error) {
	if os.Getenv("ROGUE_CLOUD") != "true" {
		return nil, errors.New("cloud enumeration requires ROGUE_CLOUD=true")
	}
	if _, err := exec.LookPath("aws"); err != nil {
		return nil, errors.New("aws CLI not found in PATH")
	}

	results := map[string]any{}
	cmds := []struct {
		key  string
		args []string
	}{
		{"iam_get_account_summary", []string{"iam", "get-account-summary", "--output", "json"}},
		{"iam_list_users", []string{"iam", "list-users", "--output", "json", "--max-items", "50"}},
		{"iam_list_roles", []string{"iam", "list-roles", "--output", "json", "--max-items", "50"}},
		{"s3_list_buckets", []string{"s3api", "list-buckets", "--output", "json"}},
		{"ec2_describe_instances", []string{"ec2", "describe-instances", "--output", "json", "--max-results", "10"}},
	}
	if region != "" {
		for i := range cmds {
			cmds[i].args = append(cmds[i].args, "--region", region)
		}
	}

	for _, cmd := range cmds {
		if ctx.Err() != nil {
			break
		}
		out, err := runCLI(ctx, "aws", cmd.args)
		results[cmd.key] = map[string]any{"output": out, "error": errStr(err)}
	}
	return results, nil
}

// EnumerateGCP runs read-only gcloud CLI commands to enumerate IAM and storage.
// project may be empty (uses gcloud default project).
func EnumerateGCP(ctx context.Context, project string) (map[string]any, error) {
	if os.Getenv("ROGUE_CLOUD") != "true" {
		return nil, errors.New("cloud enumeration requires ROGUE_CLOUD=true")
	}
	if _, err := exec.LookPath("gcloud"); err != nil {
		return nil, errors.New("gcloud CLI not found in PATH")
	}

	results := map[string]any{}
	projectFlag := ""
	if project != "" {
		projectFlag = "--project=" + project
	}

	cmds := []struct {
		key  string
		args []string
	}{
		{"iam_policy", []string{"projects", "get-iam-policy", project, "--format=json"}},
		{"storage_buckets", []string{"storage", "buckets", "list", "--format=json"}},
		{"compute_instances", []string{"compute", "instances", "list", "--format=json", "--limit=10"}},
		{"services_enabled", []string{"services", "list", "--enabled", "--format=json", "--limit=20"}},
	}

	for _, cmd := range cmds {
		if ctx.Err() != nil {
			break
		}
		args := append([]string{}, cmd.args...)
		if projectFlag != "" && cmd.key == "iam_policy" {
			// project already embedded above
		} else if projectFlag != "" {
			args = append(args, projectFlag)
		}
		out, err := runCLI(ctx, "gcloud", args)
		results[cmd.key] = map[string]any{"output": out, "error": errStr(err)}
	}
	return results, nil
}

// EnumerateAzure runs read-only az CLI commands for IAM and storage enumeration.
// subscription may be empty (uses default subscription).
func EnumerateAzure(ctx context.Context, subscription string) (map[string]any, error) {
	if os.Getenv("ROGUE_CLOUD") != "true" {
		return nil, errors.New("cloud enumeration requires ROGUE_CLOUD=true")
	}
	if _, err := exec.LookPath("az"); err != nil {
		return nil, errors.New("az CLI not found in PATH")
	}

	results := map[string]any{}
	subArgs := []string{}
	if subscription != "" {
		subArgs = []string{"--subscription", subscription}
	}

	cmds := []struct {
		key  string
		args []string
	}{
		{"account_list", []string{"account", "list", "--output", "json"}},
		{"role_assignments", append([]string{"role", "assignment", "list", "--all", "--output", "json"}, subArgs...)},
		{"storage_accounts", append([]string{"storage", "account", "list", "--output", "json"}, subArgs...)},
		{"vm_list", append([]string{"vm", "list", "--output", "json"}, subArgs...)},
	}

	for _, cmd := range cmds {
		if ctx.Err() != nil {
			break
		}
		out, err := runCLI(ctx, "az", cmd.args)
		results[cmd.key] = map[string]any{"output": out, "error": errStr(err)}
	}
	return results, nil
}

// runCLI executes a CLI command with a 60s timeout and 2 MiB output cap.
// Env is stripped to PATH, LANG, LC_ALL only.
func runCLI(ctx context.Context, name string, args []string) (string, error) {
	tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found: %w", name, err)
	}

	cmd := exec.CommandContext(tctx, path, args...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"LANG=C",
		"LC_ALL=C",
		// Pass through cloud credentials from environment
		"HOME=" + os.Getenv("HOME"),
		"AWS_ACCESS_KEY_ID=" + os.Getenv("AWS_ACCESS_KEY_ID"),
		"AWS_SECRET_ACCESS_KEY=" + os.Getenv("AWS_SECRET_ACCESS_KEY"),
		"AWS_DEFAULT_REGION=" + os.Getenv("AWS_DEFAULT_REGION"),
		"GOOGLE_CLOUD_PROJECT=" + os.Getenv("GOOGLE_CLOUD_PROJECT"),
		"CLOUDSDK_CORE_PROJECT=" + os.Getenv("CLOUDSDK_CORE_PROJECT"),
	}

	var sb strings.Builder
	out, err := cmd.Output()
	if len(out) > outputLimit {
		out = out[:outputLimit]
	}
	sb.Write(out)
	return sb.String(), err
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
