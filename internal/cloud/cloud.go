// Package cloud provides read-only cloud environment enumeration via local
// CLI wrappers (aws, gcloud, az) and cloud metadata posture verification.
// All operations are non-destructive and gated behind ROGUE_CLOUD=true.
package cloud

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	stdoutLimit = 2 * 1024 * 1024 // 2 MiB
	stderrLimit = 16 * 1024       // 16 KiB
)

type limitedBuf struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	limit  int
	cancel context.CancelFunc
}

func (l *limitedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buf.Len()+len(p) > l.limit {
		l.cancel()
		return 0, errors.New("cloud CLI output exceeded limit")
	}
	return l.buf.Write(p)
}

func validateCloudArg(val, name string) error {
	if val != "" && (strings.HasPrefix(val, "-") || strings.ContainsAny(val, " \r\n\t;|&`$")) {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}

// EnumerateAWS runs read-only AWS CLI commands to enumerate IAM, S3, and EC2 posture.
func EnumerateAWS(ctx context.Context, region string) (map[string]any, error) {
	if os.Getenv("ROGUE_CLOUD") != "true" {
		return nil, errors.New("cloud enumeration requires ROGUE_CLOUD=true")
	}
	if err := validateCloudArg(region, "region"); err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("aws"); err != nil {
		return nil, errors.New("aws CLI not found in PATH")
	}

	results := map[string]any{}
	cmds := []struct {
		key  string
		args []string
	}{
		{"sts_caller_identity", []string{"sts", "get-caller-identity", "--output", "json"}},
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

// EnumerateGCP runs read-only gcloud CLI commands to enumerate projects, IAM, and storage.
func EnumerateGCP(ctx context.Context, project string) (map[string]any, error) {
	if os.Getenv("ROGUE_CLOUD") != "true" {
		return nil, errors.New("cloud enumeration requires ROGUE_CLOUD=true")
	}
	if err := validateCloudArg(project, "project"); err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("gcloud"); err != nil {
		return nil, errors.New("gcloud CLI not found in PATH")
	}
	if project == "" {
		project = strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_PROJECT"))
	}
	if project == "" {
		project = strings.TrimSpace(os.Getenv("CLOUDSDK_CORE_PROJECT"))
	}

	results := map[string]any{}
	cmds := []struct {
		key  string
		args []string
	}{
		{"projects_list", []string{"projects", "list", "--format=json", "--limit=20"}},
		{"storage_buckets", []string{"storage", "buckets", "list", "--format=json"}},
		{"compute_instances", []string{"compute", "instances", "list", "--format=json", "--limit=10"}},
		{"services_enabled", []string{"services", "list", "--enabled", "--format=json", "--limit=20"}},
	}
	if project != "" {
		cmds = append([]struct {
			key  string
			args []string
		}{
			{"iam_policy", []string{"projects", "get-iam-policy", project, "--format=json"}},
		}, cmds...)
	}

	for _, cmd := range cmds {
		if ctx.Err() != nil {
			break
		}
		args := append([]string{}, cmd.args...)
		if project != "" && cmd.key != "iam_policy" && cmd.key != "projects_list" {
			args = append(args, "--project="+project)
		}
		out, err := runCLI(ctx, "gcloud", args)
		results[cmd.key] = map[string]any{"output": out, "error": errStr(err)}
	}
	return results, nil
}

// EnumerateAzure runs read-only az CLI commands for IAM and storage enumeration.
func EnumerateAzure(ctx context.Context, subscription string) (map[string]any, error) {
	if os.Getenv("ROGUE_CLOUD") != "true" {
		return nil, errors.New("cloud enumeration requires ROGUE_CLOUD=true")
	}
	if err := validateCloudArg(subscription, "subscription"); err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("az"); err != nil {
		return nil, errors.New("az CLI not found in PATH")
	}

	results := map[string]any{}
	var subArgs []string
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

// CheckMetadataPosture performs a bounded, read-only IMDSv1 vs IMDSv2 posture
// check against 169.254.169.254 when ROGUE_CLOUD=true. It only checks status
// codes (whether IMDSv1 returns 200 vs 401/403 requiring IMDSv2 session tokens);
// it never returns metadata values or instance credentials.
func CheckMetadataPosture(ctx context.Context) (map[string]any, error) {
	if os.Getenv("ROGUE_CLOUD") != "true" {
		return nil, errors.New("cloud metadata check requires ROGUE_CLOUD=true")
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"reachable": false, "imdsv1_open": false, "note": "metadata service unreachable from this host", "error": err.Error()}, nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	imdsv1Open := resp.StatusCode == http.StatusOK
	return map[string]any{
		"reachable":   true,
		"status_code": resp.StatusCode,
		"imdsv1_open": imdsv1Open,
		"posture": func() string {
			if imdsv1Open {
				return "IMDSv1 responded 200 without session token; enforce IMDSv2 HttpTokens=required"
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return "IMDSv2 session token enforced (HTTP 401/403 on unauthenticated GET)"
			}
			return fmt.Sprintf("metadata endpoint returned HTTP %d", resp.StatusCode)
		}(),
	}, nil
}

// runCLI executes a cloud CLI command with a 60s timeout and bounded stdout/stderr.
func runCLI(ctx context.Context, name string, args []string) (string, error) {
	tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found: %w", name, err)
	}

	outBuf := &limitedBuf{limit: stdoutLimit, cancel: cancel}
	errBuf := &limitedBuf{limit: stderrLimit, cancel: cancel}

	cmd := exec.CommandContext(tctx, path, args...)
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf
	cmd.Stdin = strings.NewReader("")
	cmd.WaitDelay = time.Second
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"LANG=C",
		"LC_ALL=C",
		"HOME=" + os.Getenv("HOME"),
		"AWS_ACCESS_KEY_ID=" + os.Getenv("AWS_ACCESS_KEY_ID"),
		"AWS_SECRET_ACCESS_KEY=" + os.Getenv("AWS_SECRET_ACCESS_KEY"),
		"AWS_SESSION_TOKEN=" + os.Getenv("AWS_SESSION_TOKEN"),
		"AWS_DEFAULT_REGION=" + os.Getenv("AWS_DEFAULT_REGION"),
		"GOOGLE_CLOUD_PROJECT=" + os.Getenv("GOOGLE_CLOUD_PROJECT"),
		"CLOUDSDK_CORE_PROJECT=" + os.Getenv("CLOUDSDK_CORE_PROJECT"),
		"GOOGLE_APPLICATION_CREDENTIALS=" + os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
		"AZURE_CONFIG_DIR=" + os.Getenv("AZURE_CONFIG_DIR"),
	}

	err = cmd.Run()
	if err != nil && errBuf.buf.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(errBuf.buf.String()))
	}
	return outBuf.buf.String(), err
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
