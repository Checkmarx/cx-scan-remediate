package app

import (
	"context"
	"strings"
	"testing"
)

func TestExitCodeForIsNeverZero(t *testing.T) {
	if got := exitCodeFor(0); got != exitGateFailed {
		t.Errorf("exitCodeFor(0) = %d, want %d", got, exitGateFailed)
	}
	if got := exitCodeFor(2); got != exitError {
		t.Errorf("exitCodeFor(2) = %d, want %d", got, exitError)
	}
}

// clearEnv stops the developer's or runner's environment from supplying settings to Main.
func clearEnv(t *testing.T) {
	for _, name := range []string{
		"GITHUB_TOKEN", "CX_APIKEY", "CX_CLIENT_ID", "CX_CLIENT_SECRET", "CX_BASE_URI", "CX_BASE_AUTH_URI", "CX_TENANT",
		"CXSR_LOG_LEVEL", "CXSR_REPORT_FILE", "CXSR_ENGINES", "CXSR_SEVERITIES", "CXSR_TRIAGE_COUNT", "CXSR_REMEDIATE_COUNT",
		"CXSR_PROXY", "CXSR_INSECURE", "CXSR_CA_CERT", "CXSR_REPO",
	} {
		t.Setenv(name, "")
	}
}

// Main returns the exit code instead of exiting, so every early exit can be tested. None of these
// cases reaches the network: they stop at the command line, the transport or the client setup.
func TestMainExitCodes(t *testing.T) {
	clearEnv(t)
	cases := []struct {
		name string
		args []string
		want int
		log  string
	}{
		{"help", []string{"-h"}, 0, ""},
		{"unknown flag", []string{"--no-such-flag"}, exitUsage, ""},
		{"bad log level", []string{"--log-level", "verbose"}, exitUsage, "Invalid --log-level"},
		{"bad severity", []string{"--severities", "BOGUS"}, exitUsage, "Invalid --severities"},
		{"unsupported engine", []string{"--engines", "iac"}, exitUsage, "Invalid --engines"},
		{"negative count", []string{"--triage-count", "-1"}, exitUsage, "must not be negative"},
		{"remediation without a token", []string{"--remediate-count", "1"}, exitUsage, "requires a GitHub token"},
		{"bad proxy", []string{"--remediate-count", "0", "--proxy", "proxy.corp:8080"}, exitError, "[FATAL]"},
		{"client cannot be created", []string{"--remediate-count", "0", "--apikey", "x", "--base-uri", "https://localhost:1", "--report-file", "missing.json"}, exitError, "[FATAL]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out strings.Builder
			got := Main(context.Background(), "test", append([]string{"cxscanremediate"}, c.args...), &out)
			if got != c.want {
				t.Errorf("exit code %d, want %d; log:\n%s", got, c.want, out.String())
			}
			if !strings.Contains(out.String(), "Starting cxscanremediate test") || !strings.Contains(out.String(), c.log) {
				t.Errorf("log does not contain %q:\n%s", c.log, out.String())
			}
		})
	}
}

func TestMainInvalidEnvironmentValue(t *testing.T) {
	clearEnv(t)
	t.Setenv("CXSR_TRIAGE_COUNT", "many")
	var out strings.Builder
	if got := Main(context.Background(), "test", []string{"cxscanremediate"}, &out); got != exitUsage {
		t.Errorf("exit code %d, want %d", got, exitUsage)
	}
	if !strings.Contains(out.String(), "CXSR_TRIAGE_COUNT") {
		t.Errorf("the error should name the variable:\n%s", out.String())
	}
}
