package cli

import (
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/Checkmarx/cx-scan-remediate/internal/testutil"
)

// every flag except --access-token (short-lived) has an environment variable, and every
// environment variable belongs to a flag
func TestEveryFlagHasEnv(t *testing.T) {
	fs, _ := NewFlagSet("t", "dev")
	defined := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		defined[f.Name] = true
		_, ok := flagEnv[f.Name]
		if ok == (f.Name == "access-token") {
			t.Errorf("flag --%s: has environment variable = %v", f.Name, ok)
		}
		if ok && !strings.Contains(f.Usage, "[env: ") {
			t.Errorf("flag --%s: help text does not name its environment variable", f.Name)
		}
	})
	for name := range flagEnv {
		if !defined[name] {
			t.Errorf("environment variable for unknown flag --%s", name)
		}
	}
}

func TestParse(t *testing.T) {
	t.Setenv("CXSR_REPO", "o/r")
	t.Setenv("CXSR_TRIAGE_COUNT", "")
	c, err := Parse("t", "1.2.3", []string{"--triage-count", "3"})
	if err != nil {
		t.Fatal(err)
	}
	if c.TriageCount != 3 || c.Repo != "o/r" || c.RemediateCount != 1 || c.UserAgent != "cxscanremediate/1.2.3" {
		t.Errorf("unexpected config %+v", c)
	}

	// errors the flag package reports itself (printing the usage text) are marked, so they are
	// not reported twice
	if _, err := Parse("t", "dev", []string{"-h"}); !errors.Is(err, flag.ErrHelp) || !errors.Is(err, ErrReported) {
		t.Errorf("-h: got %v", err)
	}
	if _, err := Parse("t", "dev", []string{"--nope"}); !errors.Is(err, ErrReported) {
		t.Errorf("unknown flag: got %v", err)
	}

	// an invalid environment value is not reported by the flag package
	t.Setenv("CXSR_TRIAGE_COUNT", "many")
	if _, err := Parse("t", "dev", nil); err == nil || errors.Is(err, ErrReported) || !strings.Contains(err.Error(), "CXSR_TRIAGE_COUNT") {
		t.Errorf("invalid environment value: got %v", err)
	}
}

func TestValidate(t *testing.T) {
	base := func() *Config {
		_, c := NewFlagSet("t", "dev")
		c.GitHubToken = "token"
		return c
	}

	c := base()
	c.TriageCount = 1000
	severities, engines, err := c.Validate(testutil.Logger())
	if err != nil || !severities["CRITICAL"] || !severities["HIGH"] || len(severities) != 2 || !engines.SAST || !engines.SCA {
		t.Errorf("defaults: %v %+v %v", severities, engines, err)
	}
	if c.TriageCount != maxAIFindings {
		t.Errorf("triage count %d, want it capped at %d", c.TriageCount, maxAIFindings)
	}

	for name, change := range map[string]func(*Config){
		"Invalid --severities":    func(c *Config) { c.Severities = "BOGUS" },
		"Invalid --engines":       func(c *Config) { c.Engines = "iac" },
		"must not be negative":    func(c *Config) { c.RemediateCount = -1 },
		"requires a GitHub token": func(c *Config) { c.GitHubToken = "" },
	} {
		c := base()
		change(c)
		if _, _, err := c.Validate(testutil.Logger()); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("want an error containing %q, got %v", name, err)
		}
	}

	// no token is needed when nothing is remediated
	c = base()
	c.GitHubToken, c.RemediateCount = "", 0
	if _, _, err := c.Validate(testutil.Logger()); err != nil {
		t.Errorf("no remediation, no token: %v", err)
	}
}
