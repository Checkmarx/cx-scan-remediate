package findings

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestNormalizeState(t *testing.T) {
	for in, want := range map[string]string{
		"TO_VERIFY":                "TO_VERIFY",
		" confirmed ":              "CONFIRMED",
		"Proposed Not Exploitable": "PROPOSED_NOT_EXPLOITABLE",
		"not-exploitable":          "NOT_EXPLOITABLE",
		"urgent":                   "URGENT",
	} {
		if got := NormalizeState(in); got != want {
			t.Errorf("NormalizeState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveState(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)

	for _, s := range []string{"TO_VERIFY", "NOT_EXPLOITABLE", "PROPOSED_NOT_EXPLOITABLE", "CONFIRMED", "URGENT"} {
		if got := ResolveState(logger, "t", s, "TO_VERIFY"); got != s {
			t.Errorf("ResolveState(%q) = %q", s, got)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected warnings for known states: %s", buf.String())
	}

	if got := ResolveState(logger, "t", "Proposed Not Exploitable", "TO_VERIFY"); got != "PROPOSED_NOT_EXPLOITABLE" {
		t.Errorf("got %q", got)
	}

	// unknown and empty values keep the fallback and warn
	for _, bad := range []string{"", "EXPLOITABLE", "false_positive"} {
		buf.Reset()
		if got := ResolveState(logger, "t", bad, "CONFIRMED"); got != "CONFIRMED" {
			t.Errorf("ResolveState(%q) = %q, want fallback", bad, got)
		}
		if !strings.Contains(buf.String(), "level=warning") {
			t.Errorf("expected a warning for %q, got %q", bad, buf.String())
		}
	}
}

func TestIsVerifiedOnlyConfirmedOrUrgent(t *testing.T) {
	for state, want := range map[string]bool{
		"CONFIRMED": true, "URGENT": true,
		"TO_VERIFY": false, "NOT_EXPLOITABLE": false, "PROPOSED_NOT_EXPLOITABLE": false,
	} {
		if got := IsVerified(&Finding{State: state}); got != want {
			t.Errorf("IsVerified(%s) = %v, want %v", state, got, want)
		}
	}
}

func TestCanTriage(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})

	cases := []struct {
		name string
		f    Finding
		want bool
	}{
		{"sast to_verify", Finding{Engine: "sast", State: "TO_VERIFY", SimilarityID: "1"}, true},
		{"sast confirmed", Finding{Engine: "sast", State: "CONFIRMED", SimilarityID: "1"}, false},
		{"sca complete", Finding{Engine: "sca", State: "TO_VERIFY", SimilarityID: "1", PackageID: "Npm-x-1.0"}, true},
		{"sca no package id", Finding{Engine: "sca", State: "TO_VERIFY", SimilarityID: "1"}, false},
		{"sca no similarity id", Finding{Engine: "sca", State: "TO_VERIFY", PackageID: "Npm-x-1.0"}, false},
	}
	for _, c := range cases {
		if got := CanTriage(logger, &c.f); got != c.want {
			t.Errorf("%s: CanTriage = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAITriageState(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	for _, c := range []struct{ exploitability, reachability, want string }{
		{"NOT_EXPLOITABLE", "REACHABLE", "PROPOSED_NOT_EXPLOITABLE"},
		{"CONFIRMED", "NOT_REACHABLE", "PROPOSED_NOT_EXPLOITABLE"},
		{"CONFIRMED", "REACHABLE", "CONFIRMED"},
		{"EXPLOITABLE", "REACHABLE", "CONFIRMED"},
		{"EXPLOITABLE", "NOT_REACHABLE", "PROPOSED_NOT_EXPLOITABLE"},
		{"false_positive", "REACHABLE", "TO_VERIFY"}, // not a state: keeps the fallback
	} {
		a := Assessment{Exploitability: c.exploitability, Reachability: c.reachability}
		if got := AITriageState(logger, "t", a, "TO_VERIFY"); got != c.want {
			t.Errorf("AITriageState(%s, %s) = %s, want %s", c.exploitability, c.reachability, got, c.want)
		}
	}
}

// the SAST API bug: triageStatus TO_VERIFY with exploitability NOT_EXPLOITABLE / attackability NOT_ATTACKABLE
func TestAITriageStateSASTInconsistency(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	for _, c := range []struct {
		name string
		a    Assessment
		want string
		warn bool
	}{
		{"to_verify, not exploitable and not attackable", Assessment{"TO_VERIFY", "REACHABLE", "NOT_EXPLOITABLE", "NOT_ATTACKABLE"}, "PROPOSED_NOT_EXPLOITABLE", true},
		{"to_verify, only not attackable", Assessment{"TO_VERIFY", "REACHABLE", "", "NOT_ATTACKABLE"}, "PROPOSED_NOT_EXPLOITABLE", true},
		{"to_verify, only not exploitable", Assessment{"TO_VERIFY", "REACHABLE", "NOT_EXPLOITABLE", ""}, "PROPOSED_NOT_EXPLOITABLE", true},
		{"to_verify, exploitable and attackable", Assessment{"TO_VERIFY", "REACHABLE", "EXPLOITABLE", "ATTACKABLE"}, "TO_VERIFY", false},
		{"to_verify, nothing else said", Assessment{Exploitability: "TO_VERIFY", Reachability: "REACHABLE"}, "TO_VERIFY", false},
		{"confirmed despite not exploitable: warn, keep", Assessment{"CONFIRMED", "REACHABLE", "NOT_EXPLOITABLE", "NOT_ATTACKABLE"}, "CONFIRMED", true},
	} {
		buf.Reset()
		if got := AITriageState(logger, "t", c.a, "TO_VERIFY"); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
		if warned := strings.Contains(buf.String(), "API inconsistency"); warned != c.warn {
			t.Errorf("%s: warned=%v, want %v (%q)", c.name, warned, c.warn, buf.String())
		}
	}
	// the parked re-read path expects the same state
	if got := ExpectedStates(Assessment{"TO_VERIFY", "REACHABLE", "NOT_EXPLOITABLE", "NOT_ATTACKABLE"}); !slices.Contains(got, "PROPOSED_NOT_EXPLOITABLE") {
		t.Errorf("ExpectedStates = %v", got)
	}
}

func TestExpectedStates(t *testing.T) {
	cases := []struct {
		ex, re string
		want   []string
	}{
		{"NOT_EXPLOITABLE", "REACHABLE", []string{"PROPOSED_NOT_EXPLOITABLE", "NOT_EXPLOITABLE"}},
		{"TO_VERIFY", "NOT_REACHABLE", []string{"PROPOSED_NOT_EXPLOITABLE", "NOT_EXPLOITABLE"}},
		{"EXPLOITABLE", "REACHABLE", []string{"CONFIRMED", "URGENT"}},
		{"exploitable", "", []string{"CONFIRMED", "URGENT"}},
		{"URGENT", "", []string{"CONFIRMED", "URGENT"}},
		{"TO_VERIFY", "REACHABLE", nil},
		{"", "", nil},
		{"garbage", "", nil},
	}
	for _, c := range cases {
		got := ExpectedStates(Assessment{Exploitability: c.ex, Reachability: c.re})
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("ExpectedStates(%q, %q) = %v, want %v", c.ex, c.re, got, c.want)
		}
	}
}
