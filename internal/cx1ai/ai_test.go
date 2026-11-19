package cx1ai

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Checkmarx/cx-scan-remediate/internal/findings"
	"github.com/Checkmarx/cx-scan-remediate/internal/testutil"
	"github.com/cxpsemea/Cx1ClientGo"
)

func TestClampBatchSize(t *testing.T) {
	for in, want := range map[int]int{-3: 1, 0: 1, 1: 1, 4: 4, 5: 5, 6: 5, 100: 5} {
		if got := ClampBatchSize(testutil.Logger(), "x", in); got != want {
			t.Errorf("ClampBatchSize(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestToBuckets(t *testing.T) {
	got := toBuckets([]*findings.Finding{
		{Engine: "sast", AlternateID: "s1"},
		{Engine: "sca", AlternateID: "c1"},
		{Engine: "sast", AlternateID: "s2"},
	})
	want := []Cx1ClientGo.AIRequestBucket{
		{Engine: "sast", AlternateIDs: []string{"s1", "s2"}},
		{Engine: "sca", AlternateIDs: []string{"c1"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i].Engine != want[i].Engine || !slices.Equal(got[i].AlternateIDs, want[i].AlternateIDs) {
			t.Errorf("bucket %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func resultWith(id string) Cx1ClientGo.AIRemediationResult {
	return Cx1ClientGo.AIRemediationResult{ResultID: id, RemediationID: "rem-1"}
}

func TestSelectResult(t *testing.T) {
	failure := "model failed"
	errored := resultWith("a")
	errored.Data.Error = &failure

	details := func(rs ...Cx1ClientGo.AIRemediationResult) Cx1ClientGo.AIRemediationDetails {
		return Cx1ClientGo.AIRemediationDetails{Results: rs}
	}

	// the matching result is chosen, whatever its position
	got, err := selectResult(details(errored, resultWith("b")), "b")
	if err != nil || got.ResultID != "b" {
		t.Errorf("matching result: got %q, %v", got.ResultID, err)
	}
	// a single result is used when its ID does not match
	if got, err := selectResult(details(resultWith("other")), "b"); err != nil || got.ResultID != "other" {
		t.Errorf("single result: got %q, %v", got.ResultID, err)
	}
	// several results and no match: nothing can be chosen
	if _, err := selectResult(details(resultWith("x"), resultWith("y")), "b"); err == nil {
		t.Error("expected an error when no result matches")
	}
	if _, err := selectResult(details(), "b"); err == nil {
		t.Error("expected an error for no results")
	}
	// the finding's own result errored: it must not be replaced by another one
	if _, err := selectResult(details(errored, resultWith("b")), "a"); err == nil || !strings.Contains(err.Error(), "model failed") {
		t.Errorf("errored result: got %v", err)
	}
}

func TestApplyPollingOverrides(t *testing.T) {
	vars := Cx1ClientGo.ClientVars{AIPollingDelaySeconds: 30, AIPollingMaxSeconds: 600, AIDetailsPollingDelaySeconds: 15, AIDetailsPollingMaxSeconds: 60}
	if err := ApplyPollingOverrides(&vars, 0, 20*time.Minute, 1500*time.Millisecond, 0); err != nil {
		t.Fatal(err)
	}
	if vars.AIPollingDelaySeconds != 30 || vars.AIPollingMaxSeconds != 1200 || vars.AIDetailsPollingDelaySeconds != 2 || vars.AIDetailsPollingMaxSeconds != 60 {
		t.Errorf("unexpected %+v", vars)
	}
	if err := ApplyPollingOverrides(&vars, -time.Second, 0, 0, 0); err == nil {
		t.Error("a negative duration must be rejected")
	}
}
