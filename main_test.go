package main

import (
	"slices"
	"testing"

	"github.com/Checkmarx/cx-scan-remediate/internal/findings"
	"github.com/Checkmarx/cx-scan-remediate/internal/testutil"
	"github.com/cxpsemea/Cx1ClientGo"
)

func TestClampBatchSize(t *testing.T) {
	for in, want := range map[int]int{-3: 1, 0: 1, 1: 1, 4: 4, 5: 5, 6: 5, 100: 5} {
		if got := clampBatchSize(testutil.Logger(), "x", in); got != want {
			t.Errorf("clampBatchSize(%d) = %d, want %d", in, got, want)
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

func TestExitCodeForIsNeverZero(t *testing.T) {
	if got := exitCodeFor(0); got != exitGateFailed {
		t.Errorf("exitCodeFor(0) = %d, want %d", got, exitGateFailed)
	}
	if got := exitCodeFor(2); got != exitError {
		t.Errorf("exitCodeFor(2) = %d, want %d", got, exitError)
	}
}
