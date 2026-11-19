package cx1ai

import (
	"io"
	"testing"

	"github.com/Checkmarx/cx-scan-remediate/internal/findings"
	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

func TestApplyFetchedStates(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	index := []findings.Finding{
		{Engine: "sca", AlternateID: "a1", State: "TO_VERIFY"},  // becomes proposed not exploitable
		{Engine: "sca", AlternateID: "a2", State: "TO_VERIFY"},  // becomes confirmed
		{Engine: "sast", AlternateID: "a1", State: "TO_VERIFY"}, // same alternate ID, other engine: unchanged
		{Engine: "sca", AlternateID: "a3", State: "TO_VERIFY"},  // platform reports an unknown state: kept
		{Engine: "sca", AlternateID: "a4", State: "CONFIRMED"},  // not returned by the platform: kept
	}
	fetched := &Cx1ClientGo.ScanResultSet{
		SCA: []Cx1ClientGo.ScanSCAResult{
			{ScanResultBase: Cx1ClientGo.ScanResultBase{AlternateID: "a1", State: "PROPOSED_NOT_EXPLOITABLE"}},
			{ScanResultBase: Cx1ClientGo.ScanResultBase{AlternateID: "a2", State: "Confirmed"}},
			{ScanResultBase: Cx1ClientGo.ScanResultBase{AlternateID: "a3", State: "EXPLOITABLE"}},
		},
		SAST: []Cx1ClientGo.ScanSASTResult{
			{ScanResultBase: Cx1ClientGo.ScanResultBase{AlternateID: "a1", State: "TO_VERIFY"}},
		},
	}

	changed, missing := applyFetchedStates(logger, index, fetched)
	want := []string{"PROPOSED_NOT_EXPLOITABLE", "CONFIRMED", "TO_VERIFY", "TO_VERIFY", "CONFIRMED"}
	for i, w := range want {
		if index[i].State != w {
			t.Errorf("finding %d: state %q, want %q", i, index[i].State, w)
		}
	}
	if changed != 2 || missing != 1 {
		t.Errorf("changed=%d missing=%d, want 2 and 1", changed, missing)
	}
	if findings.IsVerified(&index[0]) || !findings.IsVerified(&index[1]) {
		t.Error("only the finding the platform reports as CONFIRMED may be remediated")
	}
}

func TestSeverityList(t *testing.T) {
	got := severityList(map[string]bool{"HIGH": true, "CRITICAL": true, "LOW": true})
	if len(got) != 3 || got[0] != "CRITICAL" || got[1] != "HIGH" || got[2] != "LOW" {
		t.Errorf("got %v", got)
	}
}
