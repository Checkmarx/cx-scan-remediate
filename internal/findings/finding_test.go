package findings

import (
	"slices"
	"testing"

	"github.com/Checkmarx/cx-scan-remediate/internal/testutil"
	"github.com/cxpsemea/Cx1ClientGo"
)

func TestParseSeverities(t *testing.T) {
	got, err := ParseSeverities(" critical, High,,")
	if err != nil || len(got) != 2 || !got["CRITICAL"] || !got["HIGH"] {
		t.Errorf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", " , ", "HIGH,URGENT"} {
		if _, err := ParseSeverities(bad); err == nil {
			t.Errorf("ParseSeverities(%q) should fail", bad)
		}
	}
}

func TestPick(t *testing.T) {
	index := []Finding{
		{AlternateID: "a", State: "TO_VERIFY"},
		{AlternateID: "b", State: "NOT_EXPLOITABLE"},
		{AlternateID: "c", State: "TO_VERIFY"},
		{AlternateID: "d", State: "TO_VERIFY"},
	}
	toVerify := func(f *Finding) bool { return f.State == "TO_VERIFY" }

	ids := func(fs []*Finding) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.AlternateID)
		}
		return out
	}

	if got := ids(Pick(index, 2, toVerify)); !slices.Equal(got, []string{"a", "c"}) {
		t.Errorf("limit 2: got %v", got)
	}
	// asking for more than exist (including exactly len(index)) must not run past the end
	if got := ids(Pick(index, 10, toVerify)); !slices.Equal(got, []string{"a", "c", "d"}) {
		t.Errorf("limit 10: got %v", got)
	}

	// picks alias the index so state updates made by triage are seen by the remediation selection
	picked := Pick(index, 1, toVerify)
	picked[0].State = "NOT_EXPLOITABLE"
	if index[0].State != "NOT_EXPLOITABLE" {
		t.Error("picked finding does not alias the index")
	}
}

func TestIsVerified(t *testing.T) {
	for state, want := range map[string]bool{
		"CONFIRMED": true, "URGENT": true,
		"TO_VERIFY": false, "NOT_EXPLOITABLE": false, "PROPOSED_NOT_EXPLOITABLE": false, "": false,
	} {
		if got := IsVerified(&Finding{State: state}); got != want {
			t.Errorf("IsVerified(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestCompareSeverity(t *testing.T) {
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	for i := range order {
		for j := range order {
			got := CompareSeverity(order[i], order[j])
			if (i < j && got >= 0) || (i == j && got != 0) || (i > j && got <= 0) {
				t.Errorf("CompareSeverity(%s, %s) = %d", order[i], order[j], got)
			}
		}
	}
	// a severity this tool does not know sorts after every known one
	if CompareSeverity("HIGH", "WEIRD") >= 0 || CompareSeverity("WEIRD", "HIGH") <= 0 || CompareSeverity("WEIRD", "ODD") != 0 {
		t.Error("unknown severities must sort last")
	}
}

func TestCollectAndPrioritize(t *testing.T) {
	base := func(id, severity, state string) Cx1ClientGo.ScanResultBase {
		return Cx1ClientGo.ScanResultBase{AlternateID: id, Severity: severity, State: state}
	}
	// the library's String() of a SAST result needs at least one node, as real results have
	nodes := Cx1ClientGo.ScanSASTResultData{Nodes: []Cx1ClientGo.ScanSASTResultNodes{{}}}
	results := &Cx1ClientGo.ScanResultSet{
		SAST: []Cx1ClientGo.ScanSASTResult{
			{ScanResultBase: base("s2", "HIGH", "TO_VERIFY"), Data: nodes},
			{ScanResultBase: base("s1", "HIGH", "Confirmed"), Data: nodes},
			{ScanResultBase: base("s3", "MEDIUM", "TO_VERIFY"), Data: nodes}, // severity not selected
		},
		SCA: []Cx1ClientGo.ScanSCAResult{
			{ScanResultBase: base("c1", "CRITICAL", "TO_VERIFY"), Data: Cx1ClientGo.ScanSCAResultData{PackageIdentifier: "Npm-x-1.0"}},
		},
		IAC: []Cx1ClientGo.ScanIACResult{{ScanResultBase: base("i1", "CRITICAL", "TO_VERIFY")}}, // engine not selected
	}
	sev := map[string]bool{"CRITICAL": true, "HIGH": true}

	index := Collect(results, sev, Engines{SAST: true, SCA: true})
	if len(index) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(index), index)
	}
	Prioritize(testutil.Logger(), index)

	var got []string
	for _, f := range index {
		got = append(got, f.Engine+"/"+f.AlternateID+"/"+f.State)
	}
	// most severe first, then by alternate ID; states normalized
	want := []string{"sca/c1/TO_VERIFY", "sast/s1/CONFIRMED", "sast/s2/TO_VERIFY"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if index[0].PackageID != "Npm-x-1.0" || Key(&index[0]) != "sca/c1" {
		t.Errorf("SCA finding: package %q, key %q", index[0].PackageID, Key(&index[0]))
	}

	if got := Collect(results, map[string]bool{"LOW": true}, Engines{SAST: true, SCA: true}); len(got) != 0 {
		t.Errorf("no finding has a selected severity, got %+v", got)
	}
}
