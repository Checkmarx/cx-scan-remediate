// Package findings is the domain model: the scan report results this tool handles, their
// priority order, and their triage states. It does no I/O.
package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

// Finding is one scan report result this tool handles.
type Finding struct {
	Engine       string
	Severity     string
	AlternateID  string
	SimilarityID string
	// PackageID is the SCA package identifier; only set for SCA results.
	PackageID string
	State     string
	// AI is what AI Triage said about this finding, if it was triaged in this run. It is only an
	// expectation to compare the platform's state against, never used as the state.
	AI *Assessment
	// Refreshed is true if State was last confirmed against the results re-read from the platform
	// (the finding was found in them), as opposed to being the state from the scan report.
	Refreshed bool
	// Result is the originating results.SAST / IAC / SCA entry, kept for its String() in log output.
	Result fmt.Stringer
}

// String describes the finding using the underlying result's own String(), falling back to the
// basic identifiers if no result is attached.
func (r Finding) String() string {
	if r.Result != nil {
		return r.Result.String()
	}
	return fmt.Sprintf("No linked result for %s %s %s", r.Engine, r.Severity, r.AlternateID)
}

// Key identifies a finding within a run.
func Key(f *Finding) string { return f.Engine + "/" + f.AlternateID }

// Engines records which engines the run will triage and remediate.
type Engines struct {
	SAST bool
	IAC  bool // not supported by AI Triage/Remediation yet; always false
	SCA  bool
}

// Collect returns the results of the report that this tool handles: those of an engine in scope
// with one of the severities, in the internal priority list SAST, IAC, SCA. Prioritize puts them
// in the order they are worked on.
func Collect(results *Cx1ClientGo.ScanResultSet, severities map[string]bool, engines Engines) []Finding {
	var index []Finding
	if engines.SAST {
		for _, r := range results.SAST {
			if !severities[r.Severity] {
				continue
			}
			index = append(index, Finding{
				Engine:       "sast",
				Severity:     r.Severity,
				AlternateID:  r.AlternateID,
				State:        r.State,
				SimilarityID: r.SimilarityID,
				Result:       r,
			})
		}
	}

	if engines.IAC {
		for _, r := range results.IAC {
			if !severities[r.Severity] {
				continue
			}
			index = append(index, Finding{
				Engine:       "iac",
				Severity:     r.Severity,
				AlternateID:  r.AlternateID,
				State:        r.State,
				SimilarityID: r.SimilarityID,
				Result:       r,
			})
		}
	}

	if engines.SCA {
		for _, r := range results.SCA {
			if !severities[r.Severity] {
				continue
			}
			index = append(index, Finding{
				Engine:       "sca",
				Severity:     r.Severity,
				AlternateID:  r.AlternateID,
				State:        r.State,
				SimilarityID: r.SimilarityID,
				Result:       r,
				PackageID:    r.Data.PackageIdentifier,
			})
		}
	}
	return index
}

// Prioritize normalizes the state each finding has in the report (see ResolveState) and sorts
// the findings most severe first, with ties broken by the platform's alternate ID.
func Prioritize(logger *logrus.Logger, index []Finding) {
	for i := range index {
		index[i].State = ResolveState(logger, "Scan report entry "+index[i].String(), index[i].State, index[i].State)
	}

	slices.SortFunc(index, func(a, b Finding) int {
		sev := CompareSeverity(a.Severity, b.Severity)
		if sev != 0 {
			return sev
		}

		return cmp.Compare(a.AlternateID, b.AlternateID)
	})
}

// Pick returns pointers to the first limit findings (in the index's priority order)
// that satisfy eligible. The pointers alias index, so later state updates are visible to it.
func Pick(index []Finding, limit int, eligible func(*Finding) bool) []*Finding {
	var picked []*Finding
	for i := range index {
		if len(picked) >= limit {
			break
		}
		if eligible(&index[i]) {
			picked = append(picked, &index[i])
		}
	}
	return picked
}

// CanTriage reports whether a finding should be submitted to AI Triage: it must still be
// TO_VERIFY, and an SCA finding must carry its package identifier, which is part of the job's
// key. Without it the platform has no such job, and polling would just wait out the timeout.
func CanTriage(logger *logrus.Logger, f *Finding) bool {
	if f.State != StateToVerify {
		return false
	}
	if f.Engine == "sca" && (f.SimilarityID == "" || f.PackageID == "") {
		logger.Warnf("Skipping AI Triage for %s: the report entry has no similarity ID or package identifier", f)
		return false
	}
	return true
}

// IsVerified reports whether a finding has been confirmed as a real issue, the only states
// eligible for AI Remediation. To_Verify, Not_Exploitable and the like are never remediated.
func IsVerified(f *Finding) bool {
	return f.State == StateConfirmed || f.State == StateUrgent
}

var sevmap = map[string]int{
	"CRITICAL": 0,
	"HIGH":     1,
	"MEDIUM":   2,
	"LOW":      3,
	"INFO":     4,
}

// ParseSeverities turns a comma-separated severity list (case-insensitive) into a set of backend severity values.
func ParseSeverities(list string) (map[string]bool, error) {
	set := map[string]bool{}
	for _, s := range strings.Split(list, ",") {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := sevmap[s]; !ok {
			return nil, fmt.Errorf("unknown severity %q, expected any of CRITICAL,HIGH,MEDIUM,LOW,INFO", s)
		}
		set[s] = true
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("no severities specified")
	}
	return set, nil
}

// CompareSeverity orders severities highest first; a severity this tool does not know sorts
// after every known one.
func CompareSeverity(sev1, sev2 string) int {
	s1, ok1 := sevmap[sev1]
	s2, ok2 := sevmap[sev2]

	if ok1 && !ok2 {
		return -1
	}
	if ok2 && !ok1 {
		return 1
	}
	if !ok1 && !ok2 {
		return 0
	}

	if s1 < s2 {
		return -1
	}
	if s1 == s2 {
		return 0
	}
	return 1
}
