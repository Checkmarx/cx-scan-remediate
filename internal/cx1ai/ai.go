// Package cx1ai drives Checkmarx One AI Triage and AI Remediation: submitting findings in
// batches, waiting for the jobs within the run's time budget, and reading the results back.
package cx1ai

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/Checkmarx/cx-scan-remediate/internal/errlog"
	"github.com/Checkmarx/cx-scan-remediate/internal/findings"
	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

// MaxBatchSize is how many results the AI Triage / AI Remediation backends are known to handle
// per request.
const MaxBatchSize = 5

// ClampBatchSize forces a user-supplied batch size into the supported 1..MaxBatchSize range.
func ClampBatchSize(logger *logrus.Logger, name string, n int) int {
	switch {
	case n < 1:
		logger.Warnf("--%s must be at least 1, using 1", name)
		return 1
	case n > MaxBatchSize:
		logger.Warnf("--%s capped at %d (requested %d)", name, MaxBatchSize, n)
		return MaxBatchSize
	}
	return n
}

// ApplyPollingOverrides sets the library's AI polling settings from the --ai-* flags: how often
// the platform is asked whether an AI Triage or AI Remediation job has finished, and how long to
// wait for one finding, and the same for fetching the result details afterwards. A zero value
// keeps the library's default; a negative one is an error. Values are rounded up to whole seconds.
func ApplyPollingOverrides(vars *Cx1ClientGo.ClientVars, interval, timeout, detailsInterval, detailsTimeout time.Duration) error {
	for _, o := range []struct {
		name string
		d    time.Duration
		dst  *int
	}{
		{"--ai-poll-interval", interval, &vars.AIPollingDelaySeconds},
		{"--ai-poll-timeout", timeout, &vars.AIPollingMaxSeconds},
		{"--ai-details-poll-interval", detailsInterval, &vars.AIDetailsPollingDelaySeconds},
		{"--ai-details-poll-timeout", detailsTimeout, &vars.AIDetailsPollingMaxSeconds},
	} {
		if o.d < 0 {
			return fmt.Errorf("%s must not be negative (got %s)", o.name, o.d)
		}
		if o.d > 0 {
			*o.dst = int(math.Ceil(o.d.Seconds()))
		}
	}
	return nil
}

// toBuckets groups findings by engine into the request format shared by the AI endpoints.
func toBuckets(batch []*findings.Finding) []Cx1ClientGo.AIRequestBucket {
	var buckets []Cx1ClientGo.AIRequestBucket
	for _, f := range batch {
		i := slices.IndexFunc(buckets, func(b Cx1ClientGo.AIRequestBucket) bool { return b.Engine == f.Engine })
		if i < 0 {
			buckets = append(buckets, Cx1ClientGo.AIRequestBucket{Engine: f.Engine})
			i = len(buckets) - 1
		}
		buckets[i].AlternateIDs = append(buckets[i].AlternateIDs, f.AlternateID)
	}
	return buckets
}

// Triage submits the findings to AI Triage in a single request, then waits for each
// in turn. The jobs run concurrently on the platform, so only the first wait is long.
func Triage(cxclient *Cx1ClientGo.Cx1Client, logger *logrus.Logger, errs *errlog.Recorder, scan *Cx1ClientGo.Scan, batch []*findings.Finding, aiBudget Budget, vars Cx1ClientGo.ClientVars) {
	for _, finding := range batch {
		logger.Infof("AI Auto-Triage %s finding: %s", finding.Severity, finding)
	}

	triageId, err := cxclient.RequestAITriages(scan.ScanID, toBuckets(batch))
	if err != nil {
		errs.Errorf("Failed to request triage: %s", err)
		return
	}
	logger.Infof("AI Triage request ID: %s", triageId)

	for _, finding := range batch {
		var status string
		var err error
		delay, max := aiBudget.PollTimeouts(vars.AIPollingDelaySeconds, vars.AIPollingMaxSeconds)
		if finding.Engine == "sca" {
			status, err = cxclient.PollSCAAITriageStatusWithTimeout(scan.ProjectID, finding.SimilarityID, finding.PackageID, delay, max)
		} else {
			status, err = cxclient.PollSASTAITriageStatusWithTimeout(scan.ProjectID, finding.SimilarityID, delay, max)
		}
		if err != nil && aiBudget.Expired() {
			errs.Errorf("Overall --timeout reached before AI Triage finished for %s (%s); its state is unchanged", finding, err)
			continue
		}
		if err != nil {
			// the job may have already finished while an earlier finding in the batch was being polled
			logger.Warnf("Failed while polling AI Triage for %s (%s); trying to fetch the result anyway", finding, err)
		} else {
			logger.Infof("AI Triage for %s finished with status: %s", finding, status)
		}

		// The AI's assessment is only logged for information: the finding's state is read back
		// from the platform once the whole triage is done (see RefreshStates).
		if finding.Engine == "sca" {
			details, err := cxclient.GetSCAAITriage(scan.ScanID, scan.ProjectID, finding.SimilarityID, finding.PackageID)
			if err != nil {
				logger.Warnf("Could not get the AI Triage assessment for %s: %s", finding, err)
				continue
			}
			logger.Infof("AI Triage results: exploitability %s, reachability %s", details.Analysis.Exploitability.Status, details.Analysis.Reachability.Status)
			finding.AI = &findings.Assessment{Exploitability: details.Analysis.Exploitability.Status, Reachability: details.Analysis.Reachability.Status}
			if !UseRefetchedStates {
				finding.State = findings.AITriageState(logger, "AI Triage of "+finding.String(), *finding.AI, finding.State)
			}
			continue
		}

		details, err := cxclient.GetSASTAITriage(scan.ProjectID, finding.SimilarityID)
		if err != nil {
			logger.Warnf("Could not get the AI Triage assessment for %s: %s", finding, err)
			continue
		}
		logger.Infof("AI Triage results: %s (reachability %s, exploitability %s, attackability %s)", details.TriageStatus, details.ReachabilityStatus, details.ExploitabilityStatus, details.AttackabilityStatus)
		finding.AI = &findings.Assessment{Exploitability: details.TriageStatus, Reachability: details.ReachabilityStatus, ExploitabilityStatus: details.ExploitabilityStatus, AttackabilityStatus: details.AttackabilityStatus}
		if !UseRefetchedStates {
			finding.State = findings.AITriageState(logger, "AI Triage of "+finding.String(), *finding.AI, finding.State)
		}
	}
}

// RemediationHandler receives a finished remediation: details holds only this finding's result,
// so whatever is built from it holds exactly that finding's fix.
type RemediationHandler func(finding *findings.Finding, details Cx1ClientGo.AIRemediationDetails, result Cx1ClientGo.AIRemediationResult)

// Remediate submits the findings to AI Remediation in a single request, then waits for each in
// turn and passes its result to onResult as soon as it is available. The jobs run concurrently
// on the platform, so only the first wait is long. Handing each result over as it finishes means
// the work completed before the --timeout budget runs out is never lost.
func Remediate(cxclient *Cx1ClientGo.Cx1Client, logger *logrus.Logger, errs *errlog.Recorder, scan *Cx1ClientGo.Scan, batch []*findings.Finding, aiBudget Budget, vars Cx1ClientGo.ClientVars, onResult RemediationHandler) {
	for _, finding := range batch {
		logger.Infof("AI Auto-Remediate finding: %s", finding)
	}

	remediationId, err := cxclient.RequestAIRemediations(scan.ScanID, scan.ProjectID, toBuckets(batch))
	if err != nil {
		errs.Errorf("Failed to request remediation: %s", err)
		return
	}
	logger.Tracef("Requested remediation id: %s", remediationId)

	for _, finding := range batch {
		delay, max := aiBudget.PollTimeouts(vars.AIPollingDelaySeconds, vars.AIPollingMaxSeconds)
		status, err := cxclient.PollAIRemediationStatusWithTimeout(scan.ScanID, finding.Engine, finding.AlternateID, delay, max)
		if err != nil && aiBudget.Expired() {
			// jobs that finished earlier still get their pull request; only this unfinished one is abandoned
			errs.Errorf("Overall --timeout reached before AI Remediation finished for %s (%s); abandoning it", finding, err)
			continue
		}
		if err != nil {
			// the job may have already finished while an earlier finding in the batch was being polled
			logger.Warnf("Failed while polling remediation for %s (%s); trying to fetch the result anyway", finding, err)
		} else {
			logger.Tracef("Remediation for %s finished with status: %s", finding, status)
		}

		details, err := cxclient.GetAIRemediationDetails(scan.ScanID, finding.AlternateID)
		if err != nil {
			errs.Errorf("Failed while retrieving remediation for %s %s finding %s: %s", finding.Severity, finding.Engine, finding, err)
			continue
		}

		result, err := selectResult(details, finding.AlternateID)
		if err != nil {
			errs.Errorf("Skipping remediation for %s %s finding %s: %s", finding.Severity, finding.Engine, finding, err)
			continue
		}
		// only this finding's result is applied, so the pull request holds exactly its fix
		details.Results = []Cx1ClientGo.AIRemediationResult{result}

		onResult(finding, details, result)
	}
}

// selectResult picks the remediation result for the finding with this alternate ID from the details
// the platform returned. The result is matched by its ID; if none matches and there is exactly one
// result, that one is used. A result that reports an error is not usable.
func selectResult(details Cx1ClientGo.AIRemediationDetails, alternateID string) (Cx1ClientGo.AIRemediationResult, error) {
	var result Cx1ClientGo.AIRemediationResult
	switch i := slices.IndexFunc(details.Results, func(r Cx1ClientGo.AIRemediationResult) bool { return r.ResultID == alternateID }); {
	case i >= 0:
		result = details.Results[i]
	case len(details.Results) == 1:
		result = details.Results[0]
	default:
		return result, fmt.Errorf("none of the %d remediation results returned is for result %s", len(details.Results), alternateID)
	}
	if result.Data.Error != nil {
		return result, fmt.Errorf("remediation %s reported an error: %s", result.RemediationID, *result.Data.Error)
	}
	return result, nil
}
