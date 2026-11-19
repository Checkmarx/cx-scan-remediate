// Package app runs the tool: it reads the scan report, triggers AI Triage and AI Remediation on
// the highest-priority findings, publishes each remediation as a pull request, and decides the
// process exit code.
package app

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/Checkmarx/cx-scan-remediate/internal/cli"
	"github.com/Checkmarx/cx-scan-remediate/internal/cx1ai"
	"github.com/Checkmarx/cx-scan-remediate/internal/errlog"
	"github.com/Checkmarx/cx-scan-remediate/internal/findings"
	"github.com/Checkmarx/cx-scan-remediate/internal/ghpr"
	"github.com/Checkmarx/cx-scan-remediate/internal/patch"
	"github.com/Checkmarx/cx-scan-remediate/internal/summary"
	"github.com/Checkmarx/cx-scan-remediate/internal/transport"
	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

// Process exit codes. This tool only runs after the scan has broken the pipeline's threshold,
// and nothing it does can clear that: AI Triage only ever proposes "Not Exploitable" (a human
// must still confirm), and remediations are only pull requests. So a completed run is never 0.
const (
	exitGateFailed = 1 // ran to completion; findings above threshold remain, so the pipeline must still fail
	exitUsage      = 2 // invalid flags (set by the flag package)
	exitError      = 3 // an operational failure (API, patch, or pull request error), or a fatal error
)

// exitCodeFor returns the process exit code for a run that completed: never 0.
func exitCodeFor(operationErrors int) int {
	if operationErrors > 0 {
		return exitError
	}
	return exitGateFailed
}

// run is what one run has read and done, so that finish can summarize it on every exit path.
type run struct {
	logger   *logrus.Logger
	errs     *errlog.Recorder
	counters summary.RunCounters
	// set once the report is parsed
	results    *Cx1ClientGo.ScanResultSet
	severities map[string]bool
	engines    findings.Engines
	index      []findings.Finding // the findings this tool handles; their states are the current ones
}

// finish ends the run with a non-zero exit code so the calling pipeline still fails.
func (r *run) finish(deepLink string) int {
	summary.Log(r.logger, r.results, r.severities, r.engines, r.index, r.counters)
	code := exitCodeFor(r.errs.Count())
	if code == exitError {
		r.logger.Errorf("Finished with %d error(s); exiting with code %d", r.errs.Count(), code)
	} else {
		r.logger.Warnf("Findings above the threshold remain (AI Triage only proposes a state and remediation needs a reviewed pull request); exiting with code %d so the pipeline fails", code)
	}
	r.logger.Infof("Review the results at %s", deepLink)
	return code
}

func newLogger(out io.Writer) *logrus.Logger {
	logger := logrus.New()
	// Nothing in this tool calls logger.Fatal*: failures are returned and mapped to an exit code.
	// This is only a safety net, in case a library calls it.
	logger.ExitFunc = func(int) { os.Exit(exitError) }
	logger.SetLevel(logrus.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(out)
	return logger
}

// Main runs the tool with the command line args (args[0] is the program name), logging to
// stdout, and returns the process exit code. Nothing below it exits the process.
func Main(ctx context.Context, version string, args []string, stdout io.Writer) int {
	logger := newLogger(stdout)
	r := &run{logger: logger, errs: errlog.New(logger), counters: summary.NewRunCounters()}

	logger.Infof("Starting cxscanremediate %s", version)
	cfg, err := cli.Parse(args[0], version, args[1:])
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, cli.ErrReported):
		return exitUsage // the flag package has already reported the problem
	case err != nil:
		return usageError(logger, "%s", err)
	}

	// Validate the arguments before connecting to anything or spending any AI credits.
	level, err := cli.ParseLogLevel(cfg.LogLevel)
	if err != nil {
		return usageError(logger, "Invalid --log-level: %s", err)
	}
	logger.SetLevel(level)

	severities, inScope, err := cfg.Selection()
	if err != nil {
		return usageError(logger, "Invalid %s", err) // e.g. "Invalid --severities: unknown severity ..."
	}
	if err := cfg.CheckCounts(logger); err != nil {
		return usageError(logger, "%s", err)
	}

	httpTransport, err := transport.New(cfg.Proxy, cfg.Insecure, cfg.CACert)
	if err != nil {
		return fatalError(logger, "Invalid proxy/TLS configuration: %s", err)
	}
	httpTransport.DisableKeepAlives = cfg.NoKeepAlive
	if cfg.NoKeepAlive {
		logger.Info("HTTP keep-alives disabled (--no-keep-alive)")
	}
	if cfg.Proxy != "" {
		logger.Infof("Using proxy")
	}
	if cfg.Insecure {
		logger.Warn("TLS certificate verification is DISABLED (--insecure); credentials and results can be intercepted. Prefer --ca-cert")
	}
	if cfg.CACert != "" {
		logger.Infof("Trusting additional CA certificate(s) from %s", cfg.CACert)
	}

	cxclient, err := Cx1ClientGo.NewClientWithOptions(Cx1ClientGo.Cx1ClientConfiguration{
		HttpClient:  &http.Client{Transport: httpTransport},
		Logger:      logger,
		HTTPHeaders: http.Header{"User-Agent": []string{cfg.UserAgent}},
		Auth: Cx1ClientGo.Cx1ClientAuth{
			APIKey:       cfg.APIKey,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			AccessToken:  cfg.AccessToken,
		},
		Cx1Url: cfg.BaseURI,
		IAMUrl: cfg.BaseAuthURI,
		Tenant: cfg.Tenant,
	})
	if err != nil {
		return fatalError(logger, "Error creating client: %s", err)
	}
	logger.Infof("Connected with %v", cxclient.String())

	var scan Cx1ClientGo.Scan

	// The operator chooses the report (--report-file), so it may be anywhere; it is only read.
	data, err := os.ReadFile(filepath.Clean(cfg.ReportFile))
	if err != nil {
		return fatalError(logger, "Failed to read report file %s: %s", cfg.ReportFile, err)
	}

	scanId, count, results, err := cxclient.ParseReportJSON(data)
	if err != nil {
		return fatalError(logger, "Failed to parse report file %s: %s", cfg.ReportFile, err)
	}

	scan, err = cxclient.GetScanByID(scanId)
	if err != nil {
		return fatalError(logger, "Failed to retrieve scan information for scan ID %s: %s", scanId, err)
	}
	logger.Infof("Target scan is %s", scan.String())

	deepLink := cxclient.GetBaseURL() + "/riskhub/" + scan.ProjectID

	// Pull requests are the only way remediations are delivered, so make sure they can be
	// created before any AI Triage or Remediation credits are spent.
	pr := ghpr.Options{
		Token:      cfg.GitHubToken,
		Transport:  httpTransport,
		Repo:       cfg.Repo,
		BaseBranch: cfg.BaseBranch,
		Branch:     cfg.PRBranch,
		DeepLink:   deepLink,
	}
	if cfg.RemediateCount > 0 {
		pr, err = ghpr.Preflight(ctx, logger, cxclient, &scan, pr, cfg.SourceDir)
		if err != nil {
			code := exitError
			if errors.Is(err, ghpr.ErrConfig) {
				code = exitUsage
			}
			logger.Errorf("Pull request preflight check failed: %s", err)
			return code
		}
	}

	logger.Infof("Scan has %d SAST and %d SCA", len(results.SAST), len(results.SCA))

	// remembered so that finish can report what still counts against the threshold, per engine
	r.results, r.severities, r.engines = &results, severities, inScope

	index := findings.Collect(&results, severities, inScope)
	if len(index) == 0 {
		logger.Warn("No results are in a supported engine/severity for AI Triage or Remediation; the threshold break must be resolved manually")
		return r.finish(deepLink)
	}

	logger.Infof("Parsed scan ID %s report %s: %d results found with %d in scope", scanId, cfg.ReportFile, count, len(index))
	findings.Prioritize(logger, index)
	r.index = index // the states in it are updated as the run goes on; finish summarizes them

	clientVars := cxclient.GetClientVars()
	if err := cx1ai.ApplyPollingOverrides(&clientVars, cfg.AIPollInterval, cfg.AIPollTimeout, cfg.AIDetailsPollInterval, cfg.AIDetailsPollTimeout); err != nil {
		return usageError(logger, "%s", err)
	}
	cxclient.SetClientVars(clientVars) // the library uses the details settings itself
	aiBudget := cx1ai.NewBudget(cfg.Timeout)
	if !aiBudget.Unlimited() {
		logger.Infof("AI Triage and Remediation share an overall time limit of %s", cfg.Timeout)
	}

	if cfg.TriageCount > 0 {
		r.triage(cxclient, &scan, cfg, aiBudget, clientVars)
	}
	if cfg.RemediateCount > 0 {
		r.remediate(ctx, cxclient, &scan, cfg, pr, aiBudget, clientVars)
	}
	return r.finish(deepLink)
}

// triage submits up to cfg.TriageCount To_Verify findings to AI Triage, then, if enabled, re-reads
// their states from the platform.
func (r *run) triage(cxclient *Cx1ClientGo.Cx1Client, scan *Cx1ClientGo.Scan, cfg *cli.Config, aiBudget cx1ai.Budget, clientVars Cx1ClientGo.ClientVars) {
	logger := r.logger
	candidates := findings.Pick(r.index, cfg.TriageCount, func(f *findings.Finding) bool { return findings.CanTriage(logger, f) })
	batchSize := cx1ai.ClampBatchSize(logger, "triage-batch-size", cfg.TriageBatchSize)
	logger.Infof("Will auto-triage %d results (requested %d) in batches of up to %d", len(candidates), cfg.TriageCount, batchSize)

	for batch := range slices.Chunk(candidates, batchSize) {
		if aiBudget.Expired() {
			r.errs.Errorf("Overall --timeout of %s reached; not submitting further AI Triage batches", cfg.Timeout)
			break
		}
		cx1ai.Triage(cxclient, logger, r.errs, scan, batch, aiBudget, clientVars)
	}

	if cx1ai.UseRefetchedStates && len(candidates) > 0 {
		// Whether a finding is exploitable is decided by the platform, so re-read the results
		// now that AI Triage has finished instead of interpreting its labels here.
		if err := cx1ai.RefreshStates(logger, cx1ai.FetchResultsFor(cxclient, scan.ScanID, r.severities), r.index, aiBudget, cx1ai.StateRetryDelay, time.Sleep); err != nil {
			r.errs.Errorf("Could not re-read the scan results after AI Triage (%s); findings keep the state from the scan report, so none become eligible for AI Remediation because of the triage", err)
		}
	}
}

// remediate submits up to cfg.RemediateCount Confirmed/Urgent findings that have no pull request
// branch yet to AI Remediation, and publishes each result as its own pull request.
func (r *run) remediate(ctx context.Context, cxclient *Cx1ClientGo.Cx1Client, scan *Cx1ClientGo.Scan, cfg *cli.Config, pr ghpr.Options, aiBudget cx1ai.Budget, clientVars Cx1ClientGo.ClientVars) {
	logger := r.logger
	// A finding whose branch already exists was remediated by an earlier run (its pull
	// request is open, or was closed without deleting the branch), so it is skipped and
	// the next finding takes its place.

	ghClient, owner, repo, err := ghpr.Target(pr)
	if err != nil {
		r.errs.Errorf("Cannot check for existing branches (%s); skipping AI Remediation", err)
		return
	}
	eligible := func(f *findings.Finding) bool {
		if !findings.IsVerified(f) {
			return false
		}
		branch := ghpr.BranchFor(pr, f)
		exists, err := ghpr.BranchExists(ctx, ghClient, owner, repo, branch)
		switch {
		case err != nil:
			r.errs.Errorf("Could not check whether branch %q exists for %s: %s; skipping it", branch, f, err)
			return false
		case exists:
			r.counters.BranchExists[findings.Key(f)] = true
			logger.Infof("Skipping %s: branch %q already exists in %s/%s (remediated by an earlier run); delete the branch to retry", f, branch, owner, repo)
			return false
		}
		return true
	}

	candidates := findings.Pick(r.index, cfg.RemediateCount, eligible)
	for _, c := range candidates {
		r.counters.Requested[findings.Key(c)] = true
	}
	batchSize := cx1ai.ClampBatchSize(logger, "remediation-batch-size", cfg.RemediationBatchSize)
	logger.Infof("Will auto-remediate %d results (requested %d, out of %d) in batches of up to %d", len(candidates), cfg.RemediateCount, len(r.index), batchSize)

	// Every remediation is computed in memory against the untouched source tree and published
	// as its own independent pull request, so remediations that touch the same file do not
	// interfere with one another. The source tree is never modified.
	publish := func(finding *findings.Finding, details Cx1ClientGo.AIRemediationDetails, result Cx1ClientGo.AIRemediationResult) {
		changes, err := patch.Apply(logger, details, cfg.SourceDir, cfg.KeepTemp)
		if err != nil {
			r.errs.Errorf("Skipping remediation for %s %s finding %s: %s", finding.Severity, finding.Engine, finding, err)
			return
		}
		if ghpr.Publish(logger, r.errs, result, finding, changes, pr, ghpr.BranchFor(pr, finding)) {
			r.counters.PRsOpened++
		}
	}

	for batch := range slices.Chunk(candidates, batchSize) {
		if aiBudget.Expired() {
			r.errs.Errorf("Overall --timeout of %s reached; not submitting further AI Remediation batches", cfg.Timeout)
			break
		}
		cx1ai.Remediate(cxclient, logger, r.errs, scan, batch, aiBudget, clientVars, publish)
	}
}

// usageError reports an invalid command line and returns the usage exit code. It is used before any
// network call or AI credit has been used.
func usageError(logger *logrus.Logger, format string, args ...interface{}) int {
	logger.Errorf(format, args...)
	return exitUsage
}

// fatalError logs a failure that ends the run, at FATAL level but without exiting (unlike
// logger.Fatalf), and returns the operational-error exit code.
func fatalError(logger *logrus.Logger, format string, args ...interface{}) int {
	logger.Logf(logrus.FatalLevel, format, args...)
	return exitError
}
