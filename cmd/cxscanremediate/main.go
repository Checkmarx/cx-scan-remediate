// Command cxscanremediate runs in a CI/CD pipeline after a Checkmarx One scan has broken the
// threshold: it triggers Checkmarx One AI Triage and AI Remediation on the highest-priority
// findings of the scan report and opens a GitHub pull request for each remediation.
package main

import (
	"context"
	"os"

	"github.com/Checkmarx/cx-scan-remediate/internal/app"
)

// version is the release this binary was built from. goreleaser sets it (its default ldflags
// include -X main.version={{.Version}}); a plain "go build" reports "dev". It is part of the
// default user agent, so requests can be traced to this tool in the platform logs.
var version = "dev"

func main() {
	os.Exit(app.Main(context.Background(), version, os.Args, os.Stdout))
}
