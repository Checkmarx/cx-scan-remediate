# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial repository setup: license, code of conduct, contribution guidelines, security policy,
  maintainers/code owners, issue and pull request templates, DCO check, and Checkmarx One scan workflow.
- The `cxscanremediate` tool and the `scan_and_check.sh` / `scan_and_check.ps1` pipeline scripts,
  imported from the proof-of-concept repository `cx-michael-kubiaczyk/cx1-scan-remediate` at v0.0.15
  (commit `b50b750`). Its flags, environment variables, log output and exit codes are unchanged.
- CI (gofmt, build, vet, test) and goreleaser release workflows.

### Changed
- The Go module is `github.com/Checkmarx/cx-scan-remediate`, and the code follows the standard
  layout: `cmd/cxscanremediate` and packages under `internal/` (see the
  [code layout](docs/usage.md#code-layout)).
- The pipeline scripts download the tool from `Checkmarx/cx-scan-remediate` releases by default
  (override with `CXSR_RELEASE_REPO`).
- The usage guide holds the full documentation of the tool and the scripts.
