# Usage Guide

> This guide is a skeleton and will be completed as the implementation lands.

## Overview

`cx-scan-remediate` runs in your CI/CD pipeline and chains three Checkmarx One capabilities:

| Stage | Checkmarx One capability | Output |
| --- | --- | --- |
| Scan | SAST + SCA scan | Findings in Checkmarx One |
| Triage | AI Triage | Prioritized findings |
| Remediate | AI Remediation | One GitHub pull request per generated fix |

## Configuration

| Setting | Description | Required |
| --- | --- | --- |
| Checkmarx One base URI | Your tenant's API base URL | Yes |
| Checkmarx One tenant | Tenant name | Yes |
| Checkmarx One credentials | Client ID/secret or API key, stored as CI secrets | Yes |
| GitHub token | Token allowed to push branches and open pull requests | Yes |

Never commit credentials. Store them as encrypted CI secrets.

## Example: GitHub Actions

_TODO: add a workflow example once the entry point is published._

## Reviewing Remediation Pull Requests

Each generated fix is opened as a separate pull request so it can be reviewed, tested and merged on its own.
Treat AI-generated fixes like any other contribution: review the diff and wait for CI, including the
Checkmarx One scan, to pass before merging.

## Troubleshooting

_TODO._
