# Checkmarx One Scan & Remediate

[![CI](https://github.com/Checkmarx/cx-scan-remediate/actions/workflows/ci.yml/badge.svg)](https://github.com/Checkmarx/cx-scan-remediate/actions/workflows/ci.yml)
[![Checkmarx One Scan](https://github.com/Checkmarx/cx-scan-remediate/actions/workflows/cx-one-scan.yaml/badge.svg)](https://github.com/Checkmarx/cx-scan-remediate/actions/workflows/cx-one-scan.yaml)
[![DCO](https://github.com/Checkmarx/cx-scan-remediate/actions/workflows/dco.yml/badge.svg)](https://github.com/Checkmarx/cx-scan-remediate/actions/workflows/dco.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE.txt)

Find, triage and fix security findings automatically in your CI/CD pipeline.

- Runs a **Checkmarx One** scan in CI/CD, then triggers **Checkmarx One AI Triage** and **AI Remediation**
  for prioritized **SAST** and **SCA** findings.
- Opens a **GitHub pull request for each generated fix**, so developers can review and merge remediations.

## How It Works

1. **Scan**: a Checkmarx One scan (SAST + SCA) runs against the repository in your pipeline.
2. **Triage**: Checkmarx One AI Triage prioritizes the findings.
3. **Remediate**: Checkmarx One AI Remediation generates fixes for the prioritized findings.
4. **Review**: each fix is opened as its own GitHub pull request for developers to review and merge.

## Prerequisites

- A Checkmarx One tenant with AI Triage and AI Remediation enabled
- Checkmarx One API credentials stored as CI secrets
- A GitHub token allowed to create branches and pull requests in the target repository

## Usage

See the [Usage Guide](docs/usage.md) for setup, configuration and examples.

## Contributing

We welcome contributions. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our
[Code of Conduct](docs/CODE_OF_CONDUCT.md) first. All commits must be signed and signed off (DCO).

## Security

Please **do not** report security vulnerabilities in public issues. See [Checkmarx Security Policy](https://github.com/Checkmarx/.github/blob/main/SECURITY.md).

## Support

- Bugs and feature requests: [GitHub Issues](https://github.com/Checkmarx/cx-scan-remediate/issues)
- Maintainers and contacts: [MAINTAINERS.md](MAINTAINERS.md)
- Product support: [Checkmarx Support Portal](https://support.checkmarx.com/CheckmarxCustomerServiceCommunity/s/)

## License

Licensed under the [Apache License 2.0](LICENSE.txt).
