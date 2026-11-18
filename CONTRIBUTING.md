# Contributing to cx-scan-remediate

Welcome, and thank you for considering contributing to **cx-scan-remediate** (`github.com/Checkmarx/cx-scan-remediate`). It is CI/CD automation that runs a Checkmarx One scan, then uses Checkmarx One AI Triage and AI Remediation to open a pull request for each generated fix.

Reading and following these guidelines will help us make the contribution process easy and effective for everyone involved. It also communicates that you agree to respect the time of the developers managing and developing these open source projects. In return, we will reciprocate that respect by addressing your issue, assessing changes, and helping you finalize your pull requests.

## Quicklinks

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Issues](#issues)
  - [Templates](#templates)
- [Pull Requests](#pull-requests)
  - [Pull Request Template](#pull-request-template)
- [DCO Sign-off Requirement](#dco-sign-off-requirement)
- [Signed Commits Requirement](#signed-commits-requirement)
- [Code Review Requirement](#code-review-requirement)
- [Security Issues](#security-issues)
- [Resources](#resources)

## Code of Conduct

By participating and contributing to any Checkmarx projects, you agree to uphold our [Code of Conduct](/docs/CODE_OF_CONDUCT.md).

## Getting Started

If you have suggestions for how this project could be improved, or want to report a bug, open an issue. We appreciate all contributions. If you have questions, we'd love to hear them.

We also appreciate PRs. If you're thinking of submitting any PR, please open an issue first to spark a discussion around it.

Contributions are made to this repo via Issues and Pull Requests (PRs). A few general guidelines that cover both:

- Search for existing Issues and PRs before creating your own to avoid duplicates.
- PRs will only be accepted if associated with an issue (enhancement or bug) that has been submitted and reviewed/labeled as *accepted* by a Checkmarx team member.
- We will work hard to make sure issues that are raised are handled in a timely manner.

Before your first commit, install the pre-commit hooks so secrets are caught locally:

```bash
pip install pre-commit
pre-commit install
```

## Issues

Issues should be used to report problems with the solution / source code, request a new feature, or to discuss potential changes before a PR is created. When you create a new Issue, a template will be loaded that will guide you through collecting and providing the information we need to investigate.

If you find an Issue that addresses the problem you're having, please add your own reproduction information to the existing issue rather than creating a new one. Adding a [reaction](https://github.blog/news-insights/product-news/add-reactions-to-pull-requests-issues-and-comments/) can also help by indicating to our maintainers that a particular problem is affecting more than just the reporter.

### Templates

The following templates will be used within Checkmarx github repositories

- [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.yml)
- [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.yml)

## Pull Requests

PRs to our source are always welcome and can be a quick way to get your fix or improvement slated for the next release. In general, PRs should:

- Only fix/add the functionality in question **or** address code style issues, not both.
- Ensure all necessary details are provided and adhered to
- Add unit or integration tests for fixed or changed functionality (if a test suite already exists) or specify steps taken to ensure changes were tested and functionality works as expected.
- Address a single concern in the least number of changed lines as possible.
- Include documentation in the repo or Provide additional comments in Markdown comments that should be pulled/reflected in GitHub Wiki for the given project.
- Be accompanied by a complete Pull Request template (loaded automatically when a PR is created).

For changes that address core functionality or would require breaking changes (e.g. a major release), please open an Issue to discuss your proposal first.

In general, we follow the *fork-and-pull* Git workflow

1. Fork the repository to your own Github account
2. Clone the project to your machine
3. Create a branch locally with a succinct but descriptive name (prefix with feature/<issue#>-descriptive-name> or hotfix/<issue#>-descriptive-name)
4. Commit changes to the branch
5. Push changes to your fork
6. Open a PR in our repository and follow the PR template so that we can efficiently review and assess the changes. *Ensure an associated Issue has been accepted by the Checkmarx team.*

### Pull Request Template

The following template will be used within Checkmarx github repositories

[Pull Request Template](.github/pull_request_template.md)

## DCO Sign-off Requirement

All commits must include a `Signed-off-by` trailer ([Developer Certificate of Origin](https://developercertificate.org/)). The [DCO workflow](.github/workflows/dco.yml) blocks PRs that contain commits without a sign-off.

- One commit:
  - `git commit -s -m "your message"`
- Existing commit (amend sign-off):
  - `git commit --amend -s`
- Entire branch:
  - `git rebase --signoff origin/master`

## Signed Commits Requirement

All commits merged to the default branch must be cryptographically signed (GPG, SSH or S/MIME) and show as **Verified** on GitHub.

```bash
# Example: SSH signing
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

See [GitHub: Signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

## Code Review Requirement

The default branch is protected. Every change must be merged through a pull request that:

- is approved by at least one [code owner](CODEOWNERS) (see [MAINTAINERS.md](MAINTAINERS.md)),
- passes all required checks, including the [Checkmarx One scan](.github/workflows/checkmarx-one-scan.yml) and the DCO check.

## Security Issues

Do not report security vulnerabilities in public issues or PRs. Follow [SECURITY.md](SECURITY.md).

## Resources

- [How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
- [Using Pull Requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests)
- [GitHub Help](https://support.github.com/request/landing)
