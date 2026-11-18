# Security Policy

Checkmarx takes the security of this project seriously. Thank you for helping us keep it and its users safe.

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues, discussions or pull requests.**

Report them privately through one of the following channels:

- **Vulnerability reporting form:** [Checkmarx Support Portal](https://support.checkmarx.com/CheckmarxCustomerServiceCommunity/s/login/) — open a case and select this project.
- **Checkmarx disclosure policy:** follow the organization-wide process in
  [Checkmarx/.github SECURITY.md](https://github.com/Checkmarx/.github/blob/main/SECURITY.md).

Please include as much of the following as you can:

- The type of issue (for example, token exposure, injection, privilege escalation)
- The affected file(s), version or commit, and configuration
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code, if available
- The impact of the issue and how an attacker might exploit it

## What to Expect

- We acknowledge receipt of your report within **3 business days**.
- We investigate, keep you informed of progress, and may ask for more information.
- Once a fix is available, we release it and credit you in the release notes, unless you prefer to remain anonymous.

Please give us reasonable time to address the issue before any public disclosure.

## Supported Versions

Security fixes are applied to the latest released version. Please upgrade to the latest release before reporting.

## Security Practices in This Repository

- Every pull request and the default branch are scanned by Checkmarx One (SAST, SCA, IaC Security) — see
  [`.github/workflows/checkmarx-one-scan.yml`](.github/workflows/checkmarx-one-scan.yml).
- Secrets are blocked locally with a [gitleaks](https://github.com/gitleaks/gitleaks) pre-commit hook.
- All commits must be signed and carry a DCO `Signed-off-by` trailer.
- All changes to the default branch require a reviewed pull request approved by a code owner.
