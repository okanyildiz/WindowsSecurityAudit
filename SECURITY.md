# Security Policy

## Supported Versions

Only the latest release of WindowsSecurityAudit receives security fixes. Older versions are not maintained; please upgrade before reporting or after a fix is published.

| Version  | Supported          |
| -------- | ------------------ |
| Latest   | :white_check_mark: |
| < Latest | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities **privately** — do not open a public GitHub issue.

Preferred channels, in order:

1. **GitHub Security Advisories**: open a private advisory at
   <https://github.com/okanyildiz/WindowsSecurityAudit/security/advisories/new>
2. **Maintainer contact**: use the contact options published at <https://github.com/okanyildiz> if you cannot use Security Advisories.

### What to include

- A description of the vulnerability and its potential impact.
- The module version and PowerShell version affected.
- Steps to reproduce or a proof of concept, if available.
- Any suggested remediation, if you have one.

### Response expectations

- **Acknowledgement**: within 7 days of the report.
- **Initial assessment**: within 30 days, including whether the report is accepted or declined and why.
- **Resolution**: fixes are shipped in the next release when feasible; confirmed vulnerabilities are disclosed through a GitHub Security Advisory after a fix is available.

## Scope

WindowsSecurityAudit is a defensive auditing toolkit: its functions run read-oriented security checks against Windows systems and cloud tenants. Findings about the module's own code are in scope, for example:

- Credential or API-key exposure (keys written to logs, exported reports, or error output).
- Unsafe handling of untrusted input (feed data, STIX bundles, imported baselines).
- Fabricated audit results presented as real measurements.
- Remediation functions that change system state beyond their documented, `-WhatIf`-gated behavior.

Findings about the security posture of systems the tool *scans* are the tool's intended output, not vulnerabilities in the tool itself — please route those to the owners of the scanned systems.
