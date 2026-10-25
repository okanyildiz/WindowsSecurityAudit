# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `CHANGELOG.md`, `SECURITY.md`, and a PowerShell Gallery publish workflow (`.github/workflows/publish.yml`).
- Real module manifest metadata (author, license/project URIs, gallery tags) in `WindowsSecurityAudit.psd1`.

### Changed

- `Get-CloudComplianceStatus` no longer reports fabricated `Compliant`/`Non-Compliant` results. Controls are returned with `Status = 'NotEvaluated'` until framework-specific Microsoft Graph/API evaluation is implemented, and the compliance score is `$null` when no controls were actually evaluated.

## [1.3.0] - 2026-10-25

### Added

- `Resolve-CpeName` (Vulnerability): resolve an installed product to a CPE 2.3 name via a curated offline mapping table (~35 common products), an optional NVD CPE API lookup (`-UseOnlineLookup -ApiKey`), or a heuristic guess (always Low confidence).
- `Invoke-SecurityRemediation` (Hardening): apply a curated map of 7 safe remediations (firewall profiles, UAC, Defender real-time protection, SMBv1, Guest account, PowerShell script block logging, RDP NLA) from assessment findings, WhatIf-first with `SupportsShouldProcess`, optional `-GenerateRollback` script; unmatched findings go to `ManualReview`.
- `Get-VulnerabilityAssessment -ExactCVEMatch`: version-exact NVD CVE matching via CPE names, with per-application `ExactCVEs` and summary counts.
- `Get-ThreatIntelligence` MISP (`-MISPUrl -MISPApiKey`), TAXII 2.x (`-TaxiiServerUrl -TaxiiCollection`, `SecureString` password), and offline STIX 2.x bundle (`-StixFilePath`) indicator sources.
- Pester suite grew to 353 tests, covering v1.3 parameter help, secret-handling AST checks, and remediation safety.

## [1.2.0] - 2026-10-25

### Added

- `Get-NVDCveData` (Vulnerability): query the NVD API 2.0 by keyword or CPE name with pagination, rate-limit handling, and an optional API key.
- `Get-VulnerabilityAssessment -CheckCVEs -NVDApiKey -MaxCVEChecks`: match installed software against real NVD CVE data (keyword-based candidate matching); matched CVEs attach as `RealCVEs` per application.
- `Get-ThreatIntelligence -UpdateFeeds`: merge live abuse.ch feeds (URLhaus payload URLs, Feodo Tracker C2 IPs) plus an optional AbuseIPDB blacklist into the IOC database, with freshness-aware caching, offline fallback, and per-feed statistics.
- Pester suite grew to 333 tests.

## [1.1.0] - 2026-10-25

### Added

- `Compare-SecurityBaseline` (Core): detect configuration drift between two security baselines with Improved/Degraded/New/Removed classification and JSON/CSV export.
- `Register-ScheduledSecurityScan` (Enterprise): recurring daily/weekly/monthly scans via Scheduled Tasks with Teams/Slack webhook and email alerting on Critical findings.
- `Export-AttackNavigatorLayer` (Threat Hunting): export hunt findings as a MITRE ATT&CK Navigator layer (JSON v4.x) with severity-based scoring and colors.
- `New-ConsolidatedReport` (Reporting): single interactive Chart.js HTML report combining results from all modules, with offline mode from saved JSON.
- `Invoke-SecurityAssessment -IncludeCompliance`, `Get-ExposedServices -CustomPorts`, `Get-ComplianceReport -IncludeEvidence`, `New-ExecutiveReport -CustomLogo`, `Export-SecurityReport -IncludeCharts`.
- Pester test suite (`tests/WindowsSecurityAudit.Tests.ps1`) covering the public API surface.
- GitHub Actions CI (`.github/workflows/ci.yml`) on windows-latest: PSScriptAnalyzer Error gate and module import verified under both PowerShell 7 and Windows PowerShell 5.1.

### Fixed

- Approximately 100 strict-mode and runtime bugs across the module.

## [1.0.0] - 2025-10-10

### Added

- Initial release: 58 functions across 14 category modules, dot-sourced by `WindowsSecurityAudit.psm1`, targeting Windows PowerShell 5.1+.
- Core Security: `Get-SecurityBaseline` (0-100 posture score), `Get-SystemInfo`, `Test-SystemIntegrity` (SFC/DISM), `Get-EventIdDescription`.
- Threat Detection: persistence mechanisms, suspicious processes, network anomalies, authentication attack detection (brute force, lockouts, after-hours).
- Threat Hunting: APT indicators, data exfiltration, lateral movement, LOLBins abuse, MITRE ATT&CK mapping, IOC matching (incl. custom IOC files).
- Compliance: CIS Benchmark, NIST 800-53, and PCI-DSS 4.0 validation with audit-ready evidence export.
- Vulnerability Management: CVE assessment, EOL software, exposed services, certificate health, patch compliance.
- Active Directory: backdoor and DCSync detection, privileged account audit, stale objects, password policies, security posture.
- Forensics & Response: memory dumps, USB history, execution artifacts, forensic timelines, one-command incident response.
- Enterprise & Reporting: multi-system parallel scanning, executive reports, live HTML dashboards, security metrics and KPIs.
- Cloud Security: Azure AD risky sign-ins, M365 security posture, cloud compliance status.
- Hardening: audit policies, PowerShell security (logging, transcription), security baseline enforcement — all with `-WhatIf` support.

[Unreleased]: https://github.com/okanyildiz/WindowsSecurityAudit/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.3.0
[1.2.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.2.0
[1.1.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.1.0
[1.0.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.0.0
