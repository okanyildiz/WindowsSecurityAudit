# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.6.0] - 2026-10-26

### Added

- Locale-invariant Windows support: new internal helpers in `Private/` replace all localized console-output parsing with APIs, GUIDs and SIDs, so the module produces correct results on non-English Windows (Turkish, German, French, ...):
  - `Get-AuditPolicyTable`: advanced audit policy via `AuditQuerySystemPolicy` P/Invoke (GUID-keyed, privilege-failure aware), falling back to `auditpol /backup` fixed-header CSV parsing (numeric Setting Value, German-fixture tested) and GUID-addressed `auditpol /get` with honest "unknown" instead of guessing from localized text. Includes the full 59-subcategory GUID map (MS-GPAC).
  - `Get-LocalPasswordPolicy`: password/lockout policy via `NetUserModalsGet` (levels 0+3, non-admin, locale-invariant) with an elevated `secedit /export` fallback that also covers `PasswordComplexity`/`ClearTextPassword`.
  - `Get-WlanProfileList`: WLAN profiles via `wlanapi.dll` P/Invoke instead of localized `netsh wlan show profiles` output; missing WLAN service/feature is "not applicable", not an error.
  - Identity helpers: `Get-AdminGroupMembers` (SID-first with ADSI fallback, 32-bit-PowerShell and unresolvable-SID safe), `Get-LocalUserByRid` (RID 500/501 instead of localized names), `Test-IdentityReferenceIsSid`, `Get-WellKnownSid`.
- Locale regression test suite (`tests/Locale.Regression.Tests.ps1`): English/German (ANSI cp1252) auditpol fixture equivalence tests and a static "no text readers" guard that fails the build if localized-output parsing (`auditpol /get`, `net accounts`, name-based group/user lookups, string identities in ACL rules) ever re-enters the codebase.

### Fixed

- Silent false PASS on non-English Windows across compliance checks: `Guest`/`Administrator` account checks (PCI 7.1.1, CIS 2.3.1.1/2.3.1.5, NIST AC-2) and `Administrators` group membership checks (Invoke-SecurityAssessment, Get-MultiSystemAudit, Invoke-EnterpriseSecurityScan) failed closed-by-accident (lookup exception swallowed → "0 admins"/"disabled" → pass). All now SID/RID-based and report an honest "unable to determine" state on lookup failure.
- Audit policy checks (PCI 10.2.1/10.3.1, NIST AU-2/AU-12, CIS 17.1.1/17.2.1/17.5.1) and password policy checks (PCI 8.2.3/8.2.4, NIST IA-2/IA-5) never matched on localized `auditpol`/`net accounts` output.
- `Enable-AuditPolicies`: `auditpol /set` now uses subcategory GUIDs (worked only on English Windows before); post-change verification no longer parses localized text; file/registry SACLs for "Everyone" use SID `S-1-1-0` (audit rules were silently never applied on non-English systems).
- ACL lockdowns of the scheduled-scan script (embeds the webhook secret) and of memory dumps (potentially credential-bearing) threw `IdentityNotMappedException` on non-English Windows and left the files world-readable — now SID-based (`S-1-5-18`, `S-1-5-32-544`) with post-`Set-Acl` verification for dump files.
- `Get-SecurityMisconfigurations` world-writable check and `Get-RegistryAnalysis` permissive-ACL check matched localized identity names ('Everyone'/'Users') and never fired on non-English systems — now SID-based.
- `Find-DefenseEvasion` Defender 5007 severity keyed off localized event message text — now uses the structured registry-path property.
- `Get-FileSystemJournal`: elevation/permission detection now uses `$LASTEXITCODE` instead of English error text; localized fsutil output produces an explicit warning instead of silently empty forensic evidence; timestamp parsing is invariant-culture only.
- `Test-SystemIntegrity`: SFC/DISM verdicts no longer rely on localized English sentences — exit codes plus locale-stable CBS.log `[SR]`/`Cannot repair` markers are primary.
- `Set-SecurityBaseline`: `net accounts`/`bcdedit` failures are now surfaced via `$LASTEXITCODE` warnings instead of silently passing.
- `Find-APTIndicators`: service matching uses the non-localized service `Name` only, not the SCM-localized `DisplayName`.

## [1.5.0] - 2026-10-25

### Added

- `Send-SiemEvent`: live streaming of findings to Splunk HEC, Microsoft Sentinel (HMAC-SHA256 SharedKey signature), or generic webhooks, with batching and exponential-backoff retries; `Export-SecurityReport -StreamTo` integration.
- `Get-SysmonAnalytics`: Sysmon Operational log detections (process chains, network beaconing, image loads, LSASS access, file creates, registry events, DNS).
- `Get-FileSystemJournal`: USN journal parsing, MFT summary, and heuristic timestomp detection via fsutil.
- `Invoke-EnterpriseSecurityScan -UseModuleFunctions`: deploys and runs the real module functions on remote hosts (`-RemoteFunctionSet Quick/Standard/Deep`), parallel connectivity probes, per-host timeouts, `-TargetFile` input.
- Alert deduplication in `Register-ScheduledSecurityScan`: fingerprint state file, New/Persisting/Resolved classification, `-RealertAfterDays`, `-DisableAlertDedup`.
- TAXII 2.x pagination and MISP attribute expansion to 12 types in `Get-ThreatIntelligence`.
- `Resolve-CpeName`: curated table grown to ~120 products, vendor version-scheme translation (Java/.NET/Python).

### Security

- Refuse to send SIEM tokens over cleartext HTTP; TLS 1.2 floor in the generated scheduled-scan script; generated scan script ACL-locked to SYSTEM + Administrators (webhook secret protection); remote temp-path validation before remote copy/cleanup; CSV formula-injection escaping in forensic exports.

## [1.4.0] - 2026-10-25

### Added

- `ConvertTo-SiemEvent` and `Export-SecurityReport -Format NDJSON|CEF` (one event per finding) plus `-NoAutoOpen`.
- `Get-CredentialAccessEvents`: Kerberoasting, TGT anomalies, 4771 spray, golden-ticket heuristic, optional LSASS access monitoring; `Find-SuspiciousAuthentication` 4624 Type 9 and NTLM indicators.
- `Find-DefenseEvasion`: AMSI/ETW tamper patterns, Defender exclusion/tamper changes, log-clearing attribution, log-gap analysis.
- `Get-UserActivityArtifacts`: Recycle Bin $I parsing, LNK resolution, JumpList enumeration, Timeline DB copy; `Get-ArtifactCollection` SHA256-at-acquisition, raw registry hives, acquisition log.
- `CHANGELOG.md`, `SECURITY.md`, gallery publish workflow, real manifest metadata.

### Changed

- `Get-CloudComplianceStatus` no longer fabricates compliance statuses (honest NotEvaluated).
- ~30 zero-defect audit fixes across all modules (strict-mode scalar counts, ROT13 decoder, DCSync whitelist, event indexes, ShouldProcess coverage, localization-safe account lookups).

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
