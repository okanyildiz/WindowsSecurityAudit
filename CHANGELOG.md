# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.6.2] - 2026-10-29

Verified-fix release driven by an independent post-release audit (every item reproduced before fixing; one commit per item).

### Fixed

- Compliance percentages no longer hide unevaluable controls: `NotEvaluated` (tool could not read the data) stays in the denominator and never counts as compliant; `Manual` (human verification by design) is excluded and listed separately; new `CoveragePercentage` + `EvaluatedControls`; CIS `Summary.NotApplicable` no longer stores the Manual count; `Get-ComplianceReport` passes the new fields through and renders null percentages as N/A. (PCI previously showed 100% with 8 of 18 requirements unevaluated; CIS 100% with 8 of 15.)
- `Get-SecurityMetrics`: `RiskLevel`/`ThreatLevel` report `Unknown` when data is missing (majority collector failure, or all detection collectors failed) instead of `Low`/`Minimal`; new `ScoreConfidence` field (Full/Partial/Insufficient); partial-data warning notes the score is an upper bound.
- `Register-ScheduledSecurityScan`: fail-closed — pre-existing output folder/script ownership is verified (SID-based), script owner set to Administrators, and if the ACL lockdown fails the webhook-secret-bearing script is NOT written and the task NOT registered (previously warn-and-continue).
- `Invoke-SecurityRemediation -WhatIf` writes nothing to disk anymore; the rollback preview is returned in the new `RollbackPreview` result property (WhatIf contract).
- `Test-SystemIntegrity`: the SFC branch no longer prints "Attempting to repair..." without running anything — it emits honest `RepairGuidance` (DISM RestoreHealth then sfc /scannow); `RepairAttempted` is set only where DISM RestoreHealth actually runs.
- `New-ExecutiveReport`: `-IncludeCharts`/`-Audience` now warn that they are recorded but not implemented.
- CSV formula injection: v1.6.1 notes said all compliance CSV exports were escaped; `Export-ComplianceEvidence`, `Get-ComplianceReport` and 21 other exports were not. All now pipe through `ConvertTo-CsvSafeObject` (new shared helper with Pester coverage).
- `Test-PCI-DSS` renamed to `Test-PciDssCompliance` (the double-hyphen function name triggered PowerShell's 'restricted characters' warning on every import); `Test-PCI-DSS` remains as a backward-compatible alias.
- `Get-SecurityBaseline`: score weights now sum to 100 (BitLocker budget 20, proportional to protected volumes) — fully-hardened machines score 100.
- psd1 Description is pure ASCII (PS 5.1 parse safety) and the locale-invariance claim is scoped to core checks with the `Get-FileSystemJournal` fsutil exception; README function tables no longer list features the code does not have; paid-services sections removed (project is MIT + Buy Me a Coffee); static test-count badges replaced with CI-gated wording.
- New regression guards: BOM guard (non-ASCII files must be UTF-8 BOM), compliance-honesty scenarios pinned (PCI 83.33%/coverage, CIS 53.85%), import-without-restricted-characters test, alias test.

## [1.6.1] - 2026-10-27

Post-release audit hardening. Every finding below was verified against the code by independent reviewers before fixing.

### Security

- `Invoke-IncidentResponse`: network isolation now requires `-IsolateSystem` explicitly — `-Severity Critical` alone no longer disables all network adapters (WinRM lockout risk); ConfirmImpact='High' added here and in `Set-SecurityBaseline`, `Enable-PowerShellSecurity`, `Update-DefenderConfiguration`.
- `Export-MemoryDump`: SupportsShouldProcess + ConfirmImpact='High'; dump files are ACL-locked (SYSTEM+Administrators) BEFORE content is written, not after (credential-bearing dumps were world-readable during the write window).
- `Register-ScheduledSecurityScan`: the generated scan script (embeds the webhook secret) is ACL-locked before content is written.
- CSV formula-injection escaping (`Protect-CsvField`) across all forensic/incident/compliance CSV exports; HTML encoding (`ConvertTo-HtmlEncoded`) for UPN/IP/process/computer names in HTML reports; Chart.js pinned to 4.4.0 with SRI integrity hash in both HTML reports.

### Fixed

- `Test-M365SecurityPosture`: removed hardcoded Pass/Fail/Warning results — checks now query Microsoft Graph where possible (Conditional Access, Security Defaults) or honestly report NotEvaluated; score computed only over evaluated checks, null when nothing could be evaluated.
- `Get-SecurityMetrics`: no longer reports 100/Excellent when collectors fail — DataCompleteness reported, >50% collector failure → score null/Unknown, any failure caps health at Good.
- `Get-ThreatIntelligence`: domain/host IOCs now actually correlate (DNS client cache + Sysmon event 22) and hash IOCs are matched against running-process image hashes; new SourcesChecked transparency list.
- `Get-MemoryAnalysis`: replaced the structurally-dead hollowing check with an honest system-process name/image-location heuristic.
- Compliance (CIS/NIST/PCI): controls no longer vanish when a cmdlet is missing (inflating percentages) — they report Manual/NotApplicable with the reason; NIST AC-7 reads the real lockout policy via Get-LocalPasswordPolicy, AC-11 rejects 0, AU-9 no longer reports Compliant on unreadable ACLs; dead -Level/-Revision/-Version parameters now warn and label accurately.
- `Invoke-SecurityAssessment`: WDAC audit mode (1) is no longer reported as Enforced (2); failed port/share/user queries no longer score as Pass; strict-mode crash on a single restore point fixed; -AssessmentType warns it currently runs identical checks.
- Strict-mode crashes fixed in `Get-SecurityBaseline` (-ExportPath `$ComputerName_`), `Get-MultiSystemAudit` (clean hosts no longer abort the run), `Get-EventLogAnalysis` (single matching event).
- `Get-SecurityBaseline`: BitLocker points awarded proportionally (fully-encrypted single-disk machines can reach 100); -ComputerName honestly warns it labels only.
- `Invoke-SecurityRemediation -WhatIf` now generates the rollback script preview as documented.
- `Test-SystemIntegrity`: SFC/DISM verdicts no longer parse localized English text — exit codes + timestamp-correlated CBS.log markers only (locale-independence claim is now true).
- `Find-LateralMovement`/`New-ForensicTimeline`: hitting -MaxEvents now warns loudly and flags Truncated.
- `Get-USBHistory`: LastConnected no longer duplicates the install date (reported as unknown).
- Packaging: manifest exports the explicit 72-function list (Gallery metadata/autoload), psd1 is UTF-8 BOM (PS 5.1 safe), CompatiblePSEditions added, honest dependency description; loader no longer swallows file-load errors (partial loads warn loudly and export only what loaded); quiet import (Write-Verbose); publish workflow stages a clean package (no tests/.github/helper scripts) and fails on tag/manifest version mismatch.
- README: all unverifiable marketing claims and inflated feature descriptions replaced with audited, code-verified wording.

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

[Unreleased]: https://github.com/okanyildiz/WindowsSecurityAudit/compare/v1.6.2...HEAD
[1.6.2]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.6.2
[1.6.1]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.6.1
[1.6.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.6.0
[1.5.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.5.0
[1.4.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.4.0
[1.3.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.3.0
[1.2.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.2.0
[1.1.0]: https://github.com/okanyildiz/WindowsSecurityAudit/releases/tag/v1.1.0
[1.0.0]: https://github.com/okanyildiz/WindowsSecurityAudit
