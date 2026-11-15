# Outreach Kit — WindowsSecurityAudit

Ready-to-use texts for awesome-list PRs and community announcements. Neutral, verifiable wording. Verify time-sensitive counts and issue links before publishing.

## awesome-forensics (cugu/awesome-forensics) PR

**Title:** Add WindowsSecurityAudit — PowerShell Windows security-audit and DFIR toolkit

**Suggested section:** Frameworks (alternatively Windows Artifacts → NTFS/MFT Processing for the MFT-focused entry).

**Body:**

> **Project:** https://github.com/okanyildiz/WindowsSecurityAudit
>
> An open-source (MIT) PowerShell module for Windows security auditing and DFIR: 77 functions across 14 categories — MITRE ATT&CK-mapped threat hunting, selected CIS-inspired/NIST 800-53/PCI-DSS 4.0 control checks, EPSS + CISA KEV vulnerability prioritization, native binary USN journal reading (FSCTL), offline $MFT analysis with fixup repair, timeline CSV, per-process memory-dump capture, artifact collection, Sysmon analytics, credential-access and defense-evasion detection, RDP/SMB analysis plus MITRE-tagged WMI/service-creation/scheduled-task heuristics, and threat-intel correlation (abuse.ch, MISP, TAXII/STIX). Also includes a sample JEA endpoint for curated Quick/Standard/Deep scans and Sentinel Logs Ingestion with Entra client-credentials OAuth.
>
> Engineering notes: core audit/compliance checks avoid localized console parsing through APIs, GUIDs and SIDs (English/German auditpol fixture equivalence tested); compliance checks report honest NotEvaluated states rather than counting unevaluated controls as compliant. USN and MFT binary parsers have synthetic-fixture tests designed for Windows, macOS and Linux; repository CI runs them on Windows. State-changing functions support ShouldProcess/-WhatIf, with confirmation impact varying by operation.
>
> Install: `Install-Module -Name WindowsSecurityAudit` (PowerShell Gallery).

## awesome-incident-response (meirwah/awesome-incident-response) PR

**Title:** Add WindowsSecurityAudit — PowerShell DFIR toolkit for Windows hosts

**Suggested section:** All-In-One Tools (alternatively Windows Evidence Collection).

**Body:**

> **Project:** https://github.com/okanyildiz/WindowsSecurityAudit
>
> An open-source (MIT) PowerShell module for Windows security auditing and DFIR: 77 functions across 14 categories — threat hunting (MITRE ATT&CK), selected CIS-inspired/NIST/PCI-DSS control checks, EPSS + CISA KEV vulnerability prioritization, native binary USN journal reading, offline $MFT analysis with fixup repair and timeline CSV, per-process memory dumps, artifact collection, Sysmon analytics, credential-access and defense-evasion detection, RDP/SMB analysis plus MITRE-tagged WMI/service-creation/scheduled-task heuristics, and threat-intel correlation (abuse.ch, MISP, TAXII/STIX).
>
> Notable engineering: core audit/compliance checks avoid localized console parsing through APIs, GUIDs and SIDs; compliance checks report honest NotEvaluated states rather than counting unevaluated controls as compliant; USN and MFT parsers have synthetic-fixture tests; CI runs on Windows with module import and smoke tests on both PowerShell 5.1 and 7.
>
> Install: `Install-Module -Name WindowsSecurityAudit` (PowerShell Gallery).

## Note on awesome-powershell (janikvonrotz/awesome-powershell)

The GitHub repository is archived and its README points contributors to Codeberg. Submit this project there instead (same text as awesome-forensics, section: Security).

## Short community announcement (r/PowerShell, r/netsec, r/blueteamsec, LinkedIn)

> **WindowsSecurityAudit v1.9.1 — open-source Windows security audit & DFIR PowerShell module (MIT)**
>
> 77 functions: MITRE-mapped threat hunting, selected CIS-inspired/NIST/PCI-DSS control checks, EPSS + CISA KEV vulnerability prioritization, native USN journal + offline $MFT forensics, SIEM (Splunk/Sentinel OAuth), sample JEA endpoint.
>
> What makes it different: core audit/compliance checks avoid localized console parsing through APIs, GUIDs and SIDs (English/German auditpol fixture equivalence tested), and compliance checks report honest "unable to evaluate" states instead of counting unevaluated controls as compliant. 900+ Pester tests; full suite on PowerShell 7, with module import and Windows smoke tests on both PowerShell 7 and 5.1.
>
> `Install-Module -Name WindowsSecurityAudit`
> https://github.com/okanyildiz/WindowsSecurityAudit
>
> Feedback and first contributions welcome — there are three `good first issue` tickets open (Firefox artifact collection, a Turkish locale fixture, and new CPE mappings).

## Demo outline (record with asciinema; timing depends on host and network)

```powershell
# 1) Install and import
Install-Module -Name WindowsSecurityAudit
Import-Module WindowsSecurityAudit

# 2) Baseline score
Get-SecurityBaseline | Select-Object SecurityScore

# 3) One consolidated interactive HTML report (writes a timestamped HTML file
#    into the given directory; charts require internet for the Chart.js CDN)
New-ConsolidatedReport -OutputPath .\report

# 4) Prioritize CVEs with EPSS + CISA KEV (requires internet; NVD lookups
#    can take several minutes and may be rate-limited)
Get-VulnerabilityAssessment -ExactCVEMatch -IncludePriority |
    Select-Object -ExpandProperty PrioritizedVulnerabilities -First 5

# 5) Forensics (elevated Windows): native USN journal + offline MFT timeline
Get-FileSystemJournal -Mode USNJournal -MaxRecords 50
# MFT-sample.bin = a previously acquired $MFT you supply yourself
Get-FileSystemJournal -Mode OfflineMftAnalysis -MftPath .\MFT-sample.bin -TimelineCsvPath .\timeline.csv
```
