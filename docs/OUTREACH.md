# Outreach Kit — WindowsSecurityAudit

Ready-to-use texts for awesome-list PRs and community announcements. Honest, no hype — every claim is verifiable in the repo.

## awesome-powershell PR

**Title:** Add WindowsSecurityAudit — Windows security audit & DFIR toolkit (77 functions)

**Body:**

> **Project:** https://github.com/okanyildiz/WindowsSecurityAudit
>
> A comprehensive, MIT-licensed Windows security audit and DFIR PowerShell module: 77 functions across 14 categories — threat hunting (MITRE ATT&CK), compliance (CIS/NIST/PCI-DSS), vulnerability prioritization (NVD + EPSS + CISA KEV), forensics (native USN journal, offline $MFT, memory dumps), SIEM integration (Splunk HEC, Microsoft Sentinel OAuth), JEA support, Active Directory security, and hardening.
>
> Notable engineering: locale-invariant checks (correct results on non-English Windows via APIs/GUIDs/SIDs instead of localized console parsing), honest NotEvaluated states instead of silent wrong PASSes, 800+ Pester tests with real-Windows CI on both PowerShell 5.1 and 7.
>
> Install: `Install-Module -Name WindowsSecurityAudit` (PowerShell Gallery).
>
> Category suggestion: **Security / Forensics / Compliance** (or the list's closest section).

## awesome-dfir PR

**Title:** Add WindowsSecurityAudit — PowerShell DFIR toolkit for Windows hosts

**Body:**

> **Project:** https://github.com/okanyildiz/WindowsSecurityAudit
>
> An open-source (MIT) DFIR PowerShell module for Windows: native binary USN journal reading (FSCTL), offline $MFT analysis with fixup repair + deleted-record evidence, timeline CSV, memory-dump capture with ACL-locked output, artifact collection, Sysmon analytics, credential-access and defense-evasion detection, lateral-movement detection (RDP/SMB/WMI/service-creation/scheduled-tasks with MITRE technique IDs), and threat-intel correlation (abuse.ch, MISP, TAXII/STIX).
>
> All forensic parsers are locale-invariant and covered by synthetic-fixture tests that run on every OS; destructive operations support -WhatIf and ConfirmImpact=High.
>
> Install: `Install-Module -Name WindowsSecurityAudit` (PowerShell Gallery).
>
> Category suggestion: **Forensics Tools / Windows**.

## Short community announcement (r/PowerShell, r/netsec, r/blueteamsec, LinkedIn)

> **WindowsSecurityAudit v1.9.1 — open-source Windows security audit & DFIR PowerShell module (MIT)**
>
> 77 functions: MITRE-mapped threat hunting, CIS/NIST/PCI compliance, EPSS + CISA KEV vulnerability prioritization, native USN journal + offline $MFT forensics, SIEM (Splunk/Sentinel OAuth), JEA.
>
> What makes it different: every check is locale-invariant (works correctly on Turkish/German/French Windows) and it reports honest "unable to evaluate" states instead of silent wrong PASSes. 800+ tests, real-Windows CI on PS 5.1 and 7.
>
> `Install-Module -Name WindowsSecurityAudit`
> https://github.com/okanyildiz/WindowsSecurityAudit
>
> Feedback and first contributions welcome — there are three `good first issue` tickets open (Firefox artifact collection, a Turkish locale fixture, and new CPE mappings).

## 30-second demo script (asciinema)

```powershell
# 1) Install and import
Install-Module -Name WindowsSecurityAudit
Import-Module WindowsSecurityAudit

# 2) Baseline score in seconds
Get-SecurityBaseline | Select-Object SecurityScore

# 3) One consolidated interactive HTML report (severity doughnut + category bars)
New-ConsolidatedReport -OutputPath .\report.html

# 4) Prioritize a CVE with EPSS + CISA KEV
Get-VulnerabilityAssessment -IncludePriority | Select-Object -ExpandProperty PrioritizedVulnerabilities -First 5

# 5) Forensics: native USN journal + offline MFT timeline
Get-FileSystemJournal -Mode USNJournal -MaxRecords 50
Get-FileSystemJournal -Mode OfflineMftAnalysis -MftPath .\MFT-sample.bin -TimelineCsvPath .\timeline.csv
```
