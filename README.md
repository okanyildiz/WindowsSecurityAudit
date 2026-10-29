# 🛡️ Windows Security Audit PowerShell Module

<div align="center">

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Windows](https://img.shields.io/badge/Windows-10%2F11%2FServer%202016%2B-blue.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.6.2-orange.svg)](https://github.com/okanyildiz/WindowsSecurityAudit/releases)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/WindowsSecurityAudit.svg?label=PSGallery)](https://www.powershellgallery.com/packages/WindowsSecurityAudit)
[![Functions](https://img.shields.io/badge/Functions-72-brightgreen.svg)](https://github.com/okanyildiz/WindowsSecurityAudit)
[![Modules](https://img.shields.io/badge/Modules-14-blue.svg)](https://github.com/okanyildiz/WindowsSecurityAudit)
[![CI](https://github.com/okanyildiz/WindowsSecurityAudit/actions/workflows/ci.yml/badge.svg)](https://github.com/okanyildiz/WindowsSecurityAudit/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/Tests-CI_Gated-brightgreen.svg)](https://github.com/okanyildiz/WindowsSecurityAudit/tree/main/tests)

[![GitHub stars](https://img.shields.io/github/stars/okanyildiz/WindowsSecurityAudit)](https://github.com/okanyildiz/WindowsSecurityAudit/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/okanyildiz/WindowsSecurityAudit)](https://github.com/okanyildiz/WindowsSecurityAudit/network/members)
[![GitHub watchers](https://img.shields.io/github/watchers/okanyildiz/WindowsSecurityAudit)](https://github.com/okanyildiz/WindowsSecurityAudit/watchers)

**Enterprise-Grade Windows Security Auditing & Threat Detection Toolkit**

**🧱 Dependency-Free Core • 🌍 Locale-Invariant Core Checks • 🧪 CI-Gated Test Suite • 📜 MIT Licensed**

[Features](#-full-feature-overview) • [Why](#-why-windows-security-audit-module) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Release Highlights](#-release-highlights) • [Support](#-support--contact)

</div>

---

## 🧰 Full Feature Overview

**72 functions across 14 modules** — the complete toolkit at a glance:

| Module | Functions | Scope |
|--------|:---------:|-------|
| 🧱 **Core Security** | 5 | Security baseline scoring (0-100), system inventory, SFC/DISM integrity checks, Event ID context, baseline drift diffing |
| 🕵️ **Detection** | 7 | Persistence mechanisms, suspicious processes, network anomalies, authentication attacks, credential-access events (Kerberoasting/spray/golden-ticket heuristic), defense-evasion & tamper detection, Sysmon log analytics (process chains/beaconing/LSASS access) |
| 🔬 **Analysis** | 4 | Deep-dive analysis of event logs, registry, process memory, and file system |
| 🚨 **Response** | 5 | Incident response orchestration, forensic evidence collection, HTML/JSON/CSV/NDJSON/CEF report export, SIEM event conversion, SIEM live streaming (Splunk HEC/Sentinel/webhook) |
| 🏢 **Enterprise** | 4 | Multi-system parallel scanning, full assessment orchestration, scheduled scans with Teams/Slack/email alerts |
| 🔒 **Hardening** | 4 | Audit policies, PowerShell security, baseline enforcement, curated auto-remediation (WhatIf-first, with rollback) |
| 🛡️ **Windows Defender** | 3 | Defender health monitoring, custom scans, configuration optimization |
| 🎯 **Threat Hunting** | 7 | APT indicators, data exfiltration, lateral movement, LOLBins, ATT&CK mapping/Navigator export, threat intel (MISP/TAXII/STIX) |
| ✅ **Compliance** | 5 | CIS Benchmark, NIST 800-53, PCI-DSS 4.0 validation, compliance reports, audit evidence export |
| 🌳 **Active Directory** | 6 | AD backdoors & DCSync detection, vulnerability scan, stale objects, password policies, privileged accounts, posture |
| 🩹 **Vulnerability** | 8 | CVE assessment (real NVD data + version-exact CPE matching), EOL software, exposed services, certificates, patches |
| 🔍 **Forensics** | 7 | Per-process memory dumps (ProcDump/MiniDumpWriteDump), artifact collection with SHA256-at-acquisition, execution artifacts (prefetch/UserAssist/BAM), USB history, user activity artifacts (Recycle Bin/LNK/JumpLists/Timeline), forensic timelines, USN journal/MFT summary/timestomp evidence |
| ☁️ **Cloud Security** | 3 | Azure AD risky sign-ins (Entra ID detections), M365 security posture, cloud compliance catalog (NotEvaluated until Graph queries land) |
| 📊 **Reporting** | 4 | Security metrics/KPIs, executive reports, static HTML dashboards (optional meta-refresh), consolidated Chart.js report (6 collectors; charts need internet for the CDN) |

> 👇 **Deep dive per module below** — full function-by-function tables in [Module Categories - Detailed Breakdown](#-module-categories---detailed-breakdown).

---

## ☕ Support This Project

If you find this tool valuable for your security operations, consider supporting its development:

<div align="center">

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support%20Development-yellow?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/okanyildizr)


**Your support helps maintain and improve this free tool for the security community!**

</div>

---

## 📖 Executive Summary

In today's rapidly evolving threat landscape, organizations face unprecedented challenges in maintaining robust security postures across their Windows infrastructure. Traditional security tools often fall short, requiring multiple expensive licenses, complex integrations, and specialized expertise. The **Windows Security Audit Module** addresses this by offering enterprise-grade security capabilities through a unified, open-source PowerShell framework.

The toolkit bundles **72 functions across 14 specialized modules** covering the audit lifecycle end-to-end: baseline scoring, threat detection, forensic collection, hardening, compliance validation, vulnerability assessment and reporting. Capabilities that usually require stitching together several single-purpose tools ship here as one cohesive, MIT-licensed module — with a CI-gated Pester test suite on both PowerShell 7 and Windows PowerShell 5.1, and locale-invariant core checks that return correct results on non-English Windows systems (see [Known Limitations](#-known-limitations)).

### 🎯 The Vision

Our mission is to democratize enterprise security by providing world-class security tools to organizations of all sizes. Whether you're a solo IT administrator protecting a small business or a CISO managing security for thousands of endpoints, this module provides the professional-grade capabilities you need to detect threats, validate compliance, and respond to incidents effectively.

### 💡 Why Windows Security Audit Module?

**The Problem We Solve:**

Modern enterprises typically juggle 15-20 different security tools, each with its own interface, licensing model, and learning curve. This fragmentation leads to:
- **Security Gaps**: Critical threats missed between tool boundaries
- **Operational Inefficiency**: Hours wasted switching between platforms
- **Budget Constraints**: Millions spent on overlapping capabilities
- **Skill Requirements**: Need for multiple specialized experts
- **Integration Nightmares**: Custom development for tool interoperability

**Our Solution:**

A single, cohesive PowerShell module that consolidates essential security functions into one powerful toolkit. The core audit checks are built on native Windows capabilities and run without any external dependencies; only the cloud and Active Directory modules need extra tooling (Microsoft Graph PowerShell SDK and the RSAT ActiveDirectory module, respectively).

### ✅ What You Can Verify

- **🌍 Locale-invariant core checks**: compliance, audit-policy, account and ACL checks use APIs, GUIDs and SIDs instead of parsing localized console output — correct results on Turkish, German, French and other non-English Windows (exception: `Get-FileSystemJournal`, see [Known Limitations](#-known-limitations))
- **🧪 Tested**: CI-gated Pester suite plus PSScriptAnalyzer and module-import checks on both PowerShell 7 (`pwsh`) and Windows PowerShell 5.1
- **🧱 Dependency-free core**: baseline, detection, forensics, hardening and compliance checks run on a stock Windows install
- **📜 MIT licensed**: free for commercial use, full source available

---

## 🌟 Key Differentiators

### Why Choose Us Over Alternatives?

<table>
<tr>
<th>Capability</th>
<th>Windows Security Audit Module</th>
<th>Commercial Solutions</th>
<th>Other Open Source</th>
</tr>
<tr>
<td><strong>Total Cost</strong></td>
<td>✅ Free Forever (MIT)</td>
<td>❌ Commercial licensing</td>
<td>✅ Free</td>
</tr>
<tr>
<td><strong>Functions</strong></td>
<td>✅ 72 Comprehensive</td>
<td>⚠️ 20-30 Limited</td>
<td>⚠️ 5-15 Basic</td>
</tr>
<tr>
<td><strong>Dependencies</strong></td>
<td>✅ None for core checks (native PowerShell); Graph/RSAT only for cloud & AD modules</td>
<td>❌ Multiple Agents</td>
<td>❌ Python/Ruby/Tools</td>
</tr>
<tr>
<td><strong>Enterprise Scale</strong></td>
<td>✅ Parallel multi-system scanning (up to 50 threads)</td>
<td>✅ Varies</td>
<td>❌ Limited</td>
</tr>
<tr>
<td><strong>Learning Curve</strong></td>
<td>✅ PowerShell Knowledge</td>
<td>❌ Vendor Training</td>
<td>⚠️ Multiple Skills</td>
</tr>
<tr>
<td><strong>Customization</strong></td>
<td>✅ Full Source Code</td>
<td>❌ Limited APIs</td>
<td>✅ Open Source</td>
</tr>
<tr>
<td><strong>Non-English Windows</strong></td>
<td>✅ Locale-invariant core checks (API/GUID/SID; see [Known Limitations](#-known-limitations))</td>
<td>✅ Varies</td>
<td>❌ Often parses English-only output</td>
</tr>
<tr>
<td><strong>Support</strong></td>
<td>✅ Community</td>
<td>✅ Vendor Support</td>
<td>⚠️ Community Only</td>
</tr>
</table>

---

## 📁 Project Structure

```
WindowsSecurityAudit/
│
├── 📄 WindowsSecurityAudit.psd1       # Module manifest
├── 📄 WindowsSecurityAudit.psm1       # Module loader
├── 📄 CreateProjectFolderStructure.ps1 # Setup script
├── 📄 Test-Module.ps1                  # Testing script
├── 📄 CHANGELOG.md                     # Version history
├── 📄 SECURITY.md                      # Security policy & disclosure
│
├── 📁 .github/workflows/           # CI: PSScriptAnalyzer + Pester (PS 5.1 & 7); release: gallery publish
│   ├── ci.yml
│   └── publish.yml
│
├── 📁 ActiveDirectory/                 # AD Security (6 functions)
│   ├── Find-ADBackdoors.ps1
│   ├── Find-ADVulnerabilities.ps1
│   ├── Find-StaleADObjects.ps1
│   ├── Get-ADPasswordPolicy.ps1
│   ├── Get-ADPrivilegedAccounts.ps1
│   └── Test-ADSecurityPosture.ps1
│
├── 📁 Analysis/                        # System Analysis (4 functions)
│   ├── Get-EventLogAnalysis.ps1
│   ├── Get-FileSystemAnalysis.ps1
│   ├── Get-MemoryAnalysis.ps1
│   └── Get-RegistryAnalysis.ps1
│
├── 📁 CloudSecurity/                   # Cloud Security (3 functions)
│   ├── Get-AzureADRiskySignIns.ps1
│   ├── Get-CloudComplianceStatus.ps1
│   └── Test-M365SecurityPosture.ps1
│
├── 📁 Compliance/                      # Compliance (5 functions)
│   ├── Export-ComplianceEvidence.ps1
│   ├── Get-ComplianceReport.ps1
│   ├── Test-CISBenchmark.ps1
│   ├── Test-NISTCompliance.ps1
│   └── Test-PciDssCompliance.ps1
│
├── 📁 Core/                            # Core Security (5 functions)
│   ├── Compare-SecurityBaseline.ps1
│   ├── Get-EventIdDescription.ps1
│   ├── Get-SecurityBaseline.ps1
│   ├── Get-SystemInfo.ps1
│   └── Test-SystemIntegrity.ps1
│
├── 📁 Detection/                       # Threat Detection (7 functions)
│   ├── Find-DefenseEvasion.ps1
│   ├── Find-NetworkAnomalies.ps1
│   ├── Find-PersistenceMechanisms.ps1
│   ├── Find-SuspiciousAuthentication.ps1
│   ├── Find-SuspiciousProcesses.ps1
│   ├── Get-CredentialAccessEvents.ps1
│   └── Get-SysmonAnalytics.ps1
│
├── 📁 Enterprise/                      # Enterprise (4 functions)
│   ├── Get-MultiSystemAudit.ps1
│   ├── Invoke-EnterpriseSecurityScan.ps1
│   ├── Invoke-SecurityAssessment.ps1
│   └── Register-ScheduledSecurityScan.ps1
│
├── 📁 Forensics/                       # Digital Forensics (7 functions)
│   ├── Export-MemoryDump.ps1
│   ├── Get-ArtifactCollection.ps1
│   ├── Get-ExecutionArtifacts.ps1
│   ├── Get-FileSystemJournal.ps1
│   ├── Get-USBHistory.ps1
│   ├── Get-UserActivityArtifacts.ps1
│   └── New-ForensicTimeline.ps1
│
├── 📁 Hardening/                       # Security Hardening (4 functions)
│   ├── Enable-AuditPolicies.ps1
│   ├── Enable-PowerShellSecurity.ps1
│   ├── Invoke-SecurityRemediation.ps1
│   └── Set-SecurityBaseline.ps1
│
├── 📁 Private/                         # Internal locale-invariant data sources (hidden)
│   ├── Get-AuditPolicyTable.ps1        # Audit policy via AuditQuerySystemPolicy/GUID CSV
│   ├── Get-LocalPasswordPolicy.ps1     # Password policy via NetUserModalsGet
│   ├── Get-WlanProfileList.ps1         # WLAN profiles via wlanapi.dll
│   └── IdentityHelpers.ps1             # SID-first group/user/ACL resolution
│
├── 📁 Reporting/                       # Reporting (4 functions)
│   ├── Get-SecurityMetrics.ps1
│   ├── New-ConsolidatedReport.ps1
│   ├── New-ExecutiveReport.ps1
│   └── New-SecurityDashboard.ps1
│
├── 📁 Response/                        # Incident Response (5 functions)
│   ├── ConvertTo-SiemEvent.ps1
│   ├── Export-SecurityReport.ps1
│   ├── Invoke-ForensicCollection.ps1
│   ├── Invoke-IncidentResponse.ps1
│   └── Send-SiemEvent.ps1
│
├── 📁 tests/                           # Pester tests (523)
│   ├── WindowsSecurityAudit.Tests.ps1  # Public API surface (428 tests)
│   ├── Smoke.Windows.Tests.ps1         # Real-Windows execution smoke tests (49)
│   ├── Locale.Regression.Tests.ps1     # EN/DE fixture equivalence + no-text-readers guard (46)
│   └── fixtures/                       # auditpol EN/DE (cp1252) CSV fixtures
│
├── 📁 ThreatHunting/                   # Threat Hunting (7 functions)
│   ├── Export-AttackNavigatorLayer.ps1
│   ├── Find-APTIndicators.ps1
│   ├── Find-DataExfiltration.ps1
│   ├── Find-LateralMovement.ps1
│   ├── Find-LivingOffLand.ps1
│   ├── Get-MITREAttackMapping.ps1
│   └── Get-ThreatIntelligence.ps1
│
├── 📁 Vulnerability/                   # Vulnerability Management (8 functions)
│   ├── Find-EOLSoftware.ps1
│   ├── Get-ExposedServices.ps1
│   ├── Get-NVDCveData.ps1
│   ├── Get-SecurityMisconfigurations.ps1
│   ├── Get-VulnerabilityAssessment.ps1
│   ├── Resolve-CpeName.ps1
│   ├── Test-CertificateHealth.ps1
│   └── Test-PatchCompliance.ps1
│
└── 📁 WindowsDefender/                 # Windows Defender (3 functions)
    ├── Get-DefenderStatus.ps1
    ├── Invoke-DefenderScan.ps1
    └── Update-DefenderConfiguration.ps1
```

---

## 💻 System Requirements

### Minimum Requirements
- **Operating System**: Windows 10 1809+ / Windows Server 2016+
- **PowerShell**: Version 5.1 (Windows PowerShell) or PowerShell 7+
- **Display Language**: Any — core checks are locale-invariant since v1.6.0 (API/GUID/SID-based; correct results on non-English Windows; `Get-FileSystemJournal` excepted — see [Known Limitations](#-known-limitations))
- **Memory**: 4GB RAM (8GB recommended for enterprise scanning)
- **Storage**: 1GB for module + 10GB for reports and logs
- **Processor**: 2 cores minimum (4+ cores recommended)
- **Network**: Required for cloud security and multi-system scanning

### Privileges Required
- Local Administrator (most functions)
- Domain Administrator (Active Directory module)
- Global Administrator (Cloud Security module)

### Optional Components
- **ActiveDirectory module (RSAT)**: For AD security functions
- **Microsoft Graph PowerShell SDK**: For cloud functions (Azure/M365 assessments)
- **Windows Defender**: For AV management functions
- **.NET Framework 4.7.2+**: For advanced reporting features

---

## 📥 Installation

### Method 1: Git Clone (Recommended)
```powershell
# Clone repository
git clone https://github.com/okanyildiz/WindowsSecurityAudit.git
cd WindowsSecurityAudit

# Import the module directly from the clone
Import-Module ".\WindowsSecurityAudit.psd1" -Force

# Or run the smoke test
.\Test-Module.ps1

# Verify installation - should return 72
(Get-Command -Module WindowsSecurityAudit).Count
```

### Method 2: Direct Download
> **Note:** No `WindowsSecurityAudit.zip` asset is attached to GitHub releases today — the publish workflow (`.github/workflows/publish.yml`) targets the PowerShell Gallery only, so the download URL below returns 404. Use Method 1, 3 or 4 until a release ships a ZIP asset.

```powershell
# Download latest release
$url = "https://github.com/okanyildiz/WindowsSecurityAudit/releases/latest/download/WindowsSecurityAudit.zip"
$output = "$env:TEMP\WindowsSecurityAudit.zip"
Invoke-WebRequest -Uri $url -OutFile $output

# Extract to modules directory
$modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\WindowsSecurityAudit"
Expand-Archive -Path $output -DestinationPath $modulePath -Force

# Import module
Import-Module WindowsSecurityAudit -Force
```

### Method 3: Manual ZIP Download (GitHub "Download ZIP")
```powershell
# GitHub's "Code > Download ZIP" extracts to a folder named WindowsSecurityAudit-main.
# PowerShell only finds modules by name if the folder is named EXACTLY 'WindowsSecurityAudit'
# and sits inside a PSModulePath directory. Rename and move it:

# For Windows PowerShell 5.1:
$moduleDir = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
# For PowerShell 7.x:
# $moduleDir = "$env:USERPROFILE\Documents\PowerShell\Modules"

New-Item -Path $moduleDir -ItemType Directory -Force | Out-Null
Move-Item ".\WindowsSecurityAudit-main" "$moduleDir\WindowsSecurityAudit" -Force

# Unblock files downloaded from the internet (otherwise scripts may refuse to load)
Get-ChildItem "$moduleDir\WindowsSecurityAudit" -Recurse | Unblock-File

Import-Module WindowsSecurityAudit -Force
```

Alternatively, import directly by path from the extracted folder (no renaming needed):
```powershell
Import-Module ".\WindowsSecurityAudit-main\WindowsSecurityAudit.psd1" -Force
```

> **Note:** `Import-Module WindowsSecurityAudit` (by name) does NOT search the current
> directory. It only searches the folders listed in `$env:PSModulePath`. Running it
> from inside the extracted ZIP folder fails with "no valid module file was found in
> any module directory" unless you use the path-based import shown above.

### Method 4: PowerShell Gallery
> The module is **live on the PowerShell Gallery** since v1.6.0 — this is the easiest install method. Every release is published automatically after the full Windows test suite passes.

```powershell
# Once published, installation will be:
Install-Module -Name WindowsSecurityAudit -Scope CurrentUser -Force

# Import the module
Import-Module WindowsSecurityAudit
```

### Troubleshooting
- **"no valid module file was found in any module directory"** — the module folder is not
  in `$env:PSModulePath`, or the folder is named `WindowsSecurityAudit-main` instead of
  `WindowsSecurityAudit`. See Method 3.
- **"running scripts is disabled on this system"** — set an execution policy for your user:
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
- **Scripts blocked after ZIP download** — run `Get-ChildItem <module folder> -Recurse | Unblock-File`.

---

## 🚀 Quick Start

### Your First Security Scan (2 minutes)
```powershell
# 1. Import the module (from a git clone; see Installation for Gallery/other methods)
Import-Module .\WindowsSecurityAudit\WindowsSecurityAudit.psd1 -Force

# 2. Run quick assessment
$security = Get-SecurityBaseline
Write-Host "Security Score: $($security.SecurityScore)/100" -ForegroundColor Yellow

# 3. Check for threats
$threats = Find-SuspiciousProcesses
if ($threats) { 
    Write-Warning "Found $($threats.Count) suspicious processes!"
    $threats | Format-Table ProcessName, Path, SuspicionScore
}
```

### Comprehensive Assessment (5 minutes)
```powershell
# Run full security assessment
$report = Invoke-SecurityAssessment -Verbose

# Export professional report (collects its own data; returns the generated file paths)
$files = Export-SecurityReport -ReportType Technical -Format HTML -OutputPath "C:\SecurityReports"

# Open report (file name is timestamped: SecurityReport_Technical_yyyyMMdd_HHmmss.html)
Start-Process ($files | Where-Object { $_ -match '\.html$' } | Select-Object -First 1)
```

### Real CVEs & Live Threat Feeds (New in v1.2.0)
```powershell
# Match installed software against real NVD CVE data
# (keyword-based candidate matching; add -NVDApiKey for higher rate limits)
Get-VulnerabilityAssessment -CheckCVEs -NVDApiKey $key

# Pull live abuse.ch feeds (URLhaus + Feodo Tracker) and check network
# connections against them; add -AbuseIPDBApiKey to include AbuseIPDB
Get-ThreatIntelligence -CheckNetwork -UpdateFeeds
```

### Version-Exact CVEs & Automated Remediation (New in v1.3.0)
```powershell
# Version-exact CVE matching: resolve installed products to CPE names first
Get-VulnerabilityAssessment -ExactCVEMatch -NVDApiKey $key

# Import a STIX 2.x bundle fully offline, or pull from MISP/TAXII
Get-ThreatIntelligence -CheckNetwork -StixFilePath "C:\intel\bundle.json"

# Assess, then preview automated fixes with a rollback script (no changes; rollback script content is returned in RollbackPreview)
Invoke-SecurityAssessment -OutputPath "C:\Assessments"
Invoke-SecurityRemediation -AssessmentPath "C:\Assessments\SecurityAssessment.json" -GenerateRollback -WhatIf
```

### SIEM & Evasion Hunting (New in v1.4.0)
```powershell
# Detect AMSI/ETW tampering, Defender tampering, and cleared logs;
# include heuristic log-gap analysis across major logs
Find-DefenseEvasion -IncludeLogGapAnalysis

# Hunt Kerberoasting, password spray, and golden-ticket heuristics;
# -IncludeLSASSAccess needs a SACL on lsass.exe (4663) or Sysmon 10
Get-CredentialAccessEvents -IncludeLSASSAccess

# Export findings as SIEM-ready NDJSON without opening a browser
Export-SecurityReport -ReportType Technical -Format NDJSON -NoAutoOpen
```

### Fleet Scanning & Smart Alerts (New in v1.5.0)
```powershell
# Deploy the module to remote hosts and run a curated function set
# (zip -> Copy-Item -ToSession -> remote Import-Module)
Invoke-EnterpriseSecurityScan -ComputerName srv1, srv2 -UseModuleFunctions -RemoteFunctionSet Standard

# Schedule a daily full scan with webhook alerts. Alert dedup is ON by
# default: findings are fingerprinted (State\last-findings.json) and
# classified New/Persisting/Resolved, so repeat alerts are suppressed
# until -RealertAfterDays (default 7) elapses
Register-ScheduledSecurityScan -ScanType Full -Frequency Daily -WebhookUrl $url
```

### One Report to Rule Them All (New in v1.1.0)
```powershell
# Collect results from ALL modules into a single interactive Chart.js HTML report
New-ConsolidatedReport -OutputPath .\Report -OpenInBrowser

# Air-gapped? Save the raw data once, rebuild the report later without rescanning
New-ConsolidatedReport -OutputPath .\Report -SaveJson
New-ConsolidatedReport -OutputPath .\Report -FromJsonPath .\Report\ConsolidatedReportData_20261025_093000.json
```

### Visualize Threats in MITRE ATT&CK Navigator (New in v1.1.0)
```powershell
# Map live findings to ATT&CK techniques, then pipe straight into a
# Navigator layer with severity-based scoring and colors
Get-MITREAttackMapping -FullAnalysis | Export-AttackNavigatorLayer -OutputPath .\attack-layer.json

# Import .\attack-layer.json at https://mitre-attack.github.io/attack-navigator/
# to see exactly which techniques your findings cover — and where the gaps are
```

---

## 📊 Module Categories - Detailed Breakdown

### 1️⃣ Core Security Module (5 Functions)

The Core module serves as the foundation of the entire security assessment framework. These functions provide essential baseline measurements and system integrity verification that other modules build upon. Every security assessment should begin with these core evaluations to establish a security context.

| Function | Purpose | Key Features | Output Type |
|----------|---------|--------------|-------------|
| **`Get-SecurityBaseline`** | Evaluates overall security posture against industry best practices | • Windows Defender real-time protection status<br>• Firewall profile configuration (Domain/Private/Public)<br>• UAC elevation settings<br>• BitLocker encryption status<br>• Windows Update compliance<br>• Generates an aggregate 0-100 security score | PSCustomObject with scores, status, and recommendations |
| **`Get-SystemInfo`** | Collects comprehensive system information for security context | • Hardware specifications (CPU, RAM, Disks)<br>• Operating system version and patches<br>• Installed software inventory<br>• Network adapter configuration<br>• Domain membership and policies | Detailed system profile for analysis |
| **`Test-SystemIntegrity`** | Verifies Windows system file integrity and health | • SFC (System File Checker) execution<br>• DISM component store validation<br>• Windows image health check<br>• Corrupted file detection<br>• Repair guidance for files SFC could not fix; `-RepairFiles` runs DISM RestoreHealth when the component store is repairable | Integrity report with repair actions |
| **`Get-EventIdDescription`** | Provides security context for Windows Event IDs | • Maps Event IDs to security implications<br>• MITRE ATT&CK technique correlation<br>• Severity classification (Critical/High/Medium/Low)<br>• Investigation guidance<br>• Response recommendations | Event analysis with threat context |
| **`Compare-SecurityBaseline`** | Compares two security states and reports configuration drift | • Baseline vs. current state diffing<br>• Live capture when no current file given<br>• Improved/Degraded/New/Removed classification<br>• Volatile timestamp filtering<br>• Overall trend calculation<br>• JSON + CSV drift export | Drift report with trend summary |

---

### 2️⃣ Detection Module (7 Functions)

The Detection module provides real-time threat identification capabilities using both signature-based and behavioral analysis techniques. These functions are designed to identify active threats, suspicious behaviors, and potential compromises that traditional antivirus might miss.

| Function | Purpose | Detection Capabilities | Risk Indicators |
|----------|---------|------------------------|-----------------|
| **`Find-PersistenceMechanisms`** | Identifies malware persistence techniques across the system | • 8 registry Run-key locations (Run, RunOnce, RunServices, WOW6432Node)<br>• Startup folders (per-user and all-users)<br>• Scheduled Tasks (hidden, system, unusual)<br>• Windows Services (unsigned, suspicious paths)<br>• WMI Event Subscriptions<br>• Other registry autostarts (AppInit DLLs, LSA providers, print monitors) | High: Unknown entries<br>Medium: Unsigned binaries<br>Low: Unusual locations |
| **`Find-SuspiciousProcesses`** | Detects malicious process behaviors and anomalies | • Unsigned or invalid signatures<br>• Execution from temporary/suspicious directories<br>• Known suspicious tool names<br>• Unusual parent-child relationships (Office/browser spawning shells)<br>• Optional network-connection check (uncommon remote ports, `-CheckNetwork`) | Suspicion score per process<br>Unsigned or oddly-located binaries<br>Suspicious parent/child pairs |
| **`Find-NetworkAnomalies`** | Identifies abnormal network communications | • Known high-risk/malicious port usage<br>• Non-standard and unusual high listening ports<br>• Optional DNS cache anomaly heuristics (DGA/entropy-style checks, `-CheckDNS`)<br>• Established-connection review | High: Known malicious ports<br>Medium: Unusual ports<br>Medium: DNS anomalies |
| **`Find-SuspiciousAuthentication`** | Detects authentication attacks and anomalies | • Brute force attempts (multiple failures)<br>• Account lockout patterns<br>• After-hours authentication<br>• Explicit-credential logons (runas / net use, 4624 Type 9 NewCredentials)<br>• Per-account NTLM network logon indicators<br>• Service account anomalies | High: Brute force<br>Medium: After hours<br>Low: Explicit credentials |
| **`Get-CredentialAccessEvents`** | Detects runtime credential-access activity from event logs | • Kerberoasting: RC4 service ticket bursts (4769)<br>• Anomalous TGT request volumes (4768)<br>• Kerberos pre-auth failure spikes / password spray (4771)<br>• Golden-ticket heuristic (Kerberos logon with no matching TGT; labeled Heuristic/Medium)<br>• Optional LSASS access handles (`-IncludeLSASSAccess`; 4663 needs a SACL, or Sysmon 10) | High: Kerberoast bursts, suspicious LSASS access<br>Medium: TGT anomalies, spray spikes, golden-ticket heuristic |
| **`Find-DefenseEvasion`** | Detects defense-evasion and security-tampering activity | • AMSI bypass & ETW tamper patterns in script-block logs (4104)<br>• Defender exclusions and disabled real-time/behavior monitoring (Get-MpPreference)<br>• Defender tamper events (5001/5007)<br>• Log clearing (1102/104) and audit policy changes (4719) with clearing-account attribution<br>• Optional heuristic log-gap analysis (`-IncludeLogGapAnalysis`) | High: AMSI/ETW tamper, Defender tamper, cleared logs<br>Low: log gaps (heuristic) |
| **`Get-SysmonAnalytics`** | Deep analytics over the Sysmon Operational log (requires Sysmon) | • Event 1 process chains & command-line indicators<br>• Event 3 network beaconing detection<br>• Event 7 image loads<br>• Event 10 process access with LSASS access-mask analysis (T1003.001)<br>• Event 11 file creates, Events 12/13 registry writes<br>• Event 22 DNS anomalies<br>• `-Hours` / `-EventTypes` / `-MaxEvents` filtering; returns `NotAvailable` gracefully when Sysmon is absent | High: LSASS access masks, encoded commands, download cradles<br>Medium: beaconing, persistence-oriented writes |

---

### 3️⃣ Analysis Module (4 Functions)

The Analysis module performs deep forensic examination of system components to uncover hidden threats, investigate incidents, and gather evidence. These functions go beyond surface-level scanning to analyze system internals for sophisticated attack indicators.

| Function | Purpose | Analysis Techniques | Key Findings |
|----------|---------|---------------------|--------------|
| **`Get-EventLogAnalysis`** | Analyzes Windows event logs for security insights | • Security/System/Application log analysis<br>• Failed logon and audit-event highlighting (4625, 1102, 4697, ...)<br>• Event ID context and counts<br>• Application error patterns | Authentication failures<br>Audit events<br>System anomalies<br>Application errors |
| **`Get-RegistryAnalysis`** | Examines registry for security-relevant settings | • Security policy settings (LSA, WDigest, UAC)<br>• Autorun entry review (`-IncludeAutoRun`)<br>• Service key review (suspicious/unquoted paths)<br>• Registry permission checks (`-CheckPermissions`) | Weakened security settings<br>Persistence entries<br>Risky service configs |
| **`Get-MemoryAnalysis`** | Heuristic process inspection via process metadata (no raw memory reads) | • Loaded-module inventory with suspicious name/location patterns<br>• Main-module path mismatch (process-hollowing heuristic)<br>• Working-set/virtual-memory ratio anomalies (injection heuristic)<br>• Remote-thread start-address heuristics<br>• `-IncludeStrings` only notes that string extraction needs external tools (e.g. Sysinternals Strings) | Injection/hollowing heuristics<br>Suspicious modules<br>Unusual memory characteristics |
| **`Get-FileSystemAnalysis`** | Comprehensive file system security analysis | • Alternate Data Stream detection<br>• Hidden file discovery<br>• Suspicious extensions<br>• Recent file modifications | Hidden malware<br>Data staging<br>Exfiltration prep |

---

### 4️⃣ Response Module (5 Functions)

The Response module provides automated incident response capabilities, enabling rapid containment of threats and systematic evidence collection. These functions follow industry-standard incident response procedures while maintaining forensic integrity.

| Function | Purpose | Response Actions | Evidence Types |
|----------|---------|------------------|----------------|
| **`Invoke-IncidentResponse`** | Orchestrates a guided incident response procedure | • Step 1: quick security baseline<br>• Step 2: active-threat scan<br>• Step 3: optional network isolation (`-IsolateSystem`, automatic on Critical severity)<br>• Step 4: suspicious-process termination<br>• Step 5: forensic evidence collection<br>• Step 6: incident report generation | Response timeline<br>Actions taken<br>System state<br>Threat indicators |
| **`Invoke-ForensicCollection`** | Systematically collects forensic evidence | • System, process and network state capture<br>• Event log extraction<br>• Registry artifact collection (incl. USB history)<br>• File-system artifacts (Comprehensive profile)<br>• Timeline generation<br>• Memory dump: writes an instructions file pointing to external tools (WinPMEM, DumpIt, Magnet RAM Capture) — no in-module memory acquisition | State captures<br>Event logs<br>System artifacts<br>Timeline data |
| **`Export-SecurityReport`** | Generates professional security reports | • HTML interactive dashboards<br>• JSON for SIEM integration<br>• CSV for data analysis<br>• NDJSON/CEF SIEM-ready exports (`-Format NDJSON/CEF`; `All` writes .ndjson + .cef too)<br>• `-NoAutoOpen` for headless/SYSTEM-context runs | Multi-format reports<br>Executive summaries<br>Technical details<br>Recommendations |
| **`ConvertTo-SiemEvent`** | Converts findings into SIEM-ready event strings | • Pipeline conversion of findings to NDJSON (one compact JSON object per line) or CEF (`CEF:0` strings)<br>• Severity-to-number mapping and heuristic CEF `act` field<br>• MITRE technique ID passthrough when present<br>• `-HostName` / `-ProductVersion` stamping<br>• Splunk / Sentinel / QRadar / ArcSight ingestion ready | NDJSON lines<br>CEF strings |
| **`Send-SiemEvent`** | Streams findings directly to SIEM HTTP endpoints | • Splunk HEC (`Splunk <token>` auth header), Microsoft Sentinel (Log Analytics API with HMAC-SHA256 SharedKey signature), or generic webhook with custom headers<br>• NDJSON or CEF payloads via ConvertTo-SiemEvent<br>• Batching (`-BatchSize`) with exponential-backoff retry on HTTP 429/5xx (`-MaxRetries`, `-ThrottleMs`)<br>• Token always masked in console output<br>• Also wired into `Export-SecurityReport -StreamTo/-StreamUri/-StreamToken/-StreamFormat` | BatchesSent / EventsSent / Failed / DurationSec summary |

---

### 5️⃣ Enterprise Module (4 Functions)

The Enterprise module enables security operations at scale, providing centralized management and reporting across multiple systems. These functions are optimized for large environments with thousands of endpoints.

| Function | Purpose | Enterprise Features | Scalability |
|----------|---------|---------------------|-------------|
| **`Invoke-EnterpriseSecurityScan`** | Performs security scanning across multiple systems | • Parallel execution (up to 50 threads)<br>• Credential management<br>• Progress tracking<br>• Error handling<br>• Resource throttling<br>• Centralized logging | Parallel multi-system scans<br>Per-host timeouts & probes<br>CSV target lists |
| **`Get-MultiSystemAudit`** | Consolidated auditing across system groups | • Risk scoring<br>• Executive dashboards | Server groups<br>Department systems<br>Geographic regions |
| **`Invoke-SecurityAssessment`** | Comprehensive security evaluation orchestration | • Optional CIS/NIST/PCI run via `-IncludeCompliance`<br>• Risk prioritization | Complete assessment<br>Risk matrices<br>Action plans |
| **`Register-ScheduledSecurityScan`** | Automated recurring scans with alerting | • Daily/Weekly/Monthly schedules<br>• Runs as SYSTEM via Scheduled Tasks<br>• Teams/Slack webhook alerts<br>• Email alerts on Critical findings<br>• Run history and error logging<br>• WhatIf/Confirm support | Scheduled task<br>Alert notifications<br>Run summaries |

---

### 6️⃣ Hardening Module (4 Functions)

The Hardening module implements security best practices and configurations to reduce attack surface and improve system resilience. These functions apply industry-standard security baselines and monitoring configurations.

| Function | Purpose | Hardening Actions | Compliance |
|----------|---------|-------------------|-------------|
| **`Set-SecurityBaseline`** | Applies a set of security hardening configurations | • ~27 settings across UAC, firewall, Defender, network, account and system categories<br>• Basic / Recommended / Strict presets<br>• WhatIf/Confirm support (`SupportsShouldProcess`) | General hardening<br>WhatIf-first changes |
| **`Enable-PowerShellSecurity`** | Hardens PowerShell environment | • Script Block Logging<br>• Module Logging<br>• Transcription<br>• Execution policy<br>• JEA mentioned only as a follow-up recommendation (not configured) | Full audit trail<br>PowerShell logging baseline |
| **`Enable-AuditPolicies`** | Configures advanced security auditing | • Process creation with command line<br>• Logon/Logoff tracking<br>• Object access monitoring<br>• Privilege use auditing<br>• System integrity monitoring<br>• Account management tracking | Complete visibility<br>Forensic capability<br>Compliance ready |
| **`Invoke-SecurityRemediation`** | Applies automated fixes for assessment findings | • Consumes Invoke-SecurityAssessment JSON or piped findings<br>• Curated map of 7 safe remediations (firewall, UAC, Defender RTP, SMBv1, Guest, PS logging, RDP NLA)<br>• Severity filter (`-MaxSeverity`)<br>• WhatIf/Confirm first (ConfirmImpact High)<br>• `-GenerateRollback` captures pre-change state<br>• Unmatched findings routed to ManualReview | Finding-to-fix loop<br>Verified changes<br>Rollback script |

---

### 7️⃣ Windows Defender Module (3 Functions)

The Windows Defender module provides comprehensive management and monitoring of Windows Defender Antivirus, ensuring optimal protection and threat visibility.

| Function | Purpose | Management Features | Protection Level |
|----------|---------|---------------------|------------------|
| **`Get-DefenderStatus`** | Comprehensive Defender health check | • Real-time protection status<br>• Signature age and version<br>• Last scan results<br>• Threat history<br>• Exclusion audit<br>• Performance impact | Status monitoring<br>Health validation<br>Alert generation |
| **`Invoke-DefenderScan`** | Initiates custom antivirus scans | • Quick scan (critical areas)<br>• Full scan (complete system)<br>• Custom path scanning<br>• Offline scan capability<br>• Boot sector verification<br>• Performance optimization | Threat detection<br>Malware removal<br>System cleanup |
| **`Update-DefenderConfiguration`** | Optimizes Defender settings | • Real-time protection toggle<br>• Cloud-delivered protection (MAPS)<br>• Automatic sample submission<br>• PUA protection<br>• Scheduled scan (day/time) | Configurable protection settings<br>WhatIf-first changes |

---

### 8️⃣ Threat Hunting Module (7 Functions)

The Threat Hunting module provides proactive threat detection capabilities using advanced techniques, threat intelligence, and behavioral analysis to identify sophisticated attackers that evade traditional security controls.

| Function | Purpose | Hunting Techniques | Detection Coverage |
|----------|---------|-------------------|-------------------|
| **`Find-APTIndicators`** | Heuristic sweep for APT-style indicators | • Roughly 20-35 scored heuristic checks across 4 surfaces: services, scheduled tasks, registry persistence, network connections<br>• Whitelist filtering to suppress known-good software<br>• Severity scoring with Critical/High/Medium thresholds and an overall risk level<br>• No MITRE ATT&CK technique IDs attached | Heuristic indicator sweep<br>Scored findings<br>Risk-level summary |
| **`Find-DataExfiltration`** | Detects data theft attempts | • Active outbound connection review (first 10 established non-loopback connections; common browser/collaboration apps skipped)<br>• Large archive/file detection above `-ThresholdMB`<br>• Compression before transfer<br>• Cloud upload monitoring (known cloud service endpoints)<br>• Data staging detection | Data staging<br>Large transfers<br>Cloud uploads |
| **`Find-LateralMovement`** | Tracks attacker movement between systems | • RDP session analysis (4624 Type 10)<br>• SMB connection/share-access monitoring (445, 5140/5145)<br>• PSRemoting/WinRM activity (5985/5986, 4648 explicit credentials)<br>• Network logon review (4624 Type 3) | Network propagation<br>Suspicious remote sessions |
| **`Find-LivingOffLand`** | Detects abuse of legitimate tools | • 15-entry curated LOLBin database (certutil, mshta, rundll32, wmic, bitsadmin, regsvr32, ...; note: powershell.exe is not an entry)<br>• Command-line matching against known abuse patterns per binary | Fileless attacks<br>Evasion techniques<br>Stealth persistence |
| **`Get-MITREAttackMapping`** | Maps findings to ATT&CK framework | • Technique classification<br>• Tactic identification<br>• Priority scoring<br>• Coverage reporting | Framework alignment<br>Gap identification<br>Defense planning |
| **`Get-ThreatIntelligence`** | Analyzes threat intelligence indicators | • IOC matching<br>• Live threat feeds (URLhaus, Feodo Tracker, AbuseIPDB)<br>• Feed caching with freshness fallback<br>• Reputation checking<br>• Hash validation<br>• Domain analysis | Known threats<br>Emerging campaigns<br>Zero-day indicators |
| **`Export-AttackNavigatorLayer`** | Exports findings as a MITRE ATT&CK Navigator layer | • Navigator layer JSON v4.x<br>• Severity-based scoring and colors<br>• Detection count aggregation<br>• Evidence embedded in comments<br>• Pipeline input from hunting functions<br>• Output validation | ATT&CK Navigator<br>visualization |

---

### 9️⃣ Compliance Module (5 Functions)

The Compliance module automates security framework validation and generates audit-ready evidence, significantly reducing the time and effort required for compliance assessments.

| Function | Purpose | Frameworks Supported | Automation Level |
|----------|---------|---------------------|------------------|
| **`Test-CISBenchmark`** | Validates CIS-style security controls | • CIS-inspired Level 1 (basic) checks<br>• 16 automated checks<br>• Windows 10/11/Server<br>• Text remediation guidance per check (not scripts)<br>• Detailed scoring | Automated pass/fail results<br>Evidence collection |
| **`Test-NISTCompliance`** | Assesses selected NIST 800-53 controls | • 17 controls across 5 families<br>• Access Control (AC)<br>• Audit & Accountability (AU)<br>• Identification & Authentication (IA)<br>• System & Communications Protection (SC)<br>• Configuration Management (CM) | Control validation<br>Gap analysis<br>Maturity scoring |
| **`Test-PciDssCompliance`** | Validates PCI-DSS requirements | • 18 requirement checks (PCI-DSS 4.0)<br>• Network security controls<br>• Access control<br>• Encryption validation<br>• Log monitoring<br>• Vulnerability management | Requirement mapping<br>Evidence generation<br>SAQ support |
| **`Get-ComplianceReport`** | Generates comprehensive compliance reports | • Multi-framework dashboard<br>• Executive summaries<br>• Technical evidence<br>• Gap analysis | Professional reports<br>Audit-ready format<br>Action plans |
| **`Export-ComplianceEvidence`** | Collects and packages audit evidence | • Configuration exports (secedit, auditpol, firewall rules, registry, gpresult)<br>• Log extraction (event logs, failed logons, PowerShell logs)<br>• Text status captures (Defender/firewall/BitLocker) — not graphical screenshots<br>• System inventory (software, users, groups, services, updates)<br>• Chain of custody documentation<br>• SHA-256 integrity hashing of the configuration exports and the final ZIP bundle | Complete evidence<br>Timestamp verification<br>Integrity hashing |

`Test-PCI-DSS` still works as an alias.

NotEvaluated controls count against the compliance percentage; Manual controls are excluded and listed separately; see CoveragePercentage.

---

### 🔟 Active Directory Module (6 Functions)

The Active Directory module provides specialized security assessment for AD environments, identifying vulnerabilities and misconfigurations that attackers commonly exploit for domain compromise.

| Function | Purpose | Security Checks | Risk Areas |
|----------|---------|-----------------|------------|
| **`Find-ADVulnerabilities`** | AD vulnerability scanning | • Kerberoasting targets (accounts with SPNs)<br>• ASREP roasting accounts (pre-auth not required)<br>• Weak ACLs and permissions | Account compromise<br>Privilege escalation |
| **`Find-ADBackdoors`** | Detects persistence in Active Directory | • AdminSDHolder modifications<br>• DCSync permissions (replication ACLs)<br>• SID history abuse<br>• Dangerous delegations (unconstrained, constrained with protocol transition) | Domain persistence<br>Privileged access<br>Stealth backdoors |
| **`Find-StaleADObjects`** | Identifies unused AD objects for cleanup | • Inactive user accounts<br>• Stale computer objects<br>• Empty security groups | Attack surface reduction<br>Compliance cleanup<br>Performance improvement |
| **`Test-ADSecurityPosture`** | Evaluates overall AD security health | • Password policy strength<br>• Account lockout policy<br>• Domain controller review<br>• Optional trust inventory (`-IncludeTrusts`)<br>• Optional unlinked-GPO detection (`-IncludeGPO`) | Domain hardening<br>Best practices<br>Security maturity |
| **`Get-ADPasswordPolicy`** | Analyzes password security settings | • Default domain policy<br>• Fine-grained policies<br>• Complexity requirements<br>• History enforcement<br>• Lockout thresholds<br>• Expiration settings | Weak passwords<br>Brute force risk<br>Compliance gaps |
| **`Get-ADPrivilegedAccounts`** | Maps privileged access | • Domain/Enterprise Admins<br>• Schema admins<br>• Backup operators | Privilege creep<br>Excessive rights<br>Account security |

---

### 1️⃣1️⃣ Vulnerability Module (8 Functions)

The Vulnerability module identifies, assesses, and prioritizes security weaknesses across the environment, providing actionable remediation guidance based on exploitability and business impact.

| Function | Purpose | Assessment Areas | Priority Scoring |
|----------|---------|------------------|------------------|
| **`Get-VulnerabilityAssessment`** | Comprehensive vulnerability scanning | • CVE identification<br>• Real NVD CVE matching (`-CheckCVEs`)<br>• CVSS scoring (v3.1)<br>• Patch availability | Critical: CVSS 9.0+<br>High: CVSS 7.0-8.9<br>Medium: CVSS 4.0-6.9<br>Low: CVSS 0-3.9 |
| **`Get-NVDCveData`** | Queries the NVD API 2.0 for real CVE data | • Keyword or CPE 2.3 name search<br>• Normalized CVE objects (ID, description, references)<br>• CVSS v3.1/v3.0/v2 severity and score<br>• Automatic pagination<br>• NVD rate-limit handling<br>• Optional API key for higher limits | CVSS base severity<br>(Critical/High/Medium/Low) |
| **`Resolve-CpeName`** | Resolves installed products to CPE 2.3 names | • Curated offline table (~120 products, with vendor-scheme version translation)<br>• Optional NVD CPE API lookup (`-UseOnlineLookup -ApiKey`)<br>• Heuristic fallback (Low confidence)<br>• Version string normalization<br>• Confidence + MatchedBy provenance<br>• API key never logged | High: curated + version<br>Medium: curated/online<br>Low: heuristic |
| **`Get-SecurityMisconfigurations`** | Identifies configuration weaknesses | • Weak file permissions<br>• Default credentials<br>• Open network shares<br>• Service account issues<br>• Registry permissions<br>• Group Policy gaps | Exploitability rating<br>Impact assessment<br>Fix complexity |
| **`Find-EOLSoftware`** | Detects unsupported software | • End-of-life products<br>• Unsupported versions<br>• Legacy applications<br>• Missing security updates<br>• Vendor bulletins<br>• Migration paths | Support status<br>Risk exposure<br>Upgrade options |
| **`Get-ExposedServices`** | Maps attack surface | • Listening/internet-facing services<br>• Default configurations<br>• Unnecessary services<br>• Port exposure (incl. `-CustomPorts`)<br>• Authentication methods | External exposure<br>Open ports<br>Access controls |
| **`Test-CertificateHealth`** | Certificate security validation | • Expiration monitoring<br>• Signature algorithm reporting<br>• Self-signed detection<br>• Chain validation<br>• Revocation checking (`-CheckRevocation`)<br>• Trust store review | Expiry risk<br>Chain/trust issues |
| **`Test-PatchCompliance`** | Patch management assessment | • Missing critical patches<br>• Update history analysis<br>• Missing-update age/scoring | Patch age<br>Severity rating |

---

### 1️⃣2️⃣ Forensics Module (7 Functions)

The Forensics module provides digital forensic capabilities for incident investigation, evidence collection, and timeline reconstruction while maintaining chain of custody and legal admissibility.

| Function | Purpose | Forensic Capabilities | Evidence Types |
|----------|---------|----------------------|----------------|
| **`Export-MemoryDump`** | Captures process memory for analysis | • Per-process memory dumps (not a full physical RAM capture)<br>• Sysinternals ProcDump when available (`-UseProcDump`)<br>• MiniDumpWriteDump (dbghelp) fallback<br>• Optional compression | Process memory dumps<br>Dump metadata |
| **`Get-ArtifactCollection`** | Collects forensic artifacts | • Browser artifacts (Chrome and Edge Default profiles only)<br>• Download history<br>• Per-file SHA256 computed at acquisition<br>• Raw registry hive capture via `reg save`<br>• AcquisitionLog manifest block | User activity<br>File access<br>Internet activity |
| **`Get-UserActivityArtifacts`** | Collects per-user activity artifacts for DFIR | • Recycle Bin `$I` parsing (v2 + best-effort v1 headers; path, size, deletion FILETIME)<br>• Recent/Desktop LNK resolution via WScript.Shell COM (unresolved off-Windows)<br>• JumpList enumeration (AutomaticDestinations; embedded targets not parsed)<br>• ActivitiesCache.db raw copy (no SQLite parsing)<br>• Optional CSV export (`-OutputPath`) | Deleted files<br>Opened documents<br>App usage evidence<br>Timeline databases |
| **`Get-ExecutionArtifacts`** | Traces program execution | • Prefetch analysis<br>• ShimCache: raw binary data collected but NOT parsed (use ShimCacheParser for full decoding)<br>• UserAssist decoding<br>• RecentApps<br>• BAM/DAM analysis | Program execution<br>Timestamps<br>Frequency<br>User attribution |
| **`Get-FileSystemJournal`** | File-system journal & timestomp evidence via fsutil (requires elevation) | • USN journal parsing with reason decoding and executable-creation evidence<br>• MFT summary statistics (summary-level via fsutil — no raw $MFT record parsing)<br>• TimestompScan cross-checks file timestamps against USN journal creation records plus pre-2000/future anomalies — explicitly labeled heuristic<br>• `-DriveLetter`, `-MaxRecords`, optional CSV `-OutputPath` | Executable drops<br>USN journal activity<br>Timestomp indicators (heuristic) |
| **`Get-USBHistory`** | USB device forensics | • Device enumeration<br>• FirstInstalled timestamp; `LastConnected` is reported as unknown (not collected)<br>• Serial numbers | Device usage<br>Hardware inventory<br>User activity |
| **`New-ForensicTimeline`** | Timeline reconstruction | • Multi-source correlation<br>• Event sequencing<br>• File system timeline<br>• Registry timeline<br>• Log correlation<br>• Visual timeline generation | Incident timeline<br>Attack chain<br>User actions<br>System events |

---

### 1️⃣3️⃣ Cloud Security Module (3 Functions)

The Cloud Security module extends security assessment capabilities to cloud platforms, providing visibility into Azure AD and Microsoft 365 security posture.

| Function | Purpose | Cloud Platforms | Key Assessments |
|----------|---------|-----------------|-----------------|
| **`Get-CloudComplianceStatus`** | Cloud compliance catalog (evaluation pending) | • Built-in control catalog for cloud frameworks<br>• Controls currently return `NotEvaluated` — automated Microsoft Graph/API evaluation is not implemented yet<br>• Compliance score is `$null` when nothing was evaluated (no fabricated statuses) | Honest unevaluated status<br>Coverage transparency |
| **`Get-AzureADRiskySignIns`** | Retrieves risky authentication detections | • Passes through Entra ID risk detections (risk level/state as reported by Microsoft Graph — no own risk scoring)<br>• Filter by risk level and time window<br>• Optional risky-user listing (`-IncludeRiskyUsers`) | Entra ID risk detections<br>Compromised accounts<br>Suspicious activity |
| **`Test-M365SecurityPosture`** | Microsoft 365 security assessment | • Conditional Access policy review (Microsoft Graph)<br>• Exchange Online / SharePoint / Teams posture checks<br>• DLP policy status reported as `NotEvaluated` (needs Purview compliance PowerShell)<br>• Threat protection status<br>• Identity protection | Configuration weaknesses<br>Policy gaps<br>Security improvements |

---

### 1️⃣4️⃣ Reporting Module (4 Functions)

The Reporting module transforms raw security data into actionable intelligence through professional reports, interactive dashboards, and executive presentations.

| Function | Purpose | Report Types | Delivery Formats |
|----------|---------|--------------|------------------|
| **`Get-SecurityMetrics`** | Collects and calculates KPIs/KRIs | • Security scores<br>• Threat statistics<br>• Compliance rates<br>• Vulnerability metrics<br>• Trend analysis | JSON metrics<br>Time-series data |
| **`New-ExecutiveReport`** | Creates C-level presentations | • Risk matrices<br>• Business impact analysis<br>• Trend visualization<br>• Key findings<br>• Recommendations<br>• Action items | HTML dashboard<br>PDF (requires wkhtmltopdf) |
| **`New-SecurityDashboard`** | Static HTML security dashboard snapshot | • Security metrics summary<br>• Risk indicators<br>• Compliance status<br>• Alert summary<br>• Optional auto-reload via meta-refresh (`-AutoRefreshSeconds`) — the data itself is a point-in-time snapshot | HTML5 responsive<br>Optional meta-refresh<br>Export capable |
| **`New-ConsolidatedReport`** | Single interactive report combining key collectors | • 6 collectors: Assessment, Defender, Compliance, ThreatHunting, Vulnerability, Forensics<br>• Chart.js severity doughnut (loaded from the jsDelivr CDN — viewing charts requires internet)<br>• Category score bar charts<br>• Offline mode from saved JSON<br>• Section status tracking<br>• Raw data export | HTML report<br>Interactive charts (CDN)<br>JSON export |

---

## 📰 Release Highlights

The full feature set is documented in the module tables above — this section only covers what changed per release, newest first:

### 🆕 v1.6.0 — Full Non-English Windows Support (Locale-Invariant Auditing)

**A correctness overhaul, not just a feature:** every check that parsed localized console output (`auditpol`, `net accounts`, `netsh`, SFC/DISM) or matched localized identity names (`Administrators`, `Guest`, `Everyone`, `NT AUTHORITY\SYSTEM`) has been rewritten to use **APIs, GUIDs and SIDs** — the module now produces correct results on Turkish, German, French and other non-English Windows display languages, and reports an honest *"unable to determine"* instead of a silent wrong PASS when data is unreachable. Known exception: `Get-FileSystemJournal` still parses English `fsutil` output (see [Known Limitations](#-known-limitations)).

**New internal data sources (`Private/`, 4 helpers):**

| Helper | Replaces | How |
|--------|----------|-----|
| **`Get-AuditPolicyTable`** | localized `auditpol /get` text parsing | `AuditQuerySystemPolicy` P/Invoke (GUID-keyed) → elevated `auditpol /backup` fixed-header CSV (numeric Setting Value) → GUID-addressed `/get` with honest unknowns; full **59-subcategory GUID map** (MS-GPAC) |
| **`Get-LocalPasswordPolicy`** | localized `net accounts` parsing | `NetUserModalsGet` levels 0+3 (non-admin, binary API) with elevated `secedit /export` fallback for `PasswordComplexity` |
| **`Get-WlanProfileList`** | localized `netsh wlan show profiles` | `wlanapi.dll` P/Invoke; missing WLAN service/feature = "not applicable", not an error |
| **Identity helpers** | name-based group/user/ACL lookups | SID-first (`S-1-5-32-544`, RID 500/501, `S-1-1-0`…) with ADSI fallback; safe under 32-bit PowerShell and AzureAD unresolvable SIDs |

**27 call sites migrated across 16 files** — compliance frameworks (CIS/NIST/PCI-DSS), enterprise assessment & fleet scans, audit-policy hardening (GUID-based `/set` — `Enable-AuditPolicies` previously only worked on English Windows), registry/ACL analysis, defense-evasion detection, SFC/DISM integrity, memory-dump and scheduled-scan **ACL lockdowns (these silently failed on non-English systems, leaving credential-bearing files world-readable)**.

**Regression armor:** new `tests/Locale.Regression.Tests.ps1` — English/German (ANSI cp1252) auditpol fixture equivalence tests, plus a static **"no text readers" guard** that fails CI if localized-output parsing ever re-enters the codebase.

### v1.5.0 — Fleet Scans, Sysmon Analytics, SIEM Streaming & Smart Alerts

**3 new functions** — bringing the toolkit to **72 functions across 14 modules**:

| Function | Module | What It Does |
|----------|--------|--------------|
| **`Send-SiemEvent`** | Response | Stream findings directly to your SIEM over HTTP: **Splunk HEC** (`Splunk <token>` auth header), **Microsoft Sentinel** (Log Analytics Data Collector API with the documented HMAC-SHA256 **SharedKey signature**), or a **generic webhook** with custom headers — in **NDJSON or CEF** with batching (`-BatchSize`), exponential-backoff retry on HTTP 429/5xx (`-MaxRetries`, `-ThrottleMs`), and the token **masked** in all console output |
| **`Get-SysmonAnalytics`** | Detection | Deep **Sysmon Operational log analytics** (requires Sysmon; returns `NotAvailable` gracefully when absent): Event 1 process chains & command-line indicators, Event 3 network **beaconing**, Event 7 image loads, Event 10 process access with **LSASS access-mask** analysis (T1003.001), Event 11 file creates, Events 12/13 registry writes, Event 22 DNS anomalies — every finding carries a MITRE ATT&CK `Technique` property; `-Hours`, `-EventTypes`, `-MaxEvents` filtering |
| **`Get-FileSystemJournal`** | Forensics | File-system journal evidence via **fsutil** (requires elevation): **USN journal** parsing with reason decoding and **executable-creation evidence**, **MFT summary** statistics (summary-level only — no raw $MFT record parsing), and a **TimestompScan** mode that cross-checks file timestamps against journal creation records and is explicitly labeled **heuristic**; `-DriveLetter`, `-MaxRecords`, CSV `-OutputPath` |

**Extended parameters on existing functions:**

- `Invoke-EnterpriseSecurityScan -UseModuleFunctions -RemoteFunctionSet Quick/Standard/Deep` — **deploy the module to remote hosts** (zip → `Copy-Item -ToSession` → remote `Import-Module`) instead of shipping embedded script blocks; plus a parallel **connectivity probe** (`-ProbeTimeoutSec`), **per-host timeout** (`-HostTimeoutSec`), **CSV target input** (`-TargetFile`), a `-WhatIf` deployment preview, and `finally`-block session disposal
- `Register-ScheduledSecurityScan` — **alert dedup is now on by default**: findings are fingerprinted into `State\last-findings.json` and classified **New / Persisting / Resolved**, so repeat alerts are suppressed until `-RealertAfterDays` (default 7) elapses; opt out with `-DisableAlertDedup`; a broken state file degrades to normal alerting, never to silence
- `Get-ThreatIntelligence` — **TAXII pagination** (follows `more`/`next` up to a 20-page cap, reporting `PagesFetched`/`ObjectsFetched`) and **MISP attribute types expanded to 12** (adds hostname, uri, sha1, email-src, email-dst, filename, mutex → new `EmailIndicators`, `FileNameIndicators`, `MutexIndicators` lists)
- `Resolve-CpeName` — curated offline table grown to **~120 products** plus **vendor-scheme translation** for version schemes (Java/.NET/Python and friends), surfaced as `MatchedBy = 'SchemeTranslation'` with an `OriginalVersion` property
- `Export-SecurityReport -StreamTo/-StreamUri/-StreamToken/-StreamFormat` — **stream findings to a SIEM** right after report export via `Send-SiemEvent`

**Quality infrastructure:**

- 🧪 **413 Pester tests** (`tests/WindowsSecurityAudit.Tests.ps1`) — new coverage for v1.5 parameter help, SIEM token-masking AST checks, hardcoded-secret checks on the new files, MITRE `Technique` attachment, heuristic timestomp labeling, and the fingerprint state logic embedded in the generated scan script

### v1.4.0 — SIEM Integration, Credential & Evasion Detection, Forensic Integrity

**4 new functions** — bringing the toolkit to **69 functions across 14 modules**:

| Function | Module | What It Does |
|----------|--------|--------------|
| **`ConvertTo-SiemEvent`** | Response | Pipe findings straight into your SIEM: converts finding objects to **NDJSON** (one compact JSON object per line) or **CEF** (`CEF:0` strings) for Splunk, Microsoft Sentinel, QRadar and ArcSight — with `-HostName`/`-ProductVersion` stamping, severity mapping, and MITRE technique ID passthrough when a finding exposes one |
| **`Get-CredentialAccessEvents`** | Detection | Runtime credential-access detection: **Kerberoasting** (4769 RC4 service-ticket bursts), anomalous **TGT request volumes** (4768), Kerberos pre-auth failure spikes / **password spray** (4771), and a best-effort **golden-ticket heuristic** (Kerberos logons with no matching TGT in the window — explicitly labeled `Heuristic`/`Medium` confidence), plus optional **LSASS access** enumeration (`-IncludeLSASSAccess`; Security 4663 requires Object Access auditing with a SACL on lsass.exe, or Sysmon event 10) |
| **`Find-DefenseEvasion`** | Detection | Defense-evasion & tamper detection: **AMSI bypass and ETW tamper patterns** in PowerShell script-block logs (4104), **Defender tampering** (exclusions, disabled real-time/behavior monitoring, 5001/5007 events), **log clearing** (1102/104) and audit policy changes (4719) **with clearing-account attribution**, and optional heuristic **log-gap analysis** (`-IncludeLogGapAnalysis`) — every finding carries a MITRE ATT&CK `Technique` property |
| **`Get-UserActivityArtifacts`** | Forensics | Per-user DFIR artifacts: **Recycle Bin `$I` parsing** (v2 headers fully decoded, v1 best-effort; original path, size, deletion FILETIME), **LNK shortcut resolution** via WScript.Shell COM, **JumpList enumeration** (AutomaticDestinations — enumeration-level only, embedded targets are *not* parsed), and **ActivitiesCache.db raw copies** (metadata only, no SQLite parsing) with optional CSV export |

**Extended parameters on existing functions:**

- `Export-SecurityReport -Format NDJSON/CEF` — export findings in SIEM-ready formats via `ConvertTo-SiemEvent` (`All` now writes `.ndjson` + `.cef` alongside HTML/JSON/CSV); new `-NoAutoOpen` switch skips opening the HTML report for headless/SYSTEM-context runs
- `Find-SuspiciousAuthentication` — now also flags **4624 Type 9 (NewCredentials)** explicit-credential logons and **per-account NTLM network logon indicators**
- `Get-ArtifactCollection` — **per-file SHA256 at acquisition time**, raw registry hive capture via `reg save`, and an **AcquisitionLog manifest block** for chain of custody
- `Get-CloudComplianceStatus` — now honest about coverage: checks that can't be evaluated report **`NotEvaluated`** instead of fabricated statuses, and the compliance score is `$null` when nothing was evaluated

**Distribution & trust:**

- 📜 **CHANGELOG.md** and **SECURITY.md** (vulnerability disclosure policy) added to the repo
- 🚀 **PowerShell Gallery publish workflow** (`.github/workflows/publish.yml`) — publishes on release once a gallery API key is configured
- 📦 Real module metadata in `WindowsSecurityAudit.psd1`

**Quality infrastructure:**

- 🧪 **385 Pester tests** (`tests/WindowsSecurityAudit.Tests.ps1`) — new coverage for v1.4 parameter help, hardcoded-secret AST checks on the new files, MITRE `Technique` attachment, heuristic labeling, and timestamp provenance (artifacts never fabricate timestamps)

### v1.3.0 — Version-Exact CVEs, MISP/TAXII & Auto-Remediation

**2 new functions** — bringing the toolkit to **65 functions across 14 modules**:

| Function | Module | What It Does |
|----------|--------|--------------|
| **`Resolve-CpeName`** | Vulnerability | Resolve an installed product to a **CPE 2.3 name** via a curated offline mapping table (~35 common products), an optional **NVD CPE API** lookup (`-UseOnlineLookup -ApiKey`), or a heuristic guess (always **Low** confidence) — returns `CpeName`, `MatchedBy`, `Confidence` and `Version` |
| **`Invoke-SecurityRemediation`** | Hardening | Close the finding→fix loop: consume an `Invoke-SecurityAssessment` JSON (or piped findings), apply a **curated map of 7 safe remediations** (firewall profiles, UAC, Defender RTP, SMBv1, Guest account, PS script block logging, RDP NLA) **WhatIf-first** with `SupportsShouldProcess`/`ConfirmImpact=High`, optional `-GenerateRollback` script capturing pre-change state — unmatched findings go to `ManualReview`, never improvised |

**Wired-up parameters on existing functions:**

- `Get-VulnerabilityAssessment -ExactCVEMatch` — resolve each installed product to a CPE name and query NVD for **version-exact CVE matches** (implies `-CheckCVEs`, reuses `-NVDApiKey`/`-MaxCVEChecks`); High/Medium-confidence CPE matches query via `Get-NVDCveData -CpeName`, results attach as `ExactCVEs` per application with `MatchStatus` (`CpeMatched`/`NoCpeMapping`) plus `TotalExactCVEs` and per-severity counts in the summary
- `Get-ThreatIntelligence -MISPUrl -MISPApiKey` — pull indicators from a **MISP** instance via `attributes/restSearch` (key sent only as a request header)
- `Get-ThreatIntelligence -TaxiiServerUrl -TaxiiCollection [-TaxiiUsername -TaxiiPassword]` — pull STIX indicators from a **TAXII 2.x** server (discovery → collections → objects; password is a `SecureString`, sent only as a Basic auth header)
- `Get-ThreatIntelligence -StixFilePath` — import a local **STIX 2.x bundle** fully offline; regex extraction of ipv4-addr/domain-name/url/file-hash patterns — all sources share the existing cache, entry-cap and provenance machinery

**Quality infrastructure:**

- 🧪 **353 Pester tests** (`tests/WindowsSecurityAudit.Tests.ps1`) — new coverage for v1.3 parameter help, secret-handling AST checks (no API keys in log output, `SecureString` TAXII password), and remediation safety (ShouldProcess gating, ManualReview routing)

### v1.2.0 — Live Threat Feeds & Real CVE Integration

**1 new function** — bringing the toolkit to **63 functions across 14 modules**:

| Function | Module | What It Does |
|----------|--------|--------------|
| **`Get-NVDCveData`** | Vulnerability | Query the **NVD API 2.0** by keyword or CPE name and get normalized CVE objects (ID, severity, CVSS score, dates, references) — with pagination, rate-limit handling and optional API key for higher limits |

**Wired-up parameters on existing functions:**

- `Get-VulnerabilityAssessment -CheckCVEs -NVDApiKey -MaxCVEChecks` — match installed software against **real NVD CVE data** (keyword-based candidate matching, capped by `-MaxCVEChecks`, default 10); matched CVEs attach as `RealCVEs` on each Software item plus summary counts
- `Get-ThreatIntelligence -UpdateFeeds -FeedCachePath -FeedMaxAgeHours -MaxFeedEntries -AbuseIPDBApiKey` — merge **live abuse.ch feeds** (URLhaus payload URLs, Feodo Tracker C2 IPs) plus the optional **AbuseIPDB** blacklist (with API key) into the IOC database, with freshness-aware caching, offline fallback and per-feed `Summary.FeedStats`

**Quality infrastructure:**

- 🧪 **333 Pester tests** (`tests/WindowsSecurityAudit.Tests.ps1`) covering the public API surface, API-key hygiene, and offline feed behavior

### v1.1.0 — Baseline Drift, Scheduled Scans, ATT&CK Navigator & Consolidated Reports

**4 new functions** added to the toolkit:

| Function | Module | What It Does |
|----------|--------|--------------|
| **`Compare-SecurityBaseline`** | Core | Detect configuration drift by diffing two security baselines — Improved/Degraded/New/Removed classification with JSON/CSV export |
| **`Register-ScheduledSecurityScan`** | Enterprise | Automate recurring scans (daily/weekly/monthly) via Scheduled Tasks with **Teams/Slack webhook** and email alerting on Critical findings |
| **`Export-AttackNavigatorLayer`** | Threat Hunting | Export hunt findings as a **MITRE ATT&CK Navigator layer** (JSON v4.x) with severity-based scoring and colors — visualize coverage in one click |
| **`New-ConsolidatedReport`** | Reporting | Generate a **single interactive Chart.js HTML report** combining results from all modules, with offline mode from saved JSON |

**Wired-up parameters on existing functions:**

- `Invoke-SecurityAssessment -IncludeCompliance` — now runs CIS, NIST 800-53, and PCI-DSS checks as part of the assessment
- `Get-ExposedServices -CustomPorts` — scan your own port list beyond the built-in attack-surface checks
- `Get-ComplianceReport -IncludeEvidence` — bundle audit-ready evidence directly into compliance reports
- `New-ExecutiveReport -CustomLogo` — brand executive reports with your organization's logo
- `Export-SecurityReport -IncludeCharts` — embed visual charts in exported reports

**Quality infrastructure:**

- 🧪 **Pester test suite** (`tests/`) covering the public API surface plus real-Windows smoke tests and locale-regression fixtures (now 518 tests)
- ⚙️ **GitHub Actions CI** (`.github/workflows/ci.yml`) on windows-latest: PSScriptAnalyzer Error gate, module import verified under both **PowerShell 7 (pwsh)** and **Windows PowerShell 5.1**, plus the full Pester suite and a real-Windows smoke job

### 📦 Already in the Toolbox (v1.0.0)

Everything below shipped with the original release and keeps getting sharper:

| Category | Highlights |
|----------|------------|
| **Core Security** | `Get-SecurityBaseline` (0-100 posture score), `Get-SystemInfo`, `Test-SystemIntegrity` (SFC/DISM), `Get-EventIdDescription` |
| **Threat Detection** | Persistence mechanisms, suspicious processes, network anomalies, authentication attacks (brute force, lockouts, after-hours) |
| **Threat Hunting** | APT indicators, data exfiltration, lateral movement, LOLBins abuse, MITRE ATT&CK mapping, IOC matching (incl. custom IOC files) |
| **Compliance** | CIS Benchmark, NIST 800-53, PCI-DSS 4.0 validation with audit-ready evidence export |
| **Vulnerability Management** | CVE assessment, EOL software, exposed services, certificate health, patch compliance |
| **Active Directory** | Backdoor & DCSync detection, privileged account audit, stale objects, password policies, security posture |
| **Forensics & Response** | Memory dumps, USB history, execution artifacts, forensic timelines, one-command incident response |
| **Enterprise & Reporting** | Multi-system parallel scanning, executive reports, live HTML dashboards, security metrics & KPIs |
| **Cloud Security** | Azure AD risky sign-ins, M365 security posture, cloud compliance status |
| **Hardening** | Audit policies, PowerShell security (logging, transcription), security baseline enforcement — all with `-WhatIf` support |

---

## 🎯 Use Case Scenarios

### For Security Operations Centers (SOC)
- **On-Demand & Scheduled Scanning**: Automated recurring scans with alerting
- **Incident Response**: Rapid containment and investigation
- **Threat Hunting**: Proactive APT detection
- **Metrics Tracking**: Security-metrics dashboards

### For IT Administrators
- **Daily Checks**: Automated morning security reports
- **Patch Management**: Vulnerability and update tracking
- **Compliance**: Audit preparation and evidence
- **System Hardening**: Security baseline implementation

### For Security Consultants
- **Assessments**: Comprehensive security evaluations
- **Penetration Testing**: Post-exploitation validation
- **Compliance Audits**: Multi-framework validation
- **Executive Reporting**: Professional deliverables

### For Managed Service Providers (MSP)
- **Multi-Tenant**: Isolated customer assessments
- **Scalability**: Thousands of endpoints
- **Automation**: Scheduled scanning
- **White-Label**: Customizable reports

---

## 📈 Performance & Optimization

Actual scan times depend on the target's hardware, event-log sizes and the modules selected — measure on your own systems rather than trusting generic figures.

### Performance Tuning
- **Parallel Processing**: Multi-system scans run in parallel (up to 50 threads) with configurable throttling
- **Per-Host Timeouts**: Connectivity probes and per-host timeout controls in fleet scans
- **Smart Caching**: Threat-intel feeds are cached with freshness-aware fallback
- **Selective Scanning**: Run only the modules and checks you need via function parameters

---

## ⚠️ Known Limitations

- **DISM/SFC verdicts rely on CBS.log markers** — `Test-SystemIntegrity` interprets servicing-log markers rather than performing a full image analysis.
- **USN journal parsing requires English-locale `fsutil` output** — `Get-FileSystemJournal` parses `fsutil` text; full locale-invariant `FSCTL_READ_USN_JOURNAL` parsing is on the [v1.7 roadmap](#-roadmap).
- **Cloud compliance is a catalog, not an evaluation** — `Get-CloudComplianceStatus` returns `NotEvaluated` until framework-specific Microsoft Graph queries are implemented.
- **No in-module memory acquisition** — full RAM capture requires external tools (WinPMEM, DumpIt, Magnet RAM Capture); `Export-MemoryDump` creates per-process dumps.

---

## 💎 Free & Open Source

### Community Edition - Forever FREE
- ✅ **Price**: 100% FREE - No hidden costs
- ✅ **Functions**: All 72 functions included
- ✅ **Source Code**: Full access on GitHub
- ✅ **Updates**: Regular security updates
- ✅ **License**: MIT (commercial use allowed)
- ✅ **Support**: Community-driven

### Why Free?
We believe enterprise-grade security should be accessible to everyone. This project is our contribution to the security community.

---

## 🤝 Contributing

We welcome contributions from the security community! 

### How to Contribute
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Contribution Guidelines
- Follow PowerShell best practices
- Include Pester tests for new functions
- Update documentation
- Sign commits with GPG

### Development Setup
```powershell
# Clone repository
git clone https://github.com/okanyildiz/WindowsSecurityAudit.git
cd WindowsSecurityAudit

# Install development dependencies
Install-Module -Name Pester, PSScriptAnalyzer -Force

# Run tests
Invoke-Pester -Path .\tests\

# Run linter
Invoke-ScriptAnalyzer -Path . -Recurse
```

---

## 📞 Support & Contact

### 💬 Community Support (Free)

- 📖 [GitHub Discussions](https://github.com/okanyildiz/WindowsSecurityAudit/discussions) - Ask questions, share experiences
- 🐛 [Issue Tracker](https://github.com/okanyildiz/WindowsSecurityAudit/issues) - Report bugs, request features
- 📚 [Wiki Documentation](https://github.com/okanyildiz/WindowsSecurityAudit/wiki) - Comprehensive guides
- 💡 [Feature Requests](https://github.com/okanyildiz/WindowsSecurityAudit/issues/new?labels=enhancement) - Suggest improvements

Found this useful? You can support development via [Buy Me a Coffee](https://buymeacoffee.com/okanyildizr). Security issues: see [SECURITY.md](SECURITY.md).

---

## 🚀 Roadmap

### Version 1.7 (Next)
- [ ] **Raw $MFT record parsing** — go beyond fsutil summary output for full file-system timelines (locale-invariant `FSCTL_READ_USN_JOURNAL` P/Invoke replaces fsutil text parsing)
- [ ] **JEA endpoint support** — run remote scans through Just Enough Administration constrained endpoints (CLM-safe: precompiled helpers, no Add-Type dependency)
- [ ] **Alert webhook DPAPI protection** — encrypt stored webhook URLs at rest
- [ ] **SIEM streaming auth profiles** — named credential profiles and OAuth flows for Send-SiemEvent

### Version 1.6 (Released)
- [x] **Locale-invariant core checks** — localized `auditpol` / `net accounts` / `netsh` / SFC-DISM parsing and name-based identity lookups replaced by APIs, GUIDs and SIDs; correct results on non-English Windows with honest "unable to determine" states (exception: `Get-FileSystemJournal` fsutil parsing, see [Known Limitations](#-known-limitations))

### Version 2.0 (Future)
- [ ] Web-based GUI dashboard
- [ ] REST API for remote management
- [ ] Linux/macOS PowerShell Core support
- [ ] Machine learning anomaly detection
- [ ] Container security scanning
- [ ] Kubernetes integration
- [ ] Cloud-native architecture
- [ ] Mobile app for monitoring
- [ ] AI-powered threat hunting

### Long-term Vision
- Become the industry standard for Windows security assessment
- Build a thriving ecosystem of security modules
- Enable zero-trust architecture validation
- Integrate quantum-resistant cryptography checks


---

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ⚠️ No liability
- ⚠️ No warranty

---

## 🙏 Acknowledgments

### Core Contributors
- **Okan Yildiz** - Project Creator & Lead Developer



### Sponsors
Supporting the development of enterprise security tools:
- [Secure Debug Limited](https://securedebug.com/)

---

<div align="center">

## ⭐ Support This Project

**If this tool has helped secure your environment, please consider:**


[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-%E2%98%95-orange?style=for-the-badge)](https://buymeacoffee.com/okanyildizr)

### 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=okanyildiz/WindowsSecurityAudit&type=Date)](https://star-history.com/#okanyildiz/WindowsSecurityAudit&Date)

### 📈 Join Our Growing Community

<a href="https://github.com/okanyildiz/WindowsSecurityAudit/stargazers">
  <img src="https://img.shields.io/github/stars/okanyildiz/WindowsSecurityAudit" alt="GitHub stars">
</a>
<a href="https://github.com/okanyildiz/WindowsSecurityAudit/network/members">
  <img src="https://img.shields.io/github/forks/okanyildiz/WindowsSecurityAudit" alt="GitHub forks">
</a>


---

**🔒 Securing Windows Environments Since 2025**

**Made with ❤️ and ☕ by the Security Community**

**© 2025-2026 Windows Security Audit Module - Enterprise Security Democratized**

</div>
