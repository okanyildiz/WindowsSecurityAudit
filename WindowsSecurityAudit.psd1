@{
    RootModule = 'WindowsSecurityAudit.psm1'
    ModuleVersion = '1.6.2'
    GUID = 'a8d7c4e5-3b2f-4e8a-9c1d-6f5a8b9d2e7c'
    Author = 'Okan YILDIZ'
    CompanyName = 'okanyildiz'
    Copyright = '(c) 2026 Okan YILDIZ. All rights reserved.'
    Description = 'Comprehensive Windows security audit and DFIR toolkit: 72 functions across 14 categories - threat hunting (MITRE ATT&CK mapping, lateral movement, LOLBins, data exfiltration), compliance (CIS Benchmark, NIST 800-53, PCI-DSS), vulnerability management (NVD CVE matching, CPE resolution, EOL software), forensics (artifact collection, memory dumps, USN journal, Sysmon analytics), SIEM integration (Splunk HEC, Microsoft Sentinel, CEF/NDJSON), threat intelligence feeds (abuse.ch, AbuseIPDB, MISP, TAXII/STIX), Active Directory security, hardening baselines and automated remediation. Runs on Windows PowerShell 5.1+ and PowerShell 7. Locale-invariant core checks since v1.6.0: compliance, audit-policy, account and ACL checks use APIs, GUIDs and SIDs instead of localized console output (correct results on Turkish, German, French and other non-English Windows). Known exception: Get-FileSystemJournal still parses English fsutil output (see README Known Limitations). Core checks are dependency-free; AD functions require the ActiveDirectory module (RSAT) and cloud functions the Microsoft Graph SDK. Free and open source - support development: https://buymeacoffee.com/okanyildizr'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @(
        'Compare-SecurityBaseline',
        'ConvertTo-SiemEvent',
        'Enable-AuditPolicies',
        'Enable-PowerShellSecurity',
        'Export-AttackNavigatorLayer',
        'Export-ComplianceEvidence',
        'Export-MemoryDump',
        'Export-SecurityReport',
        'Find-ADBackdoors',
        'Find-ADVulnerabilities',
        'Find-APTIndicators',
        'Find-DataExfiltration',
        'Find-DefenseEvasion',
        'Find-EOLSoftware',
        'Find-LateralMovement',
        'Find-LivingOffLand',
        'Find-NetworkAnomalies',
        'Find-PersistenceMechanisms',
        'Find-StaleADObjects',
        'Find-SuspiciousAuthentication',
        'Find-SuspiciousProcesses',
        'Get-ADPasswordPolicy',
        'Get-ADPrivilegedAccounts',
        'Get-ArtifactCollection',
        'Get-AzureADRiskySignIns',
        'Get-CloudComplianceStatus',
        'Get-ComplianceReport',
        'Get-CredentialAccessEvents',
        'Get-DefenderStatus',
        'Get-EventIdDescription',
        'Get-EventLogAnalysis',
        'Get-ExecutionArtifacts',
        'Get-ExposedServices',
        'Get-FileSystemAnalysis',
        'Get-FileSystemJournal',
        'Get-MemoryAnalysis',
        'Get-MITREAttackMapping',
        'Get-MultiSystemAudit',
        'Get-NVDCveData',
        'Get-RegistryAnalysis',
        'Get-SecurityBaseline',
        'Get-SecurityMetrics',
        'Get-SecurityMisconfigurations',
        'Get-SysmonAnalytics',
        'Get-SystemInfo',
        'Get-ThreatIntelligence',
        'Get-USBHistory',
        'Get-UserActivityArtifacts',
        'Get-VulnerabilityAssessment',
        'Invoke-DefenderScan',
        'Invoke-EnterpriseSecurityScan',
        'Invoke-ForensicCollection',
        'Invoke-IncidentResponse',
        'Invoke-SecurityAssessment',
        'Invoke-SecurityRemediation',
        'New-ConsolidatedReport',
        'New-ExecutiveReport',
        'New-ForensicTimeline',
        'New-SecurityDashboard',
        'Register-ScheduledSecurityScan',
        'Resolve-CpeName',
        'Send-SiemEvent',
        'Set-SecurityBaseline',
        'Test-ADSecurityPosture',
        'Test-CertificateHealth',
        'Test-CISBenchmark',
        'Test-M365SecurityPosture',
        'Test-NISTCompliance',
        'Test-PatchCompliance',
        'Test-PciDssCompliance',
        'Test-SystemIntegrity',
        'Update-DefenderConfiguration'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @('Test-PCI-DSS')
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Audit', 'DFIR', 'ThreatHunting', 'Compliance', 'MITRE', 'IncidentResponse', 'Vulnerability', 'Windows', 'BlueTeam')
            LicenseUri = 'https://github.com/okanyildiz/WindowsSecurityAudit/blob/main/LICENSE'
            ProjectUri = 'https://github.com/okanyildiz/WindowsSecurityAudit'
            ReleaseNotes = 'https://github.com/okanyildiz/WindowsSecurityAudit/releases'
        }
    }
}
