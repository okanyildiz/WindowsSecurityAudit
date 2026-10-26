@{
    RootModule = 'WindowsSecurityAudit.psm1'
    ModuleVersion = '1.6.0'
    GUID = 'a8d7c4e5-3b2f-4e8a-9c1d-6f5a8b9d2e7c'
    Author = 'Okan YILDIZ'
    CompanyName = 'okanyildiz'
    Copyright = '(c) 2026 Okan YILDIZ. All rights reserved.'
    Description = 'Comprehensive Windows security audit and DFIR toolkit: 72 functions across 14 categories — threat hunting (MITRE ATT&CK mapping, lateral movement, LOLBins, data exfiltration), compliance (CIS Benchmark, NIST 800-53, PCI-DSS), vulnerability management (NVD CVE matching, CPE resolution, EOL software), forensics (artifact collection, memory dumps, USN journal, Sysmon analytics), SIEM integration (Splunk HEC, Microsoft Sentinel, CEF/NDJSON), threat intelligence feeds (abuse.ch, AbuseIPDB, MISP, TAXII/STIX), Active Directory security, hardening baselines and automated remediation. Runs on Windows PowerShell 5.1+ and PowerShell 7. Fully locale-invariant since v1.6.0: all checks use APIs, GUIDs and SIDs instead of parsing localized console output, producing correct results on non-English Windows (Turkish, German, French, ...). Zero external dependencies. Free and open source — support development: https://buymeacoffee.com/okanyildizr'
    PowerShellVersion = '5.1'
    FunctionsToExport = '*'
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Audit', 'DFIR', 'ThreatHunting', 'Compliance', 'MITRE', 'IncidentResponse', 'Vulnerability', 'Windows', 'BlueTeam')
            LicenseUri = 'https://github.com/okanyildiz/WindowsSecurityAudit/blob/main/LICENSE'
            ProjectUri = 'https://github.com/okanyildiz/WindowsSecurityAudit'
            ReleaseNotes = 'https://github.com/okanyildiz/WindowsSecurityAudit/releases'
        }
    }
}
