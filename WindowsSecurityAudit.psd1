@{
    RootModule = 'WindowsSecurityAudit.psm1'
    ModuleVersion = '1.6.0'
    GUID = 'a8d7c4e5-3b2f-4e8a-9c1d-6f5a8b9d2e7c'
    Author = 'Okan YILDIZ'
    CompanyName = 'okanyildiz'
    Copyright = '(c) 2026 Okan YILDIZ. All rights reserved.'
    Description = 'Windows Security Audit Module'
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
