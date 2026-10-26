#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Real-Windows execution smoke tests for the WindowsSecurityAudit module.
.DESCRIPTION
    Unlike tests/WindowsSecurityAudit.Tests.ps1 (structural, cross-platform), this suite
    IMPORTS the module and EXECUTES its exported functions against the live system with
    safe, fast parameters. No mocks. GitHub-hosted windows-latest runners are elevated,
    so admin-only calls (fsutil, Security event log, HKLM) genuinely work there.

    Assertions are deliberately shape-based: an empty result set is a valid outcome on a
    clean runner (assert structure, not content); a THROW is a failure.

    Platform guard: the whole Describe block is skipped on non-Windows platforms, so
    `Invoke-Pester -Path ./tests` on macOS/Linux stays green (tests report as Skipped).

    Run standalone on Windows:
        Invoke-Pester -Path ./tests/Smoke.Windows.Tests.ps1

    Deliberately excluded (skipped with reasons at the bottom):
      * Test-SystemIntegrity      - runs 'sfc /scannow' + DISM (10+ minutes)
      * Get-SecurityMetrics Core  - transitively invokes Test-SystemIntegrity (SFC/DISM)
      * Export-MemoryDump         - interactive (Read-Host)
      * Invoke-IncidentResponse, Set-SecurityBaseline, Register-ScheduledSecurityScan,
        Send-SiemEvent            - destructive or require real endpoints; WhatIf-covered
                                    alternatives are exercised where supported
.NOTES
    The module targets Windows PowerShell 5.1+, so only 5.1-compatible syntax is used
    here (this file is executed under both pwsh 7 and powershell 5.1 in CI).
#>

BeforeDiscovery {
    # Platform guard: evaluate once at discovery time and skip the entire Describe on
    # non-Windows hosts. $IsWindows only exists on PowerShell 6+; on Windows PowerShell
    # 5.1 (which only ships on Windows) fall back to $env:OS.
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $script:IsWindowsHost = [bool]$IsWindows
    }
    else {
        $script:IsWindowsHost = ($env:OS -eq 'Windows_NT')
    }
}

Describe 'WindowsSecurityAudit real-Windows smoke tests' -Tag @('Smoke', 'Windows') -Skip:(-not $script:IsWindowsHost) {

    BeforeAll {
        $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path -Path $script:ModuleRoot -ChildPath 'WindowsSecurityAudit.psd1') -Force -ErrorAction Stop

        # Asserts that $Object is non-null and exposes every property in $Names.
        # Property names below were verified against each function's source file.
        function Assert-ResultShape {
            param(
                [Parameter(Mandatory = $true)]
                [AllowNull()]
                [object]$Object,

                [Parameter(Mandatory = $true)]
                [string[]]$Names
            )
            $Object | Should -Not -BeNullOrEmpty
            foreach ($name in $Names) {
                $Object.PSObject.Properties.Name | Should -Contain $name
            }
        }
    }

    # ---------------------------------------------------------------- Core
    It 'Get-EventIdDescription returns a description for event 4625' {
        $result = Get-EventIdDescription -EventId 4625
        Assert-ResultShape -Object $result -Names @('EventId', 'Source', 'Category', 'Description', 'Severity', 'MITREAttack', 'SecurityImplication', 'RecommendedAction')
        $result.EventId | Should -Be 4625
        $result.Description | Should -Be 'An account failed to log on'
    }

    It 'Get-SecurityBaseline returns a baseline object' {
        $result = Get-SecurityBaseline
        Assert-ResultShape -Object $result -Names @('ComputerName', 'ScanDate', 'WindowsDefender', 'Firewall', 'UAC', 'BitLocker', 'WindowsUpdate', 'SecurityScore')
    }

    It 'Get-SystemInfo returns system information without optional switches' {
        $result = Get-SystemInfo
        Assert-ResultShape -Object $result -Names @('CollectionDate', 'ComputerSystem', 'OperatingSystem', 'Hardware', 'Network', 'Security')
    }

    # ------------------------------------------------------------ Detection
    It 'Find-SuspiciousProcesses executes and returns score-shaped objects when non-empty' {
        $result = @(Find-SuspiciousProcesses)
        # An empty result set is a valid outcome on a clean runner
        foreach ($item in $result) {
            Assert-ResultShape -Object $item -Names @('SuspicionScore')
        }
    }

    It 'Find-PersistenceMechanisms returns the persistence report object' {
        $result = Find-PersistenceMechanisms
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'RegistryRunKeys', 'StartupFolder', 'ScheduledTasks', 'Services', 'WMISubscriptions', 'TotalFindings', 'SuspiciousCount')
    }

    It 'Find-NetworkAnomalies returns the anomaly report object' {
        # Note: this function has no -Hours parameter (only -IncludeEstablished/-CheckDNS)
        $result = Find-NetworkAnomalies
        Assert-ResultShape -Object $result -Names @('ScanDate', 'SuspiciousListeners', 'SuspiciousConnections', 'UnusualPorts', 'DNSAnomalies', 'TotalAnomalies')
    }

    It 'Find-SuspiciousAuthentication -Hours 1 returns the analysis object' {
        $result = Find-SuspiciousAuthentication -Hours 1
        Assert-ResultShape -Object $result -Names @('AnalysisDate', 'TimeRange', 'FailedLogons', 'AccountLockouts', 'PrivilegeEscalations', 'BruteForceIndicators', 'Statistics')
        $result.TimeRange | Should -Be '1 hours'
    }

    It 'Get-CredentialAccessEvents -Hours 1 returns events, summary and recommendations' {
        $result = Get-CredentialAccessEvents -Hours 1
        Assert-ResultShape -Object $result -Names @('ScanDate', 'TimeRange', 'Events', 'Summary', 'Recommendations')
    }

    It 'Find-DefenseEvasion -Hours 1 returns findings with per-check status' {
        $result = Find-DefenseEvasion -Hours 1
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'TimeRange', 'EvasionFindings', 'Summary', 'CheckStatus', 'Recommendations')
    }

    It 'Get-SysmonAnalytics -Hours 1 degrades gracefully when Sysmon is absent' {
        $result = Get-SysmonAnalytics -Hours 1
        Assert-ResultShape -Object $result -Names @('ScanDate', 'TimeRange', 'Status', 'Findings', 'Summary', 'Recommendations')
        # Sysmon is not installed on GitHub-hosted runners; 'NotAvailable' must not throw
        $result.Status | Should -BeIn @('OK', 'NotAvailable')
        $result.Summary.SysmonPresent | Should -BeOfType [bool]
    }

    # ------------------------------------------------------- WindowsDefender
    It 'Get-DefenderStatus returns the Defender status object' {
        $result = Get-DefenderStatus
        Assert-ResultShape -Object $result -Names @('CollectionDate', 'ComputerName', 'ProtectionStatus', 'SignatureStatus', 'ScanHistory', 'Configuration', 'HealthStatus', 'Recommendations')
    }

    # ---------------------------------------------------------- Vulnerability
    It 'Get-VulnerabilityAssessment runs offline (no -CheckCVEs) and returns the assessment object' {
        $result = Get-VulnerabilityAssessment
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'ScanDepth', 'Software', 'Vulnerabilities', 'Summary', 'Recommendations')
    }

    It 'Get-ExposedServices returns listening-port findings' {
        $result = Get-ExposedServices
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'PublicIP', 'LocalIPs', 'ListeningPorts', 'ExposedServices', 'Summary', 'Recommendations')
    }

    It 'Get-SecurityMisconfigurations returns findings and summary' {
        $result = Get-SecurityMisconfigurations
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'OSVersion', 'Misconfigurations', 'Summary', 'Recommendations')
    }

    It 'Test-CertificateHealth returns certificate health summary' {
        $result = Test-CertificateHealth
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'TotalCertificates', 'HealthyCertificates', 'Issues', 'Summary', 'Recommendations')
    }

    It 'Test-PatchCompliance returns patch compliance summary' {
        $result = Test-PatchCompliance
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'OSVersion', 'InstalledUpdates', 'MissingUpdates', 'Summary', 'Recommendations')
    }

    It 'Find-EOLSoftware returns the EOL findings object' {
        $result = Find-EOLSoftware
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'TotalSoftware', 'EOLSoftware', 'ExpiringSoon', 'Summary', 'Recommendations')
    }

    # ------------------------------------------------------------- Compliance
    It 'Test-CISBenchmark -Level 1 returns controls and summary' {
        $result = Test-CISBenchmark -Level 1
        Assert-ResultShape -Object $result -Names @('TestDate', 'ComputerName', 'CISLevel', 'Category', 'Controls', 'Summary', 'Recommendations')
        $result.CISLevel | Should -Be 1
    }

    It 'Test-NISTCompliance returns controls and summary' {
        $result = Test-NISTCompliance
        Assert-ResultShape -Object $result -Names @('TestDate', 'ComputerName', 'NISTRevision', 'ControlFamily', 'Controls', 'Summary', 'Recommendations')
    }

    It 'Test-PCI-DSS -Version 4.0 returns requirements and summary' {
        $result = Test-PCI-DSS -Version '4.0'
        Assert-ResultShape -Object $result -Names @('TestDate', 'ComputerName', 'PCIDSSVersion', 'RequirementFilter', 'Requirements', 'Summary', 'Recommendations')
        $result.PCIDSSVersion | Should -Be '4.0'
    }

    # -------------------------------------------------------------- Analysis
    It 'Get-EventLogAnalysis -Hours 1 returns the analysis object' {
        $result = Get-EventLogAnalysis -Hours 1
        Assert-ResultShape -Object $result -Names @('AnalysisDate', 'TimeRange', 'SecurityEvents', 'SystemEvents', 'ApplicationEvents', 'CriticalErrors', 'Statistics')
    }

    # --------------------------------------------------------- ThreatHunting
    It 'Get-ThreatIntelligence matches built-in IOCs without -UpdateFeeds' {
        $result = Get-ThreatIntelligence -CheckProcesses
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'Matches', 'Summary', 'Recommendations')
    }

    It 'Find-LateralMovement returns indicators (uses -Days, not -Hours)' {
        $result = Find-LateralMovement -Days 1
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'AnalysisPeriod', 'Indicators', 'Summary')
    }

    It 'Find-LivingOffLand returns LOLBin detections object' {
        $result = Find-LivingOffLand
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'DetectedLOLBins', 'Summary', 'Recommendations')
    }

    It 'Find-APTIndicators returns indicators with threat score' {
        $result = Find-APTIndicators
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'Indicators', 'ThreatScore', 'RiskLevel', 'Summary')
    }

    It 'Find-DataExfiltration returns indicators (switch-based checks, no -Hours)' {
        $result = Find-DataExfiltration
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'ThresholdMB', 'Indicators', 'Summary')
    }

    It 'Get-MITREAttackMapping with defaults returns the mapping object' {
        $result = Get-MITREAttackMapping
        Assert-ResultShape -Object $result -Names @('AnalysisDate', 'ComputerName', 'DetectedTechniques', 'TacticBreakdown')
    }

    It 'Export-AttackNavigatorLayer exports a synthetic technique record' {
        $record = [PSCustomObject]@{
            TechniqueID   = 'T1078'
            TechniqueName = 'Valid Accounts'
            Tactic        = 'InitialAccess'
            Severity      = 'High'
        }
        $result = $record | Export-AttackNavigatorLayer -OutputPath $TestDrive -LayerName 'Smoke Test Layer'
        Assert-ResultShape -Object $result -Names @('LayerName', 'OutputPath', 'TechniqueCount', 'DetectionCount', 'NavigatorUrl')
        $result.TechniqueCount | Should -Be 1
        $result.OutputPath | Should -Exist
    }

    # -------------------------------------------------------------- Forensics
    It 'Get-USBHistory returns USB device history object' {
        $result = Get-USBHistory
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'USBDevices', 'ConnectionEvents', 'Summary')
    }

    It 'Get-ExecutionArtifacts returns the artifacts object' {
        $result = Get-ExecutionArtifacts
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'Artifacts', 'Summary')
    }

    It 'Get-ArtifactCollection -CollectionProfile Quick collects into TestDrive' {
        # Note: the profile parameter is -CollectionProfile (there is no -CollectionType)
        $outDir = Join-Path -Path $TestDrive -ChildPath 'artifacts'
        $result = Get-ArtifactCollection -CollectionProfile Quick -OutputPath $outDir
        Assert-ResultShape -Object $result -Names @('CollectionDate', 'ComputerName', 'Profile', 'OutputPath', 'ArtifactsCollected', 'Summary', 'CompressedArchive')
        $result.Profile | Should -Be 'Quick'
        $result.OutputPath | Should -Exist
    }

    It 'Get-UserActivityArtifacts returns the activity object' {
        $result = Get-UserActivityArtifacts
        Assert-ResultShape -Object $result -Names @('ScanDate', 'ComputerName', 'ProfilesAnalyzed', 'RecycleBin', 'RecentLinks', 'JumpLists', 'Timeline', 'Summary')
    }

    It 'Get-FileSystemJournal -Mode MFTSummary returns journal summary (fsutil, admin)' {
        $result = Get-FileSystemJournal -Mode MFTSummary
        Assert-ResultShape -Object $result -Names @('CollectionDate', 'ComputerName', 'DriveLetter', 'Mode', 'IsElevated', 'Records', 'Summary', 'Notes', 'Recommendations')
        $result.Mode | Should -Be 'MFTSummary'
    }

    It 'Get-FileSystemJournal -Mode USNJournal returns journal data (fsutil, admin)' {
        $result = Get-FileSystemJournal -Mode USNJournal
        Assert-ResultShape -Object $result -Names @('CollectionDate', 'ComputerName', 'DriveLetter', 'Mode', 'IsElevated', 'Records', 'Summary', 'Notes', 'Recommendations')
        $result.Mode | Should -Be 'USNJournal'
    }

    # -------------------------------------------------------------- Reporting
    It 'Get-SecurityMetrics -IncludeModules WindowsDefender returns aggregated metrics' {
        # DEVIATION from the original spec ('-IncludeModules Core'): the Core metrics
        # collector transitively invokes Test-SystemIntegrity ('sfc /scannow' + DISM,
        # 10+ minutes) and a full Invoke-SecurityAssessment, which would blow the
        # smoke-suite runtime budget. The WindowsDefender collector exercises the same
        # metrics pipeline via Get-DefenderStatus + Update-DefenderConfiguration -WhatIf.
        $result = Get-SecurityMetrics -IncludeModules WindowsDefender
        Assert-ResultShape -Object $result -Names @('Timestamp', 'Hostname', 'OverallSecurityScore', 'RiskLevel', 'Findings', 'Recommendations', 'ModulesCollected', 'WindowsDefender')
        $result.WindowsDefender.Enabled | Should -BeTrue
    }

    It 'New-ConsolidatedReport -SkipDataCollection writes a report into TestDrive' {
        $result = New-ConsolidatedReport -SkipDataCollection -OutputPath $TestDrive
        Assert-ResultShape -Object $result -Names @('Success', 'ReportPath', 'DataSource', 'SectionsCollected', 'SectionsNotCollected', 'TotalFindings', 'GenerationTime')
        $result.Success | Should -BeTrue
        $result.ReportPath | Should -Exist
    }

    # --------------------------------------------------------------- Response
    It 'ConvertTo-SiemEvent converts a synthetic finding to NDJSON and CEF' {
        $finding = [PSCustomObject]@{
            Severity       = 'High'
            Category       = 'SmokeTest'
            Finding        = 'Synthetic smoke-test finding'
            Impact         = 'None'
            Recommendation = 'No action required'
            TechniqueId    = 'T1078'
        }

        $ndjson = $finding | ConvertTo-SiemEvent -Format NDJSON
        $ndjson | Should -Not -BeNullOrEmpty
        $parsed = $ndjson | ConvertFrom-Json
        $parsed.product | Should -Be 'WindowsSecurityAudit'
        $parsed.severity | Should -Be 'High'
        $parsed.category | Should -Be 'SmokeTest'
        $parsed.technique_id | Should -Be 'T1078'

        $cef = $finding | ConvertTo-SiemEvent -Format CEF
        $cef | Should -Match '^CEF:0\|'
        $cef | Should -Match 'cs3=T1078'
    }

    It 'Export-SecurityReport -ReportType Technical -Format JSON writes a report file' {
        $result = @(Export-SecurityReport -ReportType Technical -Format JSON -NoAutoOpen -OutputPath $TestDrive)
        $result.Count | Should -BeGreaterThan 0
        foreach ($file in $result) {
            $file | Should -Exist
        }
    }

    # ------------------------------------------------------------------ Core (compare)
    It 'Compare-SecurityBaseline comparing a saved baseline to itself reports zero changes' {
        $baselinePath = Join-Path -Path $TestDrive -ChildPath 'baseline.json'
        Get-SecurityBaseline | ConvertTo-Json -Depth 6 | Out-File -FilePath $baselinePath -Encoding UTF8
        $result = Compare-SecurityBaseline -BaselinePath $baselinePath -CurrentPath $baselinePath
        Assert-ResultShape -Object $result -Names @('CompareDate', 'ComputerName', 'BaselineSource', 'CurrentSource', 'Categories', 'Changes', 'Summary')
        $result.Summary.TotalChanges | Should -Be 0
        $result.Summary.OverallTrend | Should -Be 'Stable'
    }

    # ------------------------------------------------------------- Enterprise
    It 'Invoke-SecurityAssessment -AssessmentType Basic writes SecurityAssessment.json' {
        $script:AssessmentDir = Join-Path -Path $TestDrive -ChildPath 'assess'
        $result = Invoke-SecurityAssessment -AssessmentType Basic -OutputPath $script:AssessmentDir
        Assert-ResultShape -Object $result -Names @('AssessmentDate', 'AssessmentType', 'ComputerName', 'OverallScore', 'RiskLevel', 'Categories', 'Findings', 'Recommendations', 'ComplianceChecks')
        $result.AssessmentType | Should -Be 'Basic'
        $script:AssessmentJsonPath = Join-Path -Path $script:AssessmentDir -ChildPath 'SecurityAssessment.json'
        $script:AssessmentJsonPath | Should -Exist
    }

    # ------------------------------------------------------------- Hardening
    It 'Invoke-SecurityRemediation -WhatIf against the assessment JSON changes nothing' {
        $assessmentJson = $script:AssessmentJsonPath
        if (-not $assessmentJson -or -not (Test-Path -Path $assessmentJson)) {
            # Self-heal if the assessment test did not run first
            $fallbackDir = Join-Path -Path $TestDrive -ChildPath 'assess-remediation'
            Invoke-SecurityAssessment -AssessmentType Basic -OutputPath $fallbackDir | Out-Null
            $assessmentJson = Join-Path -Path $fallbackDir -ChildPath 'SecurityAssessment.json'
        }

        $result = Invoke-SecurityRemediation -AssessmentPath $assessmentJson -GenerateRollback -WhatIf -RollbackDirectory $TestDrive
        Assert-ResultShape -Object $result -Names @('RemediationDate', 'MaxSeverity', 'WhatIf', 'FindingsProcessed', 'Remediated', 'ManualReview', 'Failed', 'RollbackPath')
        $result.WhatIf | Should -BeTrue
        # WhatIf: nothing may be applied and no rollback script may be written
        @($result.Remediated).Count | Should -Be 0
        $result.RollbackPath | Should -BeNullOrEmpty
        @(Get-ChildItem -Path $TestDrive -Filter 'SecurityRemediation_Rollback_*.ps1' -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'Update-DefenderConfiguration honors -WhatIf without changing the system' {
        { Update-DefenderConfiguration -WhatIf } | Should -Not -Throw
    }

    # ------------------------------------------------------- Skipped by design
    It 'Test-SystemIntegrity is skipped (runs sfc /scannow + DISM, 10+ minutes)' {
        Set-ItResult -Skipped -Because 'Test-SystemIntegrity runs SFC /scannow and DISM health checks (10+ minutes) - outside the smoke-test runtime budget'
    }

    It 'Export-MemoryDump is skipped (interactive Read-Host prompt)' {
        Set-ItResult -Skipped -Because 'Export-MemoryDump prompts interactively via Read-Host'
    }

    It 'Invoke-IncidentResponse is skipped (performs real response actions)' {
        Set-ItResult -Skipped -Because 'Invoke-IncidentResponse executes real incident-response actions (kills processes, disables accounts)'
    }

    It 'Register-ScheduledSecurityScan is skipped (creates a real scheduled task)' {
        Set-ItResult -Skipped -Because 'Register-ScheduledSecurityScan registers a persistent scheduled task on the runner'
    }

    It 'Send-SiemEvent is skipped (requires a real SIEM endpoint)' {
        Set-ItResult -Skipped -Because 'Send-SiemEvent posts to a live SIEM endpoint; conversion is covered via ConvertTo-SiemEvent'
    }

    It 'Set-SecurityBaseline is skipped (modifies system configuration)' {
        Set-ItResult -Skipped -Because 'Set-SecurityBaseline hardens the live system; remediation WhatIf is covered via Invoke-SecurityRemediation'
    }
}
