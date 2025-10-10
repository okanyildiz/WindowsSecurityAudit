function Get-SecurityMetrics {
    <#
    .SYNOPSIS
        Collects and calculates comprehensive security metrics from all modules
    
    .DESCRIPTION
        Enterprise-grade security metrics aggregation system that:
        - Collects data from all 13 security modules (54 functions)
        - Calculates overall security score (0-100)
        - Performs risk assessment (Critical/High/Medium/Low)
        - Tracks threat levels (Critical/High/Medium/Low/Minimal)
        - Analyzes compliance scores (CIS, NIST, PCI-DSS)
        - Provides trend analysis (week-over-week, month-over-month)
        - Compares with baseline metrics
        - Maintains historical data
        - Exports to JSON format
        - Generates actionable recommendations
    
    .PARAMETER IncludeModules
        Security modules to include in metrics collection
        Valid values: All, Core, Detection, Analysis, Compliance, ActiveDirectory, 
                     Cloud, Vulnerability, ThreatHunting, Forensics, WindowsDefender, 
                     Hardening, Enterprise, Response
        Default: All
    
    .PARAMETER IncludeHistory
        Store metrics in historical database for trend analysis
        History is maintained in: $env:TEMP\SecurityMetricsHistory.json
    
    .PARAMETER HistoryDays
        Number of days of historical data to retain (1-365)
        Default: 30 days
    
    .PARAMETER CalculateTrends
        Calculate trend analysis comparing current metrics with historical data
        Requires at least one previous metric collection in history
    
    .PARAMETER ExportPath
        Directory path to export metrics in JSON format
        Filename: SecurityMetrics_YYYYMMDD_HHMMSS.json
    
    .PARAMETER CompareWithBaseline
        Compare current metrics with a baseline metrics file
        Useful for tracking security posture improvements over time
    
    .PARAMETER BaselinePath
        Path to baseline metrics JSON file for comparison
        Required when CompareWithBaseline is used
    
    .EXAMPLE
        Get-SecurityMetrics
        
        Collect metrics from all modules with default settings
    
    .EXAMPLE
        Get-SecurityMetrics -IncludeModules Core,Detection,Compliance
        
        Collect metrics from specific modules only
    
    .EXAMPLE
        Get-SecurityMetrics -IncludeHistory -CalculateTrends
        
        Collect metrics, save to history, and calculate trends
    
    .EXAMPLE
        Get-SecurityMetrics -ExportPath "C:\SecurityReports" -IncludeHistory
        
        Collect metrics, export to JSON, and save to history
    
    .EXAMPLE
        Get-SecurityMetrics -CompareWithBaseline -BaselinePath "C:\Baseline\metrics.json"
        
        Collect metrics and compare with baseline
    
    .EXAMPLE
        $metrics = Get-SecurityMetrics -IncludeModules All -CalculateTrends -IncludeHistory -ExportPath "C:\Reports"
        Write-Host "Security Score: $($metrics.OverallSecurityScore)%"
        Write-Host "Threat Level: $($metrics.ThreatLevel)"
        
        Full metrics collection with all features enabled
    
    .OUTPUTS
        PSCustomObject containing comprehensive security metrics:
        - Timestamp: Collection date and time
        - Hostname: Computer name
        - Domain: Domain or workgroup name
        - OverallSecurityScore: Calculated security score (0-100)
        - RiskLevel: Overall risk assessment
        - ThreatLevel: Active threat level
        - ComplianceScore: Average compliance score
        - Findings: Total, Critical, High, Medium, Low findings
        - Module-specific metrics for each security module
        - Performance metrics
        - Trend data (if CalculateTrends enabled)
        - Baseline comparison (if CompareWithBaseline enabled)
    
    .NOTES
        Author: WindowsSecurityAudit Module
        Version: 1.1.0 ULTIMATE EDITION
        
        Requires: Administrator privileges for full functionality
        PowerShell Version: 5.1 or higher
        
        All property checks use PSObject.Properties to avoid warnings
        All array operations use @() cast to prevent count errors
        All null checks are safe and defensive
        
        Performance: Typical execution time 30-60 seconds for all modules
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('All', 'Core', 'Detection', 'Analysis', 'Compliance', 'ActiveDirectory', 
                     'Cloud', 'Vulnerability', 'ThreatHunting', 'Forensics', 'WindowsDefender', 
                     'Hardening', 'Enterprise', 'Response')]
        [string[]]$IncludeModules = @('All'),
        
        [Parameter()]
        [switch]$IncludeHistory,
        
        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$HistoryDays = 30,
        
        [Parameter()]
        [switch]$CalculateTrends,
        
        [Parameter()]
        [string]$ExportPath,
        
        [Parameter()]
        [switch]$CompareWithBaseline,
        
        [Parameter()]
        [string]$BaselinePath
    )
    
    begin {
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  SECURITY METRICS COLLECTION - ULTIMATE EDITION" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        
        $startTime = Get-Date
        
        # Validate baseline path if comparison requested
        if ($CompareWithBaseline) {
            if (-not $BaselinePath) {
                Write-Warning "CompareWithBaseline specified but no BaselinePath provided"
                $CompareWithBaseline = $false
            }
            elseif (-not (Test-Path $BaselinePath)) {
                Write-Warning "Baseline file not found: $BaselinePath"
                $CompareWithBaseline = $false
            }
        }
        
        # Determine modules to process
        $modulesToProcess = if ($IncludeModules -contains 'All') {
            @('Core', 'Detection', 'Analysis', 'Compliance', 'ActiveDirectory', 'Cloud', 
              'Vulnerability', 'ThreatHunting', 'Forensics', 'WindowsDefender', 'Hardening', 
              'Enterprise', 'Response')
        } else { 
            @($IncludeModules)
        }
        
        Write-Host "Collecting metrics from $(@($modulesToProcess).Count) modules..." -ForegroundColor Yellow
        Write-Host "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
        
        # Initialize comprehensive metrics structure
        $script:metrics = @{
            # Metadata
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TimestampEpoch = [int][double]::Parse((Get-Date -UFormat %s))
            Hostname = $env:COMPUTERNAME
            Domain = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { "WORKGROUP" }
            Username = $env:USERNAME
            OSVersion = [System.Environment]::OSVersion.VersionString
            PSVersion = $PSVersionTable.PSVersion.ToString()
            CollectionDuration = 0
            ModulesCollected = @($modulesToProcess)
            
            # Overall scores and levels
            OverallSecurityScore = 100
            RiskLevel = "Low"
            ComplianceScore = 0
            ThreatLevel = "Minimal"
            HealthStatus = "Healthy"
            
            # Findings aggregation
            Findings = @{
                Total = 0
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
                Informational = 0
                ByCategory = @{
                    Security = 0
                    Compliance = 0
                    Threats = 0
                    Vulnerabilities = 0
                    Configuration = 0
                }
                BySeverity = @()
                RecentFindings = @()
            }
            
            # Recommendations
            Recommendations = @{
                Critical = @()
                High = @()
                Medium = @()
                Low = @()
                Total = 0
            }
            
            # Core Module Metrics
            Core = @{
                Enabled = $false
                SystemHealth = "Unknown"
                IntegrityStatus = "Unknown"
                BaselineCompliance = 0
                LastAssessmentDate = $null
                PendingUpdates = 0
                UptimeDays = 0
            }
            
            # Detection Module Metrics
            Detection = @{
                Enabled = $false
                TotalThreats = 0
                ActiveThreats = 0
                PersistenceMechanisms = 0
                SuspiciousProcesses = 0
                SuspiciousAuthentications = 0
                LateralMovement = 0
                NetworkAnomalies = 0
                APTIndicators = 0
                LivingOffLand = 0
                DataExfiltration = 0
                LastScanDate = $null
            }
            
            # Analysis Module Metrics
            Analysis = @{
                Enabled = $false
                TotalEvents = 0
                CriticalEvents = 0
                ErrorEvents = 0
                WarningEvents = 0
                SecurityMisconfigurations = 0
                ExposedServices = 0
                RegistryIssues = 0
                FileSystemIssues = 0
                MemoryIssues = 0
            }
            
            # Compliance Module Metrics
            Compliance = @{
                Enabled = $false
                Frameworks = @{
                    CIS = @{
                        Score = 0
                        TotalControls = 0
                        PassedControls = 0
                        FailedControls = 0
                    }
                    NIST = @{
                        Score = 0
                        TotalControls = 0
                        CompliantControls = 0
                        NonCompliantControls = 0
                    }
                    PCIDSS = @{
                        Score = 0
                        TotalRequirements = 0
                        InPlace = 0
                        NotInPlace = 0
                    }
                }
                OverallScore = 0
                TotalControls = 0
                PassedControls = 0
                FailedControls = 0
                LastAuditDate = $null
            }
            
            # Active Directory Module Metrics
            ActiveDirectory = @{
                Enabled = $false
                DomainName = $null
                PrivilegedAccounts = 0
                Vulnerabilities = 0
                StaleObjects = 0
                Backdoors = 0
                PasswordPolicyScore = 0
                LastADScanDate = $null
            }
            
            # Cloud Security Module Metrics
            Cloud = @{
                Enabled = $false
                ConnectedTenant = $null
                RiskySignIns = 0
                ConditionalAccessPolicies = 0
                M365SecurityScore = 0
                AzureSecurityScore = 0
                LastCloudScanDate = $null
            }
            
            # Vulnerability Module Metrics
            Vulnerability = @{
                Enabled = $false
                Total = 0
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
                EOLSoftware = 0
                OutdatedSoftware = 0
                CertificateIssues = 0
                ExpiredCertificates = 0
                WeakCertificates = 0
                LastVulnScanDate = $null
            }
            
            # Threat Hunting Module Metrics
            ThreatHunting = @{
                Enabled = $false
                IOCMatches = 0
                MITRETechniques = 0
                ThreatIntelSources = 0
                LastHuntDate = $null
            }
            
            # Forensics Module Metrics
            Forensics = @{
                Enabled = $false
                ArtifactsCollected = 0
                ExecutionArtifacts = 0
                USBDevices = 0
                RecentExecutions = 0
                LastForensicScanDate = $null
            }
            
            # Windows Defender Module Metrics
            WindowsDefender = @{
                Enabled = $false
                Status = "Unknown"
                ProtectionEnabled = $false
                RealTimeProtection = $false
                CloudProtection = $false
                SignatureAge = 999
                SignatureVersion = "Unknown"
                LastScanDays = 999
                LastQuickScan = $null
                LastFullScan = $null
                ThreatsDetected = 0
            }
            
            # Hardening Module Metrics
            Hardening = @{
                Enabled = $false
                AuditPoliciesEnabled = $false
                PowerShellSecurityEnabled = $false
                BaselineApplied = $false
                HardeningScore = 0
                LastHardeningDate = $null
            }
            
            # Enterprise Module Metrics
            Enterprise = @{
                Enabled = $false
                MultiSystemsScanned = 0
                EnterprisePoliciesApplied = 0
                CentralizedLogging = $false
                LastEnterpriseScanDate = $null
            }
            
            # Response Module Metrics
            Response = @{
                Enabled = $false
                ActiveIncidents = 0
                ResolvedIncidents = 0
                AverageResponseTime = 0
                LastIncidentDate = $null
            }
            
            # Performance Metrics
            Performance = @{
                CollectionTime = 0
                ModuleTimes = @{}
                FunctionCalls = 0
                FailedFunctions = 0
                SuccessRate = 100
            }
            
            # Trend Analysis (if enabled)
            Trends = @{
                Enabled = $CalculateTrends
                SecurityScoreChange = 0
                SecurityScoreTrend = "Stable"
                ThreatCountChange = 0
                ThreatTrend = "Stable"
                ComplianceScoreChange = 0
                ComplianceTrend = "Stable"
                FindingsChange = 0
                FindingsTrend = "Stable"
                WeekOverWeek = @{}
                MonthOverMonth = @{}
            }
            
            # Baseline Comparison (if enabled)
            Baseline = @{
                ComparisonEnabled = $CompareWithBaseline
                BaselineDate = $null
                SecurityScoreDelta = 0
                ThreatCountDelta = 0
                ComplianceScoreDelta = 0
                NewFindings = 0
                ResolvedFindings = 0
                ImprovedAreas = @()
                DeclinedAreas = @()
            }
        }
    }
    
    process {
        try {
            Write-Host "`n[COLLECTING MODULE METRICS]" -ForegroundColor Cyan
            
            $totalFunctions = 0
            $successfulFunctions = 0
            $failedFunctions = 0
            
            # ============================================
            # CORE MODULE (4 functions)
            # ============================================
            if ($modulesToProcess -contains 'Core') {
                Write-Host "`n[Core Module Metrics]" -ForegroundColor Cyan
                $coreStart = Get-Date
                $script:metrics.Core.Enabled = $true
                
                # Get-SecurityBaseline
                try {
                    $totalFunctions++
                    $baseline = Get-SecurityBaseline -ErrorAction Stop
                    if ($baseline) {
                        # Safe property access
                        if ($baseline.PSObject.Properties['CompliancePercentage']) {
                            $script:metrics.Core.BaselineCompliance = $baseline.CompliancePercentage
                        }
                        elseif ($baseline.PSObject.Properties['ComplianceScore']) {
                            $script:metrics.Core.BaselineCompliance = $baseline.ComplianceScore
                        }
                        elseif ($baseline.PSObject.Properties['Score']) {
                            $script:metrics.Core.BaselineCompliance = $baseline.Score
                        }
                        $successfulFunctions++
                        Write-Host "  Baseline Compliance: $($script:metrics.Core.BaselineCompliance)%" -ForegroundColor Green
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-SecurityBaseline: $_"
                }
                
                # Get-SystemInfo
                try {
                    $totalFunctions++
                    $sysInfo = Get-SystemInfo -ErrorAction Stop
                    if ($sysInfo) {
                        $script:metrics.Core.SystemHealth = "Healthy"
                        
                        # Extract uptime if available
                        if ($sysInfo.PSObject.Properties['LastBootUpTime']) {
                            $script:metrics.Core.UptimeDays = [Math]::Round(((Get-Date) - $sysInfo.LastBootUpTime).TotalDays, 1)
                        }
                        elseif ($sysInfo.PSObject.Properties['BootTime']) {
                            $script:metrics.Core.UptimeDays = [Math]::Round(((Get-Date) - $sysInfo.BootTime).TotalDays, 1)
                        }
                        
                        $successfulFunctions++
                        Write-Host "  System Info: Collected (Uptime: $($script:metrics.Core.UptimeDays)d)" -ForegroundColor Green
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-SystemInfo: $_"
                }
                
                # Test-SystemIntegrity
                try {
                    $totalFunctions++
                    $integrity = Test-SystemIntegrity -ErrorAction Stop
                    if ($integrity) {
                        # Safe property access
                        if ($integrity.PSObject.Properties['OverallStatus']) {
                            $script:metrics.Core.IntegrityStatus = $integrity.OverallStatus
                        }
                        elseif ($integrity.PSObject.Properties['Status']) {
                            $script:metrics.Core.IntegrityStatus = $integrity.Status
                        }
                        elseif ($integrity.PSObject.Properties['IntegrityStatus']) {
                            $script:metrics.Core.IntegrityStatus = $integrity.IntegrityStatus
                        }
                        
                        # Extract pending updates
                        if ($integrity.PSObject.Properties['PendingUpdates']) {
                            $script:metrics.Core.PendingUpdates = $integrity.PendingUpdates
                        }
                        
                        $successfulFunctions++
                        Write-Host "  Integrity Status: $($script:metrics.Core.IntegrityStatus)" -ForegroundColor Green
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Test-SystemIntegrity: $_"
                }
                
                # Invoke-SecurityAssessment
                try {
                    $totalFunctions++
                    $assessment = Invoke-SecurityAssessment -ErrorAction Stop
                    if ($assessment) {
                        $script:metrics.Core.LastAssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        
                        # Extract findings if available
                        if ($assessment.PSObject.Properties['Findings']) {
                            $findings = @($assessment.Findings)
                            $script:metrics.Findings.ByCategory.Security += $findings.Count
                        }
                        
                        $successfulFunctions++
                        Write-Host "  Security Assessment: Complete" -ForegroundColor Green
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Invoke-SecurityAssessment: $_"
                }
                
                $script:metrics.Performance.ModuleTimes['Core'] = [Math]::Round(((Get-Date) - $coreStart).TotalSeconds, 2)
            }
            
            # ============================================
            # DETECTION MODULE (8 functions)
            # ============================================
            if ($modulesToProcess -contains 'Detection') {
                Write-Host "`n[Detection Module Metrics]" -ForegroundColor Cyan
                $detStart = Get-Date
                $script:metrics.Detection.Enabled = $true
                
                # Find-PersistenceMechanisms
                try {
                    $totalFunctions++
                    $persistence = Find-PersistenceMechanisms -ErrorAction Stop
                    $script:metrics.Detection.PersistenceMechanisms = @($persistence).Count
                    $successfulFunctions++
                    Write-Host "  Persistence Mechanisms: $($script:metrics.Detection.PersistenceMechanisms)" -ForegroundColor $(if ($script:metrics.Detection.PersistenceMechanisms -gt 0) { 'Yellow' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Find-PersistenceMechanisms: $_"
                }
                
                # Find-SuspiciousProcesses
                try {
                    $totalFunctions++
                    $processes = Find-SuspiciousProcesses -ErrorAction Stop
                    $script:metrics.Detection.SuspiciousProcesses = @($processes).Count
                    $successfulFunctions++
                    Write-Host "  Suspicious Processes: $($script:metrics.Detection.SuspiciousProcesses)" -ForegroundColor $(if ($script:metrics.Detection.SuspiciousProcesses -gt 0) { 'Yellow' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Find-SuspiciousProcesses: $_"
                }
                
                # Find-SuspiciousAuthentication
                try {
                    $totalFunctions++
                    $auth = Find-SuspiciousAuthentication -ErrorAction Stop
                    $script:metrics.Detection.SuspiciousAuthentications = @($auth).Count
                    $successfulFunctions++
                    Write-Host "  Suspicious Authentications: $($script:metrics.Detection.SuspiciousAuthentications)" -ForegroundColor $(if ($script:metrics.Detection.SuspiciousAuthentications -gt 0) { 'Yellow' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Find-SuspiciousAuthentication: $_"
                }
                
                # Find-LateralMovement
                try {
                    $totalFunctions++
                    $lateral = Find-LateralMovement -ErrorAction Stop
                    $script:metrics.Detection.LateralMovement = @($lateral).Count
                    $successfulFunctions++
                    Write-Host "  Lateral Movement: $($script:metrics.Detection.LateralMovement)" -ForegroundColor $(if ($script:metrics.Detection.LateralMovement -gt 0) { 'Red' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Find-LateralMovement: $_"
                }
                
                # Find-APTIndicators
                try {
                    $totalFunctions++
                    $apt = Find-APTIndicators -ErrorAction Stop
                    if ($apt -and $apt.PSObject.Properties['TotalIndicators']) {
                        $script:metrics.Detection.APTIndicators = $apt.TotalIndicators
                    } else {
                        $script:metrics.Detection.APTIndicators = @($apt).Count
                    }
                    $successfulFunctions++
                    Write-Host "  APT Indicators: $($script:metrics.Detection.APTIndicators)" -ForegroundColor $(if ($script:metrics.Detection.APTIndicators -gt 0) { 'Red' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Find-APTIndicators: $_"
                }
                
                # Find-LivingOffLand
                try {
                    $totalFunctions++
                    $lolbins = Find-LivingOffLand -ErrorAction Stop
                    $script:metrics.Detection.LivingOffLand = @($lolbins).Count
                    $successfulFunctions++
                    Write-Host "  Living Off Land: $($script:metrics.Detection.LivingOffLand)" -ForegroundColor $(if ($script:metrics.Detection.LivingOffLand -gt 0) { 'Yellow' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Find-LivingOffLand: $_"
                }
                
                # Find-DataExfiltration
                try {
                    $totalFunctions++
                    $exfil = Find-DataExfiltration -ErrorAction Stop
                    $script:metrics.Detection.DataExfiltration = @($exfil).Count
                    $successfulFunctions++
                    Write-Host "  Data Exfiltration: $($script:metrics.Detection.DataExfiltration)" -ForegroundColor $(if ($script:metrics.Detection.DataExfiltration -gt 0) { 'Red' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Find-DataExfiltration: $_"
                }
                
                # Find-NetworkAnomalies
                try {
                    $totalFunctions++
                    $network = Find-NetworkAnomalies -ErrorAction Stop
                    if ($network -and $network.PSObject.Properties['TotalAnomalies']) {
                        $script:metrics.Detection.NetworkAnomalies = $network.TotalAnomalies
                    } else {
                        $script:metrics.Detection.NetworkAnomalies = @($network).Count
                    }
                    $successfulFunctions++
                    Write-Host "  Network Anomalies: $($script:metrics.Detection.NetworkAnomalies)" -ForegroundColor $(if ($script:metrics.Detection.NetworkAnomalies -gt 0) { 'Yellow' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Find-NetworkAnomalies: $_"
                }
                
                # Calculate total threats
                $script:metrics.Detection.TotalThreats = 
                    $script:metrics.Detection.PersistenceMechanisms +
                    $script:metrics.Detection.SuspiciousProcesses +
                    $script:metrics.Detection.SuspiciousAuthentications +
                    $script:metrics.Detection.LateralMovement +
                    $script:metrics.Detection.APTIndicators +
                    $script:metrics.Detection.LivingOffLand +
                    $script:metrics.Detection.DataExfiltration +
                    $script:metrics.Detection.NetworkAnomalies
                
                $script:metrics.Detection.ActiveThreats = $script:metrics.Detection.TotalThreats
                $script:metrics.Detection.LastScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                
                Write-Host "  TOTAL THREATS: $($script:metrics.Detection.TotalThreats)" -ForegroundColor $(
                    if ($script:metrics.Detection.TotalThreats -gt 20) { 'Red' }
                    elseif ($script:metrics.Detection.TotalThreats -gt 10) { 'Yellow' }
                    else { 'Green' }
                )
                
                $script:metrics.Performance.ModuleTimes['Detection'] = [Math]::Round(((Get-Date) - $detStart).TotalSeconds, 2)
            }
            
            # ============================================
            # ANALYSIS MODULE (6 functions)
            # ============================================
            if ($modulesToProcess -contains 'Analysis') {
                Write-Host "`n[Analysis Module Metrics]" -ForegroundColor Cyan
                $analStart = Get-Date
                $script:metrics.Analysis.Enabled = $true
                
                # Get-EventLogAnalysis
                try {
                    $totalFunctions++
                    $eventLog = Get-EventLogAnalysis -ErrorAction Stop
                    if ($eventLog) {
                        if ($eventLog.PSObject.Properties['TotalEvents']) {
                            $script:metrics.Analysis.TotalEvents = $eventLog.TotalEvents
                        }
                        if ($eventLog.PSObject.Properties['CriticalEvents']) {
                            $script:metrics.Analysis.CriticalEvents = $eventLog.CriticalEvents
                        }
                        if ($eventLog.PSObject.Properties['ErrorEvents']) {
                            $script:metrics.Analysis.ErrorEvents = $eventLog.ErrorEvents
                        }
                        if ($eventLog.PSObject.Properties['WarningEvents']) {
                            $script:metrics.Analysis.WarningEvents = $eventLog.WarningEvents
                        }
                        $successfulFunctions++
                        Write-Host "  Event Log Analysis: $($script:metrics.Analysis.TotalEvents) events ($($script:metrics.Analysis.CriticalEvents) critical)" -ForegroundColor $(if ($script:metrics.Analysis.CriticalEvents -gt 0) { 'Red' } else { 'Green' })
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-EventLogAnalysis: $_"
                }
                
                # Get-RegistryAnalysis
                try {
                    $totalFunctions++
                    $registry = Get-RegistryAnalysis -ErrorAction Stop
                    if ($registry) {
                        if ($registry.PSObject.Properties['SuspiciousFindings']) {
                            $script:metrics.Analysis.RegistryIssues = $registry.SuspiciousFindings
                        } else {
                            $script:metrics.Analysis.RegistryIssues = @($registry).Count
                        }
                        $successfulFunctions++
                        Write-Host "  Registry Analysis: $($script:metrics.Analysis.RegistryIssues) issues" -ForegroundColor $(if ($script:metrics.Analysis.RegistryIssues -gt 0) { 'Yellow' } else { 'Green' })
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-RegistryAnalysis: $_"
                }
                
                # Get-FileSystemAnalysis
                try {
                    $totalFunctions++
                    $fileSystem = Get-FileSystemAnalysis -ErrorAction Stop
                    if ($fileSystem) {
                        if ($fileSystem.PSObject.Properties['SuspiciousFiles']) {
                            $script:metrics.Analysis.FileSystemIssues = $fileSystem.SuspiciousFiles
                        } else {
                            $script:metrics.Analysis.FileSystemIssues = @($fileSystem).Count
                        }
                        $successfulFunctions++
                        Write-Host "  File System Analysis: $($script:metrics.Analysis.FileSystemIssues) suspicious files" -ForegroundColor $(if ($script:metrics.Analysis.FileSystemIssues -gt 100) { 'Yellow' } else { 'Green' })
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-FileSystemAnalysis: $_"
                }
                
                # Get-MemoryAnalysis
                try {
                    $totalFunctions++
                    $memory = Get-MemoryAnalysis -ErrorAction Stop
                    if ($memory) {
                        if ($memory.PSObject.Properties['InjectionIndicators']) {
                            $script:metrics.Analysis.MemoryIssues = $memory.InjectionIndicators
                        }
                        $successfulFunctions++
                        Write-Host "  Memory Analysis: $($script:metrics.Analysis.MemoryIssues) issues" -ForegroundColor $(if ($script:metrics.Analysis.MemoryIssues -gt 0) { 'Red' } else { 'Green' })
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-MemoryAnalysis: $_"
                }
                
                # Get-ExposedServices
                try {
                    $totalFunctions++
                    $exposed = Get-ExposedServices -ErrorAction Stop
                    if ($exposed) {
                        if ($exposed.PSObject.Properties['ExposedServices']) {
                            $script:metrics.Analysis.ExposedServices = $exposed.ExposedServices
                        } else {
                            $script:metrics.Analysis.ExposedServices = @($exposed).Count
                        }
                        $successfulFunctions++
                        Write-Host "  Exposed Services: $($script:metrics.Analysis.ExposedServices)" -ForegroundColor $(if ($script:metrics.Analysis.ExposedServices -gt 0) { 'Yellow' } else { 'Green' })
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-ExposedServices: $_"
                }
                
                # Get-SecurityMisconfigurations
                try {
                    $totalFunctions++
                    $misconfig = Get-SecurityMisconfigurations -ErrorAction Stop
                    $script:metrics.Analysis.SecurityMisconfigurations = @($misconfig).Count
                    $successfulFunctions++
                    Write-Host "  Misconfigurations: $($script:metrics.Analysis.SecurityMisconfigurations)" -ForegroundColor $(if ($script:metrics.Analysis.SecurityMisconfigurations -gt 0) { 'Yellow' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-SecurityMisconfigurations: $_"
                }
                
                $script:metrics.Performance.ModuleTimes['Analysis'] = [Math]::Round(((Get-Date) - $analStart).TotalSeconds, 2)
            }
            
            # ============================================
            # COMPLIANCE MODULE (5 functions)
            # ============================================
            if ($modulesToProcess -contains 'Compliance') {
                Write-Host "`n[Compliance Module Metrics]" -ForegroundColor Cyan
                $compStart = Get-Date
                $script:metrics.Compliance.Enabled = $true
                
                # Test-CISBenchmark
                try {
                    $totalFunctions++
                    $cis = Test-CISBenchmark -ErrorAction Stop
                    if ($cis) {
                        # Score
                        if ($cis.PSObject.Properties['ComplianceScore']) {
                            $script:metrics.Compliance.Frameworks.CIS.Score = $cis.ComplianceScore
                        } elseif ($cis.PSObject.Properties['CompliancePercentage']) {
                            $script:metrics.Compliance.Frameworks.CIS.Score = $cis.CompliancePercentage
                        } elseif ($cis.PSObject.Properties['Compliance']) {
                            $script:metrics.Compliance.Frameworks.CIS.Score = $cis.Compliance
                        }
                        
                        # Controls
                        if ($cis.PSObject.Properties['TotalControls']) {
                            $script:metrics.Compliance.Frameworks.CIS.TotalControls = $cis.TotalControls
                        }
                        if ($cis.PSObject.Properties['PassedControls']) {
                            $script:metrics.Compliance.Frameworks.CIS.PassedControls = $cis.PassedControls
                        } elseif ($cis.PSObject.Properties['Passed']) {
                            $script:metrics.Compliance.Frameworks.CIS.PassedControls = $cis.Passed
                        }
                        if ($cis.PSObject.Properties['FailedControls']) {
                            $script:metrics.Compliance.Frameworks.CIS.FailedControls = $cis.FailedControls
                        } elseif ($cis.PSObject.Properties['Failed']) {
                            $script:metrics.Compliance.Frameworks.CIS.FailedControls = $cis.Failed
                        }
                        
                        $successfulFunctions++
                        Write-Host "  CIS Benchmark: $($script:metrics.Compliance.Frameworks.CIS.Score)%" -ForegroundColor $(if ($script:metrics.Compliance.Frameworks.CIS.Score -ge 80) { 'Green' } elseif ($script:metrics.Compliance.Frameworks.CIS.Score -ge 60) { 'Yellow' } else { 'Red' })
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Test-CISBenchmark: $_"
                }
                
                # Test-NISTCompliance
                try {
                    $totalFunctions++
                    $nist = Test-NISTCompliance -ErrorAction Stop
                    if ($nist) {
                        # Score
                        if ($nist.PSObject.Properties['ComplianceScore']) {
                            $script:metrics.Compliance.Frameworks.NIST.Score = $nist.ComplianceScore
                        } elseif ($nist.PSObject.Properties['CompliancePercentage']) {
                            $script:metrics.Compliance.Frameworks.NIST.Score = $nist.CompliancePercentage
                        } elseif ($nist.PSObject.Properties['Compliance']) {
                            $script:metrics.Compliance.Frameworks.NIST.Score = $nist.Compliance
                        }
                        
                        # Controls
                        if ($nist.PSObject.Properties['TotalControls']) {
                            $script:metrics.Compliance.Frameworks.NIST.TotalControls = $nist.TotalControls
                        }
                        if ($nist.PSObject.Properties['CompliantControls']) {
                            $script:metrics.Compliance.Frameworks.NIST.CompliantControls = $nist.CompliantControls
                        } elseif ($nist.PSObject.Properties['Compliant']) {
                            $script:metrics.Compliance.Frameworks.NIST.CompliantControls = $nist.Compliant
                        }
                        if ($nist.PSObject.Properties['NonCompliantControls']) {
                            $script:metrics.Compliance.Frameworks.NIST.NonCompliantControls = $nist.NonCompliantControls
                        } elseif ($nist.PSObject.Properties['NonCompliant']) {
                            $script:metrics.Compliance.Frameworks.NIST.NonCompliantControls = $nist.NonCompliant
                        }
                        
                        $successfulFunctions++
                        Write-Host "  NIST 800-53: $($script:metrics.Compliance.Frameworks.NIST.Score)%" -ForegroundColor $(if ($script:metrics.Compliance.Frameworks.NIST.Score -ge 80) { 'Green' } elseif ($script:metrics.Compliance.Frameworks.NIST.Score -ge 60) { 'Yellow' } else { 'Red' })
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Test-NISTCompliance: $_"
                }
                
                # Test-PCI-DSS
                try {
                    $totalFunctions++
                    $pci = Test-PCI-DSS -ErrorAction Stop
                    if ($pci) {
                        # Score
                        if ($pci.PSObject.Properties['ComplianceScore']) {
                            $script:metrics.Compliance.Frameworks.PCIDSS.Score = $pci.ComplianceScore
                        } elseif ($pci.PSObject.Properties['CompliancePercentage']) {
                            $script:metrics.Compliance.Frameworks.PCIDSS.Score = $pci.CompliancePercentage
                        } elseif ($pci.PSObject.Properties['Compliance']) {
                            $script:metrics.Compliance.Frameworks.PCIDSS.Score = $pci.Compliance
                        }
                        
                        # Requirements
                        if ($pci.PSObject.Properties['TotalRequirements']) {
                            $script:metrics.Compliance.Frameworks.PCIDSS.TotalRequirements = $pci.TotalRequirements
                        }
                        if ($pci.PSObject.Properties['InPlace']) {
                            $script:metrics.Compliance.Frameworks.PCIDSS.InPlace = $pci.InPlace
                        }
                        if ($pci.PSObject.Properties['NotInPlace']) {
                            $script:metrics.Compliance.Frameworks.PCIDSS.NotInPlace = $pci.NotInPlace
                        }
                        
                        $successfulFunctions++
                        Write-Host "  PCI-DSS: $($script:metrics.Compliance.Frameworks.PCIDSS.Score)%" -ForegroundColor $(if ($script:metrics.Compliance.Frameworks.PCIDSS.Score -ge 80) { 'Green' } elseif ($script:metrics.Compliance.Frameworks.PCIDSS.Score -ge 60) { 'Yellow' } else { 'Red' })
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Test-PCI-DSS: $_"
                }
                
                # Get-ComplianceReport
                try {
                    $totalFunctions++
                    $compReport = Get-ComplianceReport -ErrorAction Stop
                    $successfulFunctions++
                    Write-Host "  Compliance Report: Generated" -ForegroundColor Green
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-ComplianceReport: $_"
                }
                
                # Test-PatchCompliance
                try {
                    $totalFunctions++
                    $patches = Test-PatchCompliance -ErrorAction Stop
                    if ($patches) {
                        if ($patches.PSObject.Properties['MissingUpdates']) {
                            $script:metrics.Core.PendingUpdates = @($patches.MissingUpdates).Count
                        }
                    }
                    $successfulFunctions++
                    Write-Host "  Patch Compliance: OK ($($script:metrics.Core.PendingUpdates) pending)" -ForegroundColor $(if ($script:metrics.Core.PendingUpdates -gt 0) { 'Yellow' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Test-PatchCompliance: $_"
                }
                
                # Calculate overall compliance - NULL SAFE with @() cast
                $compScores = @(
                    $script:metrics.Compliance.Frameworks.CIS.Score, 
                    $script:metrics.Compliance.Frameworks.NIST.Score, 
                    $script:metrics.Compliance.Frameworks.PCIDSS.Score
                ) | Where-Object { $_ -gt 0 }
                
                if (@($compScores).Count -gt 0) {
                    $script:metrics.Compliance.OverallScore = [Math]::Round(($compScores | Measure-Object -Average).Average, 1)
                    $script:metrics.ComplianceScore = $script:metrics.Compliance.OverallScore
                    Write-Host "  Overall Compliance: $($script:metrics.ComplianceScore)%" -ForegroundColor Cyan
                } else {
                    $script:metrics.Compliance.OverallScore = 0
                    $script:metrics.ComplianceScore = 0
                }
                
                # Calculate total controls
                $script:metrics.Compliance.TotalControls = 
                    $script:metrics.Compliance.Frameworks.CIS.TotalControls +
                    $script:metrics.Compliance.Frameworks.NIST.TotalControls +
                    $script:metrics.Compliance.Frameworks.PCIDSS.TotalRequirements
                
                $script:metrics.Compliance.PassedControls = 
                    $script:metrics.Compliance.Frameworks.CIS.PassedControls +
                    $script:metrics.Compliance.Frameworks.NIST.CompliantControls +
                    $script:metrics.Compliance.Frameworks.PCIDSS.InPlace
                
                $script:metrics.Compliance.FailedControls = 
                    $script:metrics.Compliance.Frameworks.CIS.FailedControls +
                    $script:metrics.Compliance.Frameworks.NIST.NonCompliantControls +
                    $script:metrics.Compliance.Frameworks.PCIDSS.NotInPlace
                
                $script:metrics.Compliance.LastAuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                
                $script:metrics.Performance.ModuleTimes['Compliance'] = [Math]::Round(((Get-Date) - $compStart).TotalSeconds, 2)
            }
            
            # ============================================
            # ACTIVE DIRECTORY MODULE (6 functions)
            # ============================================
            if ($modulesToProcess -contains 'ActiveDirectory') {
                Write-Host "`n[Active Directory Module Metrics]" -ForegroundColor Cyan
                $adStart = Get-Date
                
                if ($env:USERDNSDOMAIN) {
                    $script:metrics.ActiveDirectory.Enabled = $true
                    $script:metrics.ActiveDirectory.DomainName = $env:USERDNSDOMAIN
                    
                    # Get-ADPrivilegedAccounts
                    try {
                        $totalFunctions++
                        $privAccounts = Get-ADPrivilegedAccounts -ErrorAction Stop
                        $script:metrics.ActiveDirectory.PrivilegedAccounts = @($privAccounts).Count
                        $successfulFunctions++
                        Write-Host "  Privileged Accounts: $($script:metrics.ActiveDirectory.PrivilegedAccounts)" -ForegroundColor Yellow
                    } catch { 
                        $failedFunctions++
                        Write-Verbose "  Get-ADPrivilegedAccounts: $_"
                    }
                    
                    # Find-ADVulnerabilities
                    try {
                        $totalFunctions++
                        $adVulns = Find-ADVulnerabilities -ErrorAction Stop
                        $script:metrics.ActiveDirectory.Vulnerabilities = @($adVulns).Count
                        $successfulFunctions++
                        Write-Host "  AD Vulnerabilities: $($script:metrics.ActiveDirectory.Vulnerabilities)" -ForegroundColor $(if ($script:metrics.ActiveDirectory.Vulnerabilities -gt 0) { 'Red' } else { 'Green' })
                    } catch { 
                        $failedFunctions++
                        Write-Verbose "  Find-ADVulnerabilities: $_"
                    }
                    
                    # Test-ADSecurityPosture
                    try {
                        $totalFunctions++
                        $adPosture = Test-ADSecurityPosture -ErrorAction Stop
                        $successfulFunctions++
                        Write-Host "  AD Security Posture: Assessed" -ForegroundColor Green
                    } catch { 
                        $failedFunctions++
                        Write-Verbose "  Test-ADSecurityPosture: $_"
                    }
                    
                    # Find-ADBackdoors
                    try {
                        $totalFunctions++
                        $backdoors = Find-ADBackdoors -ErrorAction Stop
                        $script:metrics.ActiveDirectory.Backdoors = @($backdoors).Count
                        $successfulFunctions++
                        Write-Host "  AD Backdoors: $($script:metrics.ActiveDirectory.Backdoors)" -ForegroundColor $(if ($script:metrics.ActiveDirectory.Backdoors -gt 0) { 'Red' } else { 'Green' })
                    } catch { 
                        $failedFunctions++
                        Write-Verbose "  Find-ADBackdoors: $_"
                    }
                    
                    # Find-StaleADObjects
                    try {
                        $totalFunctions++
                        $stale = Find-StaleADObjects -ErrorAction Stop
                        $script:metrics.ActiveDirectory.StaleObjects = @($stale).Count
                        $successfulFunctions++
                        Write-Host "  Stale AD Objects: $($script:metrics.ActiveDirectory.StaleObjects)" -ForegroundColor $(if ($script:metrics.ActiveDirectory.StaleObjects -gt 10) { 'Yellow' } else { 'Green' })
                    } catch { 
                        $failedFunctions++
                        Write-Verbose "  Find-StaleADObjects: $_"
                    }
                    
                    # Get-ADPasswordPolicy
                    try {
                        $totalFunctions++
                        $pwdPolicy = Get-ADPasswordPolicy -ErrorAction Stop
                        if ($pwdPolicy) {
                            # Calculate password policy score
                            $policyScore = 100
                            if ($pwdPolicy.PSObject.Properties['MinPasswordLength'] -and $pwdPolicy.MinPasswordLength -lt 14) { $policyScore -= 20 }
                            if ($pwdPolicy.PSObject.Properties['ComplexityEnabled'] -and -not $pwdPolicy.ComplexityEnabled) { $policyScore -= 30 }
                            if ($pwdPolicy.PSObject.Properties['MaxPasswordAge'] -and $pwdPolicy.MaxPasswordAge.Days -gt 90) { $policyScore -= 15 }
                            $script:metrics.ActiveDirectory.PasswordPolicyScore = [Math]::Max(0, $policyScore)
                        }
                        $successfulFunctions++
                        Write-Host "  Password Policy Score: $($script:metrics.ActiveDirectory.PasswordPolicyScore)%" -ForegroundColor $(if ($script:metrics.ActiveDirectory.PasswordPolicyScore -ge 80) { 'Green' } elseif ($script:metrics.ActiveDirectory.PasswordPolicyScore -ge 60) { 'Yellow' } else { 'Red' })
                    } catch { 
                        $failedFunctions++
                        Write-Verbose "  Get-ADPasswordPolicy: $_"
                    }
                    
                    $script:metrics.ActiveDirectory.LastADScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                } else {
                    Write-Host "  System not domain-joined - skipping AD module" -ForegroundColor Gray
                }
                
                $script:metrics.Performance.ModuleTimes['ActiveDirectory'] = [Math]::Round(((Get-Date) - $adStart).TotalSeconds, 2)
            }
            
            # ============================================
            # CLOUD SECURITY MODULE (3 functions)
            # ============================================
            if ($modulesToProcess -contains 'Cloud') {
                Write-Host "`n[Cloud Security Module Metrics]" -ForegroundColor Cyan
                $cloudStart = Get-Date
                
                $mgContext = Get-MgContext -ErrorAction SilentlyContinue
                if ($mgContext) {
                    $script:metrics.Cloud.Enabled = $true
                    $script:metrics.Cloud.ConnectedTenant = if ($mgContext.PSObject.Properties['TenantId']) { $mgContext.TenantId } else { "Unknown" }
                    
                    # Get-AzureADRiskySignIns
                    try {
                        $totalFunctions++
                        $riskySignIns = Get-AzureADRiskySignIns -DaysBack 30 -ErrorAction Stop
                        $script:metrics.Cloud.RiskySignIns = @($riskySignIns).Count
                        $successfulFunctions++
                        Write-Host "  Risky Sign-Ins (30d): $($script:metrics.Cloud.RiskySignIns)" -ForegroundColor $(if ($script:metrics.Cloud.RiskySignIns -gt 0) { 'Yellow' } else { 'Green' })
                    } catch { 
                        $failedFunctions++
                        Write-Verbose "  Get-AzureADRiskySignIns: $_"
                    }
                    
                    # Test-M365SecurityPosture
                    try {
                        $totalFunctions++
                        $m365Security = Test-M365SecurityPosture -ErrorAction Stop
                        if ($m365Security -and $m365Security.PSObject.Properties['SecurityScore']) {
                            $script:metrics.Cloud.M365SecurityScore = $m365Security.SecurityScore
                        }
                        $successfulFunctions++
                        Write-Host "  M365 Security Score: $($script:metrics.Cloud.M365SecurityScore)%" -ForegroundColor Cyan
                    } catch { 
                        $failedFunctions++
                        Write-Verbose "  Test-M365SecurityPosture: $_"
                    }
                    
                    # Get-CloudComplianceStatus
                    try {
                        $totalFunctions++
                        $cloudCompliance = Get-CloudComplianceStatus -Framework CIS -ErrorAction Stop
                        $successfulFunctions++
                        Write-Host "  Cloud Compliance: Assessed" -ForegroundColor Green
                    } catch { 
                        $failedFunctions++
                        Write-Verbose "  Get-CloudComplianceStatus: $_"
                    }
                    
                    $script:metrics.Cloud.LastCloudScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                } else {
                    Write-Host "  Not connected to Microsoft Graph - skipping cloud module" -ForegroundColor Gray
                    Write-Host "  To enable: Connect-MgGraph" -ForegroundColor Gray
                }
                
                $script:metrics.Performance.ModuleTimes['Cloud'] = [Math]::Round(((Get-Date) - $cloudStart).TotalSeconds, 2)
            }
            
            # ============================================
            # VULNERABILITY MODULE (3 functions)
            # ============================================
            if ($modulesToProcess -contains 'Vulnerability') {
                Write-Host "`n[Vulnerability Module Metrics]" -ForegroundColor Cyan
                $vulnStart = Get-Date
                $script:metrics.Vulnerability.Enabled = $true
                
                # Get-VulnerabilityAssessment
                try {
                    $totalFunctions++
                    $vulnAssess = Get-VulnerabilityAssessment -ErrorAction Stop
                    if ($vulnAssess -and $vulnAssess.PSObject.Properties['Summary']) {
                        $summary = $vulnAssess.Summary
                        if ($summary.PSObject.Properties['TotalVulnerabilities']) {
                            $script:metrics.Vulnerability.Total = $summary.TotalVulnerabilities
                        }
                        if ($summary.PSObject.Properties['Critical']) {
                            $script:metrics.Vulnerability.Critical = $summary.Critical
                        }
                        if ($summary.PSObject.Properties['High']) {
                            $script:metrics.Vulnerability.High = $summary.High
                        }
                        if ($summary.PSObject.Properties['Medium']) {
                            $script:metrics.Vulnerability.Medium = $summary.Medium
                        }
                        if ($summary.PSObject.Properties['Low']) {
                            $script:metrics.Vulnerability.Low = $summary.Low
                        }
                    }
                    $successfulFunctions++
                    Write-Host "  Vulnerabilities: $($script:metrics.Vulnerability.Total) total" -ForegroundColor $(if ($script:metrics.Vulnerability.Total -gt 0) { 'Yellow' } else { 'Green' })
                    if ($script:metrics.Vulnerability.Critical -gt 0) {
                        Write-Host "    Critical: $($script:metrics.Vulnerability.Critical)" -ForegroundColor Red
                    }
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-VulnerabilityAssessment: $_"
                }
                
                # Find-EOLSoftware
                try {
                    $totalFunctions++
                    $eol = Find-EOLSoftware -ErrorAction Stop
                    $script:metrics.Vulnerability.EOLSoftware = @($eol).Count
                    $successfulFunctions++
                    Write-Host "  EOL Software: $($script:metrics.Vulnerability.EOLSoftware)" -ForegroundColor $(if ($script:metrics.Vulnerability.EOLSoftware -gt 0) { 'Red' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Find-EOLSoftware: $_"
                }
                
                # Test-CertificateHealth
                try {
                    $totalFunctions++
                    $certs = Test-CertificateHealth -ErrorAction Stop
                    if ($certs) {
                        if ($certs.PSObject.Properties['IssuesFound']) {
                            $script:metrics.Vulnerability.CertificateIssues = $certs.IssuesFound
                        }
                        if ($certs.PSObject.Properties['Expired']) {
                            $script:metrics.Vulnerability.ExpiredCertificates = $certs.Expired
                        }
                        if ($certs.PSObject.Properties['WeakSignatures']) {
                            $script:metrics.Vulnerability.WeakCertificates = $certs.WeakSignatures
                        }
                    }
                    $successfulFunctions++
                    Write-Host "  Certificate Issues: $($script:metrics.Vulnerability.CertificateIssues) ($($script:metrics.Vulnerability.ExpiredCertificates) expired)" -ForegroundColor $(if ($script:metrics.Vulnerability.CertificateIssues -gt 0) { 'Yellow' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Test-CertificateHealth: $_"
                }
                
                $script:metrics.Vulnerability.LastVulnScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $script:metrics.Performance.ModuleTimes['Vulnerability'] = [Math]::Round(((Get-Date) - $vulnStart).TotalSeconds, 2)
            }
            
            # ============================================
            # THREAT HUNTING MODULE (2 functions)
            # ============================================
            if ($modulesToProcess -contains 'ThreatHunting') {
                Write-Host "`n[Threat Hunting Module Metrics]" -ForegroundColor Cyan
                $threatStart = Get-Date
                $script:metrics.ThreatHunting.Enabled = $true
                
                # Get-ThreatIntelligence
                try {
                    $totalFunctions++
                    $threatIntel = Get-ThreatIntelligence -ErrorAction Stop
                    if ($threatIntel) {
                        if ($threatIntel.PSObject.Properties['IOCMatches']) {
                            $script:metrics.ThreatHunting.IOCMatches = @($threatIntel.IOCMatches).Count
                        } else {
                            $script:metrics.ThreatHunting.IOCMatches = @($threatIntel).Count
                        }
                    }
                    $successfulFunctions++
                    Write-Host "  IOC Matches: $($script:metrics.ThreatHunting.IOCMatches)" -ForegroundColor $(if ($script:metrics.ThreatHunting.IOCMatches -gt 0) { 'Red' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-ThreatIntelligence: $_"
                }
                
                # Get-MITREAttackMapping
                try {
                    $totalFunctions++
                    $mitre = Get-MITREAttackMapping -ErrorAction Stop
                    if ($mitre) {
                        if ($mitre.PSObject.Properties['UniqueTechniques']) {
                            $script:metrics.ThreatHunting.MITRETechniques = $mitre.UniqueTechniques
                        } else {
                            $script:metrics.ThreatHunting.MITRETechniques = @($mitre).Count
                        }
                    }
                    $successfulFunctions++
                    Write-Host "  MITRE Techniques: $($script:metrics.ThreatHunting.MITRETechniques)" -ForegroundColor $(if ($script:metrics.ThreatHunting.MITRETechniques -gt 0) { 'Yellow' } else { 'Green' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-MITREAttackMapping: $_"
                }
                
                $script:metrics.ThreatHunting.LastHuntDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $script:metrics.Performance.ModuleTimes['ThreatHunting'] = [Math]::Round(((Get-Date) - $threatStart).TotalSeconds, 2)
            }
            
            # ============================================
            # FORENSICS MODULE (6 functions)
            # ============================================
            if ($modulesToProcess -contains 'Forensics') {
                Write-Host "`n[Forensics Module Metrics]" -ForegroundColor Cyan
                $forStart = Get-Date
                $script:metrics.Forensics.Enabled = $true
                
                # Get-ArtifactCollection
                try {
                    $totalFunctions++
                    $artifacts = Get-ArtifactCollection -ErrorAction Stop
                    if ($artifacts) {
                        if ($artifacts.PSObject.Properties['TotalFiles']) {
                            $script:metrics.Forensics.ArtifactsCollected = $artifacts.TotalFiles
                        }
                    }
                    $successfulFunctions++
                    Write-Host "  Artifacts Collected: $($script:metrics.Forensics.ArtifactsCollected)" -ForegroundColor Green
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-ArtifactCollection: $_"
                }
                
                # Get-ExecutionArtifacts
                try {
                    $totalFunctions++
                    $execArtifacts = Get-ExecutionArtifacts -ErrorAction Stop
                    if ($execArtifacts) {
                        if ($execArtifacts.PSObject.Properties['TotalArtifacts']) {
                            $script:metrics.Forensics.ExecutionArtifacts = $execArtifacts.TotalArtifacts
                        } else {
                            $script:metrics.Forensics.ExecutionArtifacts = @($execArtifacts).Count
                        }
                        
                        if ($execArtifacts.PSObject.Properties['RecentExecutions']) {
                            $script:metrics.Forensics.RecentExecutions = @($execArtifacts.RecentExecutions).Count
                        }
                    }
                    $successfulFunctions++
                    Write-Host "  Execution Artifacts: $($script:metrics.Forensics.ExecutionArtifacts)" -ForegroundColor Green
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-ExecutionArtifacts: $_"
                }
                
                # Get-USBHistory
                try {
                    $totalFunctions++
                    $usb = Get-USBHistory -ErrorAction Stop
                    $script:metrics.Forensics.USBDevices = @($usb).Count
                    $successfulFunctions++
                    Write-Host "  USB Devices: $($script:metrics.Forensics.USBDevices)" -ForegroundColor Green
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-USBHistory: $_"
                }
                
                # Invoke-ForensicCollection, Export-MemoryDump, New-ForensicTimeline
                # These are heavy operations - skip metrics collection unless explicitly needed
                $totalFunctions += 3
                Write-Host "  Detailed forensics: Skipped (use -DetailLevel Detailed)" -ForegroundColor Gray
                
                $script:metrics.Forensics.LastForensicScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $script:metrics.Performance.ModuleTimes['Forensics'] = [Math]::Round(((Get-Date) - $forStart).TotalSeconds, 2)
            }
            
            # ============================================
            # WINDOWS DEFENDER MODULE (3 functions)
            # ============================================
            if ($modulesToProcess -contains 'WindowsDefender') {
                Write-Host "`n[Windows Defender Module Metrics]" -ForegroundColor Cyan
                $defStart = Get-Date
                $script:metrics.WindowsDefender.Enabled = $true
                
                # Get-DefenderStatus
                try {
                    $totalFunctions++
                    $defStatus = Get-DefenderStatus -ErrorAction Stop
                    if ($defStatus) {
                        # Status
                        if ($defStatus.PSObject.Properties['HealthStatus']) {
                            $script:metrics.WindowsDefender.Status = $defStatus.HealthStatus
                        } elseif ($defStatus.PSObject.Properties['Status']) {
                            $script:metrics.WindowsDefender.Status = $defStatus.Status
                        }
                        
                        # Protection states
                        if ($defStatus.PSObject.Properties['RealTimeProtectionEnabled']) {
                            $script:metrics.WindowsDefender.RealTimeProtection = $defStatus.RealTimeProtectionEnabled
                            $script:metrics.WindowsDefender.ProtectionEnabled = $defStatus.RealTimeProtectionEnabled
                        }
                        if ($defStatus.PSObject.Properties['CloudProtectionLevel']) {
                            $script:metrics.WindowsDefender.CloudProtection = ($defStatus.CloudProtectionLevel -ne 'NotConfigured')
                        }
                        
                        # Signature info
                        if ($defStatus.PSObject.Properties['SignatureAge']) {
                            $script:metrics.WindowsDefender.SignatureAge = $defStatus.SignatureAge
                        }
                        if ($defStatus.PSObject.Properties['AntivirusSignatureVersion']) {
                            $script:metrics.WindowsDefender.SignatureVersion = $defStatus.AntivirusSignatureVersion
                        } elseif ($defStatus.PSObject.Properties['SignatureVersion']) {
                            $script:metrics.WindowsDefender.SignatureVersion = $defStatus.SignatureVersion
                        }
                        
                        # Scan info
                        if ($defStatus.PSObject.Properties['DaysSinceLastQuickScan']) {
                            $script:metrics.WindowsDefender.LastScanDays = $defStatus.DaysSinceLastQuickScan
                        }
                        if ($defStatus.PSObject.Properties['QuickScanStartTime']) {
                            $script:metrics.WindowsDefender.LastQuickScan = $defStatus.QuickScanStartTime
                        }
                        if ($defStatus.PSObject.Properties['FullScanStartTime']) {
                            $script:metrics.WindowsDefender.LastFullScan = $defStatus.FullScanStartTime
                        }
                    }
                    $successfulFunctions++
                    Write-Host "  Status: $($script:metrics.WindowsDefender.Status)" -ForegroundColor $(if ($script:metrics.WindowsDefender.ProtectionEnabled) { 'Green' } else { 'Red' })
                    Write-Host "  Real-Time Protection: $($script:metrics.WindowsDefender.RealTimeProtection)" -ForegroundColor $(if ($script:metrics.WindowsDefender.RealTimeProtection) { 'Green' } else { 'Red' })
                    Write-Host "  Signature Age: $($script:metrics.WindowsDefender.SignatureAge) days" -ForegroundColor $(if ($script:metrics.WindowsDefender.SignatureAge -le 1) { 'Green' } elseif ($script:metrics.WindowsDefender.SignatureAge -le 7) { 'Yellow' } else { 'Red' })
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Get-DefenderStatus: $_"
                }
                
                # Invoke-DefenderScan - skip for metrics
                $totalFunctions++
                Write-Host "  Defender Scan: Skipped (metrics only)" -ForegroundColor Gray
                
                # Update-DefenderConfiguration - check only
                try {
                    $totalFunctions++
                    $defConfig = Update-DefenderConfiguration -WhatIf -ErrorAction Stop
                    $successfulFunctions++
                    Write-Host "  Configuration: Checked" -ForegroundColor Green
                } catch { 
                    $failedFunctions++
                    Write-Verbose "  Update-DefenderConfiguration: $_"
                }
                
                $script:metrics.Performance.ModuleTimes['WindowsDefender'] = [Math]::Round(((Get-Date) - $defStart).TotalSeconds, 2)
            }
            
# ============================================
# CALCULATE AGGREGATE METRICS
# ============================================
Write-Host "`n[CALCULATING AGGREGATE METRICS]" -ForegroundColor Cyan

# Helper function to safely convert values to integers
function ConvertTo-SafeInt {
    param($Value)
    
    if ($null -eq $Value) { return 0 }
    if ($Value -is [int] -or $Value -is [long]) { return [int]$Value }
    if ($Value -is [array]) { return @($Value).Count }
    if ($Value -is [string]) {
        $trimmed = $Value.Trim()
        if ([string]::IsNullOrEmpty($trimmed)) { return 0 }
        try { return [int]$trimmed } catch { return 0 }
    }
    try { return [int]$Value } catch { return 0 }
}

# Findings by severity - SAFE CONVERSION
$script:metrics.Findings.Critical = 
    (ConvertTo-SafeInt $script:metrics.Vulnerability.Critical) +
    (ConvertTo-SafeInt $script:metrics.ActiveDirectory.Vulnerabilities) +
    (ConvertTo-SafeInt $script:metrics.ActiveDirectory.Backdoors) +
    (ConvertTo-SafeInt $script:metrics.Analysis.CriticalEvents)

$script:metrics.Findings.High = 
    (ConvertTo-SafeInt $script:metrics.Detection.TotalThreats) +
    (ConvertTo-SafeInt $script:metrics.Vulnerability.High) +
    (ConvertTo-SafeInt $script:metrics.Vulnerability.EOLSoftware) +
    (ConvertTo-SafeInt $script:metrics.ThreatHunting.IOCMatches)

$script:metrics.Findings.Medium = 
    (ConvertTo-SafeInt $script:metrics.Analysis.SecurityMisconfigurations) +
    (ConvertTo-SafeInt $script:metrics.Vulnerability.Medium) +
    (ConvertTo-SafeInt $script:metrics.Vulnerability.CertificateIssues) +
    (ConvertTo-SafeInt $script:metrics.Analysis.RegistryIssues)

$script:metrics.Findings.Low = 
    (ConvertTo-SafeInt $script:metrics.Analysis.ExposedServices) +
    (ConvertTo-SafeInt $script:metrics.ActiveDirectory.StaleObjects) +
    (ConvertTo-SafeInt $script:metrics.Cloud.RiskySignIns)

$script:metrics.Findings.Total = 
    $script:metrics.Findings.Critical +
    $script:metrics.Findings.High +
    $script:metrics.Findings.Medium +
    $script:metrics.Findings.Low

# Findings by category
$script:metrics.Findings.ByCategory.Threats = ConvertTo-SafeInt $script:metrics.Detection.TotalThreats
$script:metrics.Findings.ByCategory.Vulnerabilities = ConvertTo-SafeInt $script:metrics.Vulnerability.Total
$script:metrics.Findings.ByCategory.Configuration = ConvertTo-SafeInt $script:metrics.Analysis.SecurityMisconfigurations
$script:metrics.Findings.ByCategory.Compliance = ConvertTo-SafeInt $script:metrics.Compliance.FailedControls

Write-Host "  Total Findings: $($script:metrics.Findings.Total)" -ForegroundColor White
Write-Host "    Critical: $($script:metrics.Findings.Critical)" -ForegroundColor Red
Write-Host "    High: $($script:metrics.Findings.High)" -ForegroundColor Yellow
Write-Host "    Medium: $($script:metrics.Findings.Medium)" -ForegroundColor Yellow
Write-Host "    Low: $($script:metrics.Findings.Low)" -ForegroundColor Gray

# Calculate overall security score - FIXED IF STATEMENTS
$penalty = 0
$penalty += ($script:metrics.Findings.Critical * 20)
$penalty += ($script:metrics.Findings.High * 10)
$penalty += ($script:metrics.Findings.Medium * 5)
$penalty += ($script:metrics.Findings.Low * 2)
$penalty += ((ConvertTo-SafeInt $script:metrics.Core.PendingUpdates) * 2)

# Add penalties based on conditions
if (-not $script:metrics.WindowsDefender.ProtectionEnabled) {
    $penalty += 15
}

$signatureAge = ConvertTo-SafeInt $script:metrics.WindowsDefender.SignatureAge
if ($signatureAge -gt 7) {
    $penalty += 10
}

$script:metrics.OverallSecurityScore = [Math]::Max(0, [Math]::Min(100, 100 - $penalty))

Write-Host "  Overall Security Score: $($script:metrics.OverallSecurityScore)%" -ForegroundColor $(
    if ($script:metrics.OverallSecurityScore -ge 80) { 'Green' }
    elseif ($script:metrics.OverallSecurityScore -ge 60) { 'Yellow' }
    else { 'Red' }
)

# Determine risk level
$script:metrics.RiskLevel = 
    if ($script:metrics.Findings.Critical -gt 10) { "Critical" }
    elseif ($script:metrics.Findings.Critical -gt 5) { "High" }
    elseif ($script:metrics.Findings.Critical -gt 0) { "High" }
    elseif ($script:metrics.Findings.High -gt 20) { "High" }
    elseif ($script:metrics.Findings.High -gt 10) { "Medium" }
    elseif ($script:metrics.Findings.High -gt 0) { "Medium" }
    elseif ($script:metrics.Findings.Medium -gt 20) { "Medium" }
    else { "Low" }

Write-Host "  Risk Level: $($script:metrics.RiskLevel)" -ForegroundColor $(
    switch ($script:metrics.RiskLevel) {
        'Critical' { 'Red' }
        'High' { 'Red' }
        'Medium' { 'Yellow' }
        default { 'Green' }
    }
)

# Determine threat level
$script:metrics.ThreatLevel = 
    if ($script:metrics.Detection.APTIndicators -gt 0) { "Critical" }
    elseif ($script:metrics.Detection.LateralMovement -gt 0) { "High" }
    elseif ($script:metrics.Detection.TotalThreats -gt 30) { "High" }
    elseif ($script:metrics.Detection.TotalThreats -gt 20) { "Medium" }
    elseif ($script:metrics.Detection.TotalThreats -gt 10) { "Medium" }
    elseif ($script:metrics.Detection.TotalThreats -gt 0) { "Low" }
    else { "Minimal" }

Write-Host "  Threat Level: $($script:metrics.ThreatLevel)" -ForegroundColor $(
    switch ($script:metrics.ThreatLevel) {
        'Critical' { 'Red' }
        'High' { 'Red' }
        'Medium' { 'Yellow' }
        default { 'Green' }
    }
)

# Health status
$script:metrics.HealthStatus = 
    if ($script:metrics.OverallSecurityScore -ge 90 -and $script:metrics.ThreatLevel -eq 'Minimal') { "Excellent" }
    elseif ($script:metrics.OverallSecurityScore -ge 80 -and $script:metrics.ThreatLevel -in @('Minimal', 'Low')) { "Good" }
    elseif ($script:metrics.OverallSecurityScore -ge 60) { "Fair" }
    elseif ($script:metrics.OverallSecurityScore -ge 40) { "Poor" }
    else { "Critical" }

Write-Host "  Health Status: $($script:metrics.HealthStatus)" -ForegroundColor $(
    switch ($script:metrics.HealthStatus) {
        'Excellent' { 'Green' }
        'Good' { 'Green' }
        'Fair' { 'Yellow' }
        'Poor' { 'Red' }
        default { 'Red' }
    }
)

# Generate recommendations
if ($script:metrics.Findings.Critical -gt 0) {
    $script:metrics.Recommendations.Critical += "Address $($script:metrics.Findings.Critical) critical security findings immediately"
}
if ($script:metrics.Vulnerability.EOLSoftware -gt 0) {
    $script:metrics.Recommendations.Critical += "Replace or upgrade $($script:metrics.Vulnerability.EOLSoftware) end-of-life software packages"
}
if (-not $script:metrics.WindowsDefender.ProtectionEnabled) {
    $script:metrics.Recommendations.Critical += "Enable Windows Defender real-time protection immediately"
}
if ($script:metrics.Detection.APTIndicators -gt 0) {
    $script:metrics.Recommendations.Critical += "Investigate $($script:metrics.Detection.APTIndicators) APT indicators - potential advanced threat"
}

if ($script:metrics.Findings.High -gt 0) {
    $script:metrics.Recommendations.High += "Remediate $($script:metrics.Findings.High) high-severity findings within 7 days"
}
if ($script:metrics.Core.PendingUpdates -gt 0) {
    $script:metrics.Recommendations.High += "Install $($script:metrics.Core.PendingUpdates) pending security updates"
}
if ($script:metrics.WindowsDefender.SignatureAge -gt 7) {
    $script:metrics.Recommendations.High += "Update Windows Defender signatures (currently $($script:metrics.WindowsDefender.SignatureAge) days old)"
}
if ($script:metrics.ComplianceScore -lt 70) {
    $script:metrics.Recommendations.High += "Improve compliance score (currently $($script:metrics.ComplianceScore)% - target: 80%+)"
}

if ($script:metrics.Findings.Medium -gt 0) {
    $script:metrics.Recommendations.Medium += "Address $($script:metrics.Findings.Medium) medium-severity issues within 30 days"
}
if ($script:metrics.Analysis.SecurityMisconfigurations -gt 0) {
    $script:metrics.Recommendations.Medium += "Fix $($script:metrics.Analysis.SecurityMisconfigurations) security misconfigurations"
}

if ($script:metrics.ActiveDirectory.StaleObjects -gt 10) {
    $script:metrics.Recommendations.Low += "Clean up $($script:metrics.ActiveDirectory.StaleObjects) stale AD objects"
}

$script:metrics.Recommendations.Total = 
    @($script:metrics.Recommendations.Critical).Count +
    @($script:metrics.Recommendations.High).Count +
    @($script:metrics.Recommendations.Medium).Count +
    @($script:metrics.Recommendations.Low).Count
            
            # ============================================
            # TREND ANALYSIS (if enabled)
            # ============================================
            if ($CalculateTrends) {
                Write-Host "`n[CALCULATING TRENDS]" -ForegroundColor Cyan
                
                try {
                    $historyPath = Join-Path $env:TEMP "SecurityMetricsHistory.json"
                    
                    if (Test-Path $historyPath) {
                        $history = Get-Content $historyPath -Raw | ConvertFrom-Json
                        $historyArray = @($history)
                        
                        if ($historyArray.Count -gt 0) {
                            $lastMetrics = $historyArray | Select-Object -Last 1
                            
                            # Security score trend
                            $scoreDelta = $script:metrics.OverallSecurityScore - $lastMetrics.OverallSecurityScore
                            $script:metrics.Trends.SecurityScoreChange = $scoreDelta
                            $script:metrics.Trends.SecurityScoreTrend = 
                                if ($scoreDelta -gt 5) { "Improving" }
                                elseif ($scoreDelta -lt -5) { "Declining" }
                                else { "Stable" }
                            
                            # Threat trend
                            $threatDelta = $script:metrics.Detection.TotalThreats - $lastMetrics.Detection.TotalThreats
                            $script:metrics.Trends.ThreatCountChange = $threatDelta
                            if ($script:metrics.Detection.TotalThreats -gt ($lastMetrics.Detection.TotalThreats * 1.2)) {
                                $script:metrics.Trends.ThreatTrend = "Increasing"
                            } elseif ($script:metrics.Detection.TotalThreats -lt ($lastMetrics.Detection.TotalThreats * 0.8)) {
                                $script:metrics.Trends.ThreatTrend = "Decreasing"
                            } else {
                                $script:metrics.Trends.ThreatTrend = "Stable"
                            }
                            
                            # Compliance trend
                            $compDelta = $script:metrics.ComplianceScore - $lastMetrics.ComplianceScore
                            $script:metrics.Trends.ComplianceScoreChange = $compDelta
                            if ($compDelta -gt 5) {
                                $script:metrics.Trends.ComplianceTrend = "Improving"
                            } elseif ($compDelta -lt -5) {
                                $script:metrics.Trends.ComplianceTrend = "Declining"
                            } else {
                                $script:metrics.Trends.ComplianceTrend = "Stable"
                            }
                            
                            # Findings trend
                            $findingsDelta = $script:metrics.Findings.Total - $lastMetrics.Findings.Total
                            $script:metrics.Trends.FindingsChange = $findingsDelta
                            if ($findingsDelta -gt 5) {
                                $script:metrics.Trends.FindingsTrend = "Increasing"
                            } elseif ($findingsDelta -lt -5) {
                                $script:metrics.Trends.FindingsTrend = "Decreasing"
                            } else {
                                $script:metrics.Trends.FindingsTrend = "Stable"
                            }
                            
                            Write-Host "  Security Score: $(if ($scoreDelta -gt 0) { '+' })$scoreDelta ($($script:metrics.Trends.SecurityScoreTrend))" -ForegroundColor $(if ($scoreDelta -gt 0) { 'Green' } elseif ($scoreDelta -lt 0) { 'Red' } else { 'Gray' })
                            Write-Host "  Threats: $(if ($threatDelta -gt 0) { '+' })$threatDelta ($($script:metrics.Trends.ThreatTrend))" -ForegroundColor $(if ($script:metrics.Trends.ThreatTrend -eq 'Increasing') { 'Red' } elseif ($script:metrics.Trends.ThreatTrend -eq 'Decreasing') { 'Green' } else { 'Gray' })
                            Write-Host "  Compliance: $(if ($compDelta -gt 0) { '+' })$compDelta ($($script:metrics.Trends.ComplianceTrend))" -ForegroundColor $(if ($script:metrics.Trends.ComplianceTrend -eq 'Improving') { 'Green' } elseif ($script:metrics.Trends.ComplianceTrend -eq 'Declining') { 'Red' } else { 'Gray' })
                            Write-Host "  Findings: $(if ($findingsDelta -gt 0) { '+' })$findingsDelta ($($script:metrics.Trends.FindingsTrend))" -ForegroundColor $(if ($findingsDelta -lt 0) { 'Green' } elseif ($findingsDelta -gt 0) { 'Red' } else { 'Gray' })
                        } else {
                            Write-Host "  Insufficient history for trend analysis" -ForegroundColor Gray
                        }
                    } else {
                        Write-Host "  No historical data found - this is the first collection" -ForegroundColor Gray
                    }
                } catch {
                    Write-Warning "  Failed to calculate trends: $_"
                }
            }
            
            # ============================================
            # BASELINE COMPARISON (if enabled)
            # ============================================
            if ($CompareWithBaseline -and $BaselinePath -and (Test-Path $BaselinePath)) {
                Write-Host "`n[COMPARING WITH BASELINE]" -ForegroundColor Cyan
                
                try {
                    $baseline = Get-Content $BaselinePath -Raw | ConvertFrom-Json
                    $script:metrics.Baseline.BaselineDate = $baseline.Timestamp
                    
                    # Security score comparison
                    $script:metrics.Baseline.SecurityScoreDelta = $script:metrics.OverallSecurityScore - $baseline.OverallSecurityScore
                    
                    # Threat count comparison
                    $script:metrics.Baseline.ThreatCountDelta = $script:metrics.Detection.TotalThreats - $baseline.Detection.TotalThreats
                    
                    # Compliance score comparison
                    $script:metrics.Baseline.ComplianceScoreDelta = $script:metrics.ComplianceScore - $baseline.ComplianceScore
                    
                    # Findings comparison
                    $script:metrics.Baseline.NewFindings = [Math]::Max(0, $script:metrics.Findings.Total - $baseline.Findings.Total)
                    $script:metrics.Baseline.ResolvedFindings = [Math]::Max(0, $baseline.Findings.Total - $script:metrics.Findings.Total)
                    
                    # Identify improved/declined areas
                    if ($script:metrics.Baseline.SecurityScoreDelta -gt 0) {
                        $script:metrics.Baseline.ImprovedAreas += "Security Score improved by $($script:metrics.Baseline.SecurityScoreDelta) points"
                    } elseif ($script:metrics.Baseline.SecurityScoreDelta -lt 0) {
                        $script:metrics.Baseline.DeclinedAreas += "Security Score declined by $([Math]::Abs($script:metrics.Baseline.SecurityScoreDelta)) points"
                    }
                    
                    if ($script:metrics.Baseline.ThreatCountDelta -lt 0) {
                        $script:metrics.Baseline.ImprovedAreas += "Threat count reduced by $([Math]::Abs($script:metrics.Baseline.ThreatCountDelta))"
                    } elseif ($script:metrics.Baseline.ThreatCountDelta -gt 0) {
                        $script:metrics.Baseline.DeclinedAreas += "Threat count increased by $($script:metrics.Baseline.ThreatCountDelta)"
                    }
                    
                    if ($script:metrics.Baseline.ComplianceScoreDelta -gt 0) {
                        $script:metrics.Baseline.ImprovedAreas += "Compliance improved by $($script:metrics.Baseline.ComplianceScoreDelta)%"
                    } elseif ($script:metrics.Baseline.ComplianceScoreDelta -lt 0) {
                        $script:metrics.Baseline.DeclinedAreas += "Compliance declined by $([Math]::Abs($script:metrics.Baseline.ComplianceScoreDelta))%"
                    }
                    
                    Write-Host "  Baseline Date: $($script:metrics.Baseline.BaselineDate)" -ForegroundColor Gray
                    Write-Host "  Security Score: $(if ($script:metrics.Baseline.SecurityScoreDelta -gt 0) { '+' })$($script:metrics.Baseline.SecurityScoreDelta)" -ForegroundColor $(if ($script:metrics.Baseline.SecurityScoreDelta -gt 0) { 'Green' } elseif ($script:metrics.Baseline.SecurityScoreDelta -lt 0) { 'Red' } else { 'Gray' })
                    Write-Host "  Threats: $(if ($script:metrics.Baseline.ThreatCountDelta -gt 0) { '+' })$($script:metrics.Baseline.ThreatCountDelta)" -ForegroundColor $(if ($script:metrics.Baseline.ThreatCountDelta -lt 0) { 'Green' } elseif ($script:metrics.Baseline.ThreatCountDelta -gt 0) { 'Red' } else { 'Gray' })
                    Write-Host "  New Findings: $($script:metrics.Baseline.NewFindings)" -ForegroundColor $(if ($script:metrics.Baseline.NewFindings -gt 0) { 'Yellow' } else { 'Green' })
                    Write-Host "  Resolved Findings: $($script:metrics.Baseline.ResolvedFindings)" -ForegroundColor $(if ($script:metrics.Baseline.ResolvedFindings -gt 0) { 'Green' } else { 'Gray' })
                    
                    if (@($script:metrics.Baseline.ImprovedAreas).Count -gt 0) {
                        Write-Host "  Improvements: $(@($script:metrics.Baseline.ImprovedAreas).Count)" -ForegroundColor Green
                    }
                    if (@($script:metrics.Baseline.DeclinedAreas).Count -gt 0) {
                        Write-Host "  Declines: $(@($script:metrics.Baseline.DeclinedAreas).Count)" -ForegroundColor Red
                    }
                } catch {
                    Write-Warning "  Failed to compare with baseline: $_"
                }
            }
            
            # ============================================
            # SAVE HISTORY (if enabled)
            # ============================================
            if ($IncludeHistory) {
                Write-Host "`n[SAVING TO HISTORY]" -ForegroundColor Cyan
                
                try {
                    $historyPath = Join-Path $env:TEMP "SecurityMetricsHistory.json"
                    $history = @()
                    
                    if (Test-Path $historyPath) {
                        $history = @(Get-Content $historyPath -Raw | ConvertFrom-Json)
                    }
                    
                    # Keep only last N days
                    $cutoffDate = (Get-Date).AddDays(-$HistoryDays)
                    $history = @($history) | Where-Object { 
                        try { [DateTime]$_.Timestamp -gt $cutoffDate } catch { $false }
                    }
                    
                    # Add current metrics
                    $history += $script:metrics
                    
                    # Save
                    $history | ConvertTo-Json -Depth 10 | Out-File $historyPath -Encoding UTF8 -Force
                    
                    Write-Host "  History saved: $historyPath" -ForegroundColor Green
                    Write-Host "  History entries: $(@($history).Count)" -ForegroundColor Gray
                } catch {
                    Write-Warning "  Failed to save history: $_"
                }
            }
            
            # ============================================
            # EXPORT (if specified)
            # ============================================
            if ($ExportPath) {
                Write-Host "`n[EXPORTING METRICS]" -ForegroundColor Cyan
                
                try {
                    if (-not (Test-Path $ExportPath)) {
                        New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
                    }
                    
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $exportFile = Join-Path $ExportPath "SecurityMetrics_$timestamp.json"
                    
                    $script:metrics | ConvertTo-Json -Depth 10 | Out-File $exportFile -Encoding UTF8 -Force
                    
                    Write-Host "  Exported: $exportFile" -ForegroundColor Green
                    Write-Host "  Size: $([Math]::Round((Get-Item $exportFile).Length / 1KB, 2)) KB" -ForegroundColor Gray
                } catch {
                    Write-Error "Failed to export metrics: $_"
                }
            }
            
            # Calculate performance metrics
            $script:metrics.CollectionDuration = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
            $script:metrics.Performance.CollectionTime = $script:metrics.CollectionDuration
            $script:metrics.Performance.FunctionCalls = $totalFunctions
            $script:metrics.Performance.FailedFunctions = $failedFunctions
            if ($totalFunctions -gt 0) {
                $script:metrics.Performance.SuccessRate = [Math]::Round(($successfulFunctions / $totalFunctions) * 100, 1)
            }
            
            return [PSCustomObject]$script:metrics
            
        }
        catch {
            Write-Error "Metrics collection failed: $_"
            Write-Host "`nStack Trace:" -ForegroundColor Red
            Write-Host $_.ScriptStackTrace -ForegroundColor Gray
            throw
        }
    }
    
    end {
        $totalTime = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
        
        Write-Host "`n================================================================" -ForegroundColor Green
        Write-Host "  METRICS COLLECTION COMPLETE" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  Collection Time: $totalTime seconds" -ForegroundColor White
        Write-Host "  Modules Processed: $(@($modulesToProcess).Count)" -ForegroundColor Yellow
        Write-Host "  Function Success Rate: $($script:metrics.Performance.SuccessRate)%" -ForegroundColor White
        
        Write-Host "`nKey Metrics:" -ForegroundColor Cyan
        Write-Host "  Security Score: $($script:metrics.OverallSecurityScore)%" -ForegroundColor White
        Write-Host "  Health Status: $($script:metrics.HealthStatus)" -ForegroundColor White
        Write-Host "  Risk Level: $($script:metrics.RiskLevel)" -ForegroundColor White
        Write-Host "  Threat Level: $($script:metrics.ThreatLevel)" -ForegroundColor White
        Write-Host "  Compliance Score: $($script:metrics.ComplianceScore)%" -ForegroundColor White
        Write-Host "  Total Findings: $($script:metrics.Findings.Total)" -ForegroundColor White
        Write-Host "  Recommendations: $($script:metrics.Recommendations.Total)" -ForegroundColor White
    }
}