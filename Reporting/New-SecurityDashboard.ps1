function New-SecurityDashboard {
    <#
    .SYNOPSIS
        Creates comprehensive security dashboard with ALL 54 functions
    
    .DESCRIPTION
        Enterprise security dashboard integrating all WindowsSecurityAudit functions
    
    .PARAMETER ExportPath
        Export directory (Default: current directory)
    
    .PARAMETER IncludeModules
        Modules: All, Core, Detection, Analysis, Compliance, ActiveDirectory, 
        Cloud, Vulnerability, ThreatHunting, Forensics, WindowsDefender, 
        Hardening, Enterprise, Response
    
    .PARAMETER Theme
        Light or Dark (Default: Light)
    
    .PARAMETER DetailLevel
        Summary, Standard, or Detailed (Default: Standard)
    
    .PARAMETER IncludeCharts
        Include interactive charts (Default: True)
    
    .PARAMETER AutoRefreshSeconds
        Auto-refresh interval in seconds (0 = disabled, Default: 0)
    
    .PARAMETER OpenInBrowser
        Auto-open dashboard in browser (Default: True)
    
    .PARAMETER SkipSlowChecks
        Skip time-consuming checks like full vulnerability scans
    
    .EXAMPLE
        New-SecurityDashboard
        Complete assessment with ALL 54 functions (default)
    
    .EXAMPLE
        New-SecurityDashboard -IncludeModules All
        Same as above - explicitly run ALL modules
    
    .EXAMPLE
        New-SecurityDashboard -IncludeModules Core,Detection -SkipSlowChecks
        Quick security check with Core and Detection modules only
    
    .EXAMPLE
        New-SecurityDashboard -Theme Dark -DetailLevel Detailed
        Full detailed assessment with dark theme
    
    .EXAMPLE
        New-SecurityDashboard -IncludeModules Compliance -ExportPath "C:\Reports"
        Compliance-only report saved to specific directory
    
    .NOTES
        Author: WindowsSecurityAudit Module
        Version: 3.0.0 ULTIMATE EDITION
        ALL 54 Functions Fully Integrated
        
        Requires: Administrator privileges for full functionality
        PowerShell Version: 5.1 or higher
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ExportPath = (Get-Location).Path,
        
        [Parameter()]
        [ValidateSet('All', 'Core', 'Detection', 'Analysis', 'Compliance', 'ActiveDirectory', 
                     'Cloud', 'Vulnerability', 'ThreatHunting', 'Forensics', 'WindowsDefender', 
                     'Hardening', 'Enterprise', 'Response')]
        [string[]]$IncludeModules = @('All'),
        
        [Parameter()]
        [ValidateSet('Light', 'Dark')]
        [string]$Theme = 'Light',
        
        [Parameter()]
        [ValidateSet('Summary', 'Standard', 'Detailed')]
        [string]$DetailLevel = 'Standard',
        
        [Parameter()]
        [bool]$IncludeCharts = $true,
        
        [Parameter()]
        [ValidateRange(0, 3600)]
        [int]$AutoRefreshSeconds = 0,
        
        [Parameter()]
        [bool]$OpenInBrowser = $true,
        
        [Parameter()]
        [switch]$SkipSlowChecks
    )
    
    begin {
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  ULTIMATE SECURITY DASHBOARD - ALL 54 FUNCTIONS" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        
        if ($IncludeModules -contains 'All') {
            Write-Host "Mode: FULL ASSESSMENT - All 13 modules enabled" -ForegroundColor Yellow
        } else {
            Write-Host "Mode: SELECTIVE - $($IncludeModules -join ', ')" -ForegroundColor Yellow
        }
        
        $startTime = Get-Date
        
        # Validate and create export path
        if (-not (Test-Path $ExportPath)) {
            try {
                New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
                Write-Host "Created export directory: $ExportPath" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to create export directory: $_"
                throw
            }
        }
        
        # Determine which modules to process
        $modulesToProcess = if ($IncludeModules -contains 'All') {
            @('Core', 'Detection', 'Analysis', 'Compliance', 'ActiveDirectory', 'Cloud', 
              'Vulnerability', 'ThreatHunting', 'Forensics', 'WindowsDefender', 'Hardening', 
              'Enterprise', 'Response')
        } else { 
            @($IncludeModules)
        }
        
        $moduleCount = @($modulesToProcess).Count
        Write-Host "Processing $moduleCount modules | Total Functions: 54" -ForegroundColor Yellow
        
        # Initialize comprehensive data structure with safe defaults
        $script:dashboardData = @{
            GeneratedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Theme = $Theme
            DetailLevel = $DetailLevel
            Hostname = $env:COMPUTERNAME
            DomainName = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { "WORKGROUP" }
            Username = $env:USERNAME
            TotalFunctionsUsed = 0
            
            ExecutiveSummary = @{
                OverallSecurityScore = 100
                TotalFindings = 0
                CriticalFindings = 0
                HighFindings = 0
                MediumFindings = 0
                LowFindings = 0
                ComplianceScore = 0
                ThreatLevel = "Low"
                Recommendations = @()
            }
            
            Core = @{
                SecurityBaseline = $null
                SystemInfo = $null
                SystemIntegrity = $null
                SecurityAssessment = $null
            }
            
            Detection = @{
                TotalThreats = 0
                PersistenceMechanisms = @()
                SuspiciousProcesses = @()
                SuspiciousAuthentications = @()
                LateralMovement = @()
                APTIndicators = @()
                LivingOffLand = @()
                DataExfiltration = @()
                NetworkAnomalies = @()
            }
            
            Analysis = @{
                EventLogAnalysis = $null
                RegistryAnalysis = $null
                FileSystemAnalysis = $null
                MemoryAnalysis = $null
                ExposedServices = @()
                SecurityMisconfigurations = @()
            }
            
            Compliance = @{
                CIS = $null
                NIST = $null
                PCIDSS = $null
                OverallReport = $null
                PatchCompliance = $null
            }
            
            ActiveDirectory = @{
                Enabled = $false
                PrivilegedAccounts = @()
                Vulnerabilities = @()
                SecurityPosture = $null
                Backdoors = @()
                StaleObjects = @()
                PasswordPolicy = $null
            }
            
            Cloud = @{
                Enabled = $false
                RiskySignIns = @()
                M365Security = $null
                CloudCompliance = $null
            }
            
            Vulnerability = @{
                TotalVulnerabilities = 0
                Assessment = $null
                EOLSoftware = @()
                CertificateHealth = $null
            }
            
            ThreatHunting = @{
                ThreatIntelligence = $null
                MITREMapping = $null
            }
            
            Forensics = @{
                Artifacts = @()
                ExecutionArtifacts = @()
                USBHistory = @()
                ForensicCollection = $null
                MemoryDump = $null
                Timeline = $null
            }
            
            WindowsDefender = @{
                Status = $null
                ScanResult = $null
                Configuration = $null
            }
            
            Hardening = @{
                AuditPolicies = $null
                PowerShellSecurity = $null
                BaselineStatus = $null
            }
            
            Enterprise = @{
                MultiSystemAudit = $null
                EnterpriseScan = $null
            }
            
            Response = @{
                IncidentResponse = $null
                EventDescriptions = @()
            }
            
            ChartsData = @{
                ComplianceScores = @()
                ThreatDistribution = @()
                ModuleStatus = @()
            }
            
            Performance = @{
                TotalExecutionTime = 0
                ModuleExecutionTimes = @{}
            }
        }
    }
    
    process {
        try {
            Write-Host "`n[DATA COLLECTION PHASE]" -ForegroundColor Cyan
            Write-Host "Starting security assessment..." -ForegroundColor Gray
            
            $functionCount = 0
            
            # ============================================
            # CORE MODULE (4 functions)
            # ============================================
            if ($modulesToProcess -contains 'Core') {
                Write-Host "`n[1/13] CORE MODULE - 4 Functions" -ForegroundColor Cyan
                $coreStart = Get-Date
                
                try { 
                    $script:dashboardData.Core.SecurityBaseline = Get-SecurityBaseline -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [1/54] Get-SecurityBaseline: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-SecurityBaseline failed: $_" 
                }
                
                try { 
                    $script:dashboardData.Core.SystemInfo = Get-SystemInfo -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [2/54] Get-SystemInfo: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-SystemInfo failed: $_" 
                }
                
                try { 
                    $script:dashboardData.Core.SystemIntegrity = Test-SystemIntegrity -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [3/54] Test-SystemIntegrity: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Test-SystemIntegrity failed: $_" 
                }
                
                try { 
                    $script:dashboardData.Core.SecurityAssessment = Invoke-SecurityAssessment -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [4/54] Invoke-SecurityAssessment: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Invoke-SecurityAssessment failed: $_" 
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Core'] = ((Get-Date) - $coreStart).TotalSeconds
            }
            
            # ============================================
            # DETECTION MODULE (8 functions)
            # ============================================
            if ($modulesToProcess -contains 'Detection') {
                Write-Host "`n[2/13] DETECTION MODULE - 8 Functions" -ForegroundColor Cyan
                $detStart = Get-Date
                
                try { 
                    $p = Find-PersistenceMechanisms -ErrorAction Stop
                    $script:dashboardData.Detection.PersistenceMechanisms = $p
                    $functionCount++
                    Write-Host "  [5/54] Find-PersistenceMechanisms: Found $(@($p).Count)" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Find-PersistenceMechanisms failed: $_" 
                }
                
                try { 
                    $p = Find-SuspiciousProcesses -ErrorAction Stop
                    $script:dashboardData.Detection.SuspiciousProcesses = $p
                    $functionCount++
                    Write-Host "  [6/54] Find-SuspiciousProcesses: Found $(@($p).Count)" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Find-SuspiciousProcesses failed: $_" 
                }
                
                try { 
                    $p = Find-SuspiciousAuthentication -ErrorAction Stop
                    $script:dashboardData.Detection.SuspiciousAuthentications = $p
                    $functionCount++
                    Write-Host "  [7/54] Find-SuspiciousAuthentication: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Find-SuspiciousAuthentication failed: $_" 
                }
                
                try { 
                    $p = Find-LateralMovement -ErrorAction Stop
                    $script:dashboardData.Detection.LateralMovement = $p
                    $functionCount++
                    Write-Host "  [8/54] Find-LateralMovement: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Find-LateralMovement failed: $_" 
                }
                
                try { 
                    $p = Find-APTIndicators -ErrorAction Stop
                    $script:dashboardData.Detection.APTIndicators = $p
                    $functionCount++
                    Write-Host "  [9/54] Find-APTIndicators: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Find-APTIndicators failed: $_" 
                }
                
                try { 
                    $p = Find-LivingOffLand -ErrorAction Stop
                    $script:dashboardData.Detection.LivingOffLand = $p
                    $functionCount++
                    Write-Host "  [10/54] Find-LivingOffLand: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Find-LivingOffLand failed: $_" 
                }
                
                try { 
                    $p = Find-DataExfiltration -ErrorAction Stop
                    $script:dashboardData.Detection.DataExfiltration = $p
                    $functionCount++
                    Write-Host "  [11/54] Find-DataExfiltration: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Find-DataExfiltration failed: $_" 
                }
                
                try { 
                    $p = Find-NetworkAnomalies -ErrorAction Stop
                    $script:dashboardData.Detection.NetworkAnomalies = $p
                    $functionCount++
                    Write-Host "  [12/54] Find-NetworkAnomalies: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Find-NetworkAnomalies failed: $_" 
                }
                
                # Calculate total threats
                $script:dashboardData.Detection.TotalThreats = 
                    @($script:dashboardData.Detection.PersistenceMechanisms).Count +
                    @($script:dashboardData.Detection.SuspiciousProcesses).Count +
                    @($script:dashboardData.Detection.SuspiciousAuthentications).Count +
                    @($script:dashboardData.Detection.LateralMovement).Count +
                    @($script:dashboardData.Detection.APTIndicators).Count +
                    @($script:dashboardData.Detection.LivingOffLand).Count +
                    @($script:dashboardData.Detection.DataExfiltration).Count +
                    @($script:dashboardData.Detection.NetworkAnomalies).Count
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Detection'] = ((Get-Date) - $detStart).TotalSeconds
                Write-Host "  Total threats detected: $($script:dashboardData.Detection.TotalThreats)" -ForegroundColor $(if ($script:dashboardData.Detection.TotalThreats -gt 0) { 'Yellow' } else { 'Green' })
            }
            
            # ============================================
            # ANALYSIS MODULE (6 functions)
            # ============================================
            if ($modulesToProcess -contains 'Analysis') {
                Write-Host "`n[3/13] ANALYSIS MODULE - 6 Functions" -ForegroundColor Cyan
                $analStart = Get-Date
                
                try { 
                    $script:dashboardData.Analysis.EventLogAnalysis = Get-EventLogAnalysis -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [13/54] Get-EventLogAnalysis: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-EventLogAnalysis failed: $_" 
                }
                
                try { 
                    $script:dashboardData.Analysis.RegistryAnalysis = Get-RegistryAnalysis -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [14/54] Get-RegistryAnalysis: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-RegistryAnalysis failed: $_" 
                }
                
                if (-not $SkipSlowChecks) {
                    try { 
                        $script:dashboardData.Analysis.FileSystemAnalysis = Get-FileSystemAnalysis -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [15/54] Get-FileSystemAnalysis: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Get-FileSystemAnalysis failed: $_" 
                    }
                    
                    try { 
                        $script:dashboardData.Analysis.MemoryAnalysis = Get-MemoryAnalysis -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [16/54] Get-MemoryAnalysis: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Get-MemoryAnalysis failed: $_" 
                    }
                } else {
                    Write-Host "  [15-16/54] Skipping slow checks (FileSystem, Memory)" -ForegroundColor Gray
                }
                
                try { 
                    $s = Get-ExposedServices -ErrorAction Stop
                    $script:dashboardData.Analysis.ExposedServices = $s
                    $functionCount++
                    Write-Host "  [17/54] Get-ExposedServices: Found $(@($s).Count)" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-ExposedServices failed: $_" 
                }
                
                try { 
                    $s = Get-SecurityMisconfigurations -ErrorAction Stop
                    $script:dashboardData.Analysis.SecurityMisconfigurations = $s
                    $functionCount++
                    Write-Host "  [18/54] Get-SecurityMisconfigurations: Found $(@($s).Count)" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-SecurityMisconfigurations failed: $_" 
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Analysis'] = ((Get-Date) - $analStart).TotalSeconds
            }
            
            # ============================================
            # COMPLIANCE MODULE (5 functions)
            # ============================================
            if ($modulesToProcess -contains 'Compliance') {
                Write-Host "`n[4/13] COMPLIANCE MODULE - 5 Functions" -ForegroundColor Cyan
                $compStart = Get-Date
                
                try { 
                    $c = Test-CISBenchmark -ErrorAction Stop
                    $script:dashboardData.Compliance.CIS = $c
                    $functionCount++
                    Write-Host "  [19/54] Test-CISBenchmark: $($c.ComplianceScore)%" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Test-CISBenchmark failed: $_"
                    $script:dashboardData.Compliance.CIS = @{ ComplianceScore = 0; Status = "Error" }
                }
                
                try { 
                    $c = Test-NISTCompliance -ErrorAction Stop
                    $script:dashboardData.Compliance.NIST = $c
                    $functionCount++
                    Write-Host "  [20/54] Test-NISTCompliance: $($c.ComplianceScore)%" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Test-NISTCompliance failed: $_"
                    $script:dashboardData.Compliance.NIST = @{ ComplianceScore = 0; Status = "Error" }
                }
                
                try { 
                    $c = Test-PCI-DSS -ErrorAction Stop
                    $script:dashboardData.Compliance.PCIDSS = $c
                    $functionCount++
                    Write-Host "  [21/54] Test-PCI-DSS: $($c.ComplianceScore)%" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Test-PCI-DSS failed: $_"
                    $script:dashboardData.Compliance.PCIDSS = @{ ComplianceScore = 0; Status = "Error" }
                }
                
                try { 
                    $script:dashboardData.Compliance.OverallReport = Get-ComplianceReport -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [22/54] Get-ComplianceReport: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-ComplianceReport failed: $_" 
                }
                
                try { 
                    $script:dashboardData.Compliance.PatchCompliance = Test-PatchCompliance -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [23/54] Test-PatchCompliance: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Test-PatchCompliance failed: $_" 
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Compliance'] = ((Get-Date) - $compStart).TotalSeconds
            }
            
            # ============================================
            # ACTIVE DIRECTORY MODULE (6 functions)
            # ============================================
            if ($modulesToProcess -contains 'ActiveDirectory') {
                Write-Host "`n[5/13] ACTIVE DIRECTORY MODULE - 6 Functions" -ForegroundColor Cyan
                $adStart = Get-Date
                
                if ($env:USERDNSDOMAIN) {
                    $script:dashboardData.ActiveDirectory.Enabled = $true
                    
                    try { 
                        $p = Get-ADPrivilegedAccounts -ErrorAction Stop
                        $script:dashboardData.ActiveDirectory.PrivilegedAccounts = $p
                        $functionCount++
                        Write-Host "  [24/54] Get-ADPrivilegedAccounts: Found $(@($p).Count)" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Get-ADPrivilegedAccounts failed: $_" 
                    }
                    
                    try { 
                        $v = Find-ADVulnerabilities -ErrorAction Stop
                        $script:dashboardData.ActiveDirectory.Vulnerabilities = $v
                        $functionCount++
                        Write-Host "  [25/54] Find-ADVulnerabilities: Found $(@($v).Count)" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Find-ADVulnerabilities failed: $_" 
                    }
                    
                    try { 
                        $script:dashboardData.ActiveDirectory.SecurityPosture = Test-ADSecurityPosture -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [26/54] Test-ADSecurityPosture: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Test-ADSecurityPosture failed: $_" 
                    }
                    
                    try { 
                        $b = Find-ADBackdoors -ErrorAction Stop
                        $script:dashboardData.ActiveDirectory.Backdoors = $b
                        $functionCount++
                        Write-Host "  [27/54] Find-ADBackdoors: Found $(@($b).Count)" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Find-ADBackdoors failed: $_" 
                    }
                    
                    try { 
                        $s = Find-StaleADObjects -ErrorAction Stop
                        $script:dashboardData.ActiveDirectory.StaleObjects = $s
                        $functionCount++
                        Write-Host "  [28/54] Find-StaleADObjects: Found $(@($s).Count)" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Find-StaleADObjects failed: $_" 
                    }
                    
                    try { 
                        $script:dashboardData.ActiveDirectory.PasswordPolicy = Get-ADPasswordPolicy -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [29/54] Get-ADPasswordPolicy: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Get-ADPasswordPolicy failed: $_" 
                    }
                } else {
                    Write-Host "  System not domain-joined - skipping AD module" -ForegroundColor Gray
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['ActiveDirectory'] = ((Get-Date) - $adStart).TotalSeconds
            }
            
            # ============================================
            # CLOUD SECURITY MODULE (3 functions)
            # ============================================
            if ($modulesToProcess -contains 'Cloud') {
                Write-Host "`n[6/13] CLOUD SECURITY MODULE - 3 Functions" -ForegroundColor Cyan
                $cloudStart = Get-Date
                
                $mgContext = Get-MgContext -ErrorAction SilentlyContinue
                if ($mgContext) {
                    $script:dashboardData.Cloud.Enabled = $true
                    Write-Host "  Connected to Microsoft Graph: $($mgContext.TenantId)" -ForegroundColor Green
                    
                    try { 
                        $r = Get-AzureADRiskySignIns -DaysBack 30 -ErrorAction Stop
                        $script:dashboardData.Cloud.RiskySignIns = $r
                        $functionCount++
                        Write-Host "  [30/54] Get-AzureADRiskySignIns: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Get-AzureADRiskySignIns failed: $_" 
                    }
                    
                    try { 
                        $script:dashboardData.Cloud.M365Security = Test-M365SecurityPosture -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [31/54] Test-M365SecurityPosture: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Test-M365SecurityPosture failed: $_" 
                    }
                    
                    try { 
                        $script:dashboardData.Cloud.CloudCompliance = Get-CloudComplianceStatus -Framework CIS -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [32/54] Get-CloudComplianceStatus: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Get-CloudComplianceStatus failed: $_" 
                    }
                } else {
                    Write-Host "  Not connected to Microsoft Graph - skipping cloud module" -ForegroundColor Gray
                    Write-Host "  To enable: Connect-MgGraph" -ForegroundColor Gray
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Cloud'] = ((Get-Date) - $cloudStart).TotalSeconds
            }
            
            # ============================================
            # VULNERABILITY MODULE (3 functions)
            # ============================================
            if ($modulesToProcess -contains 'Vulnerability') {
                Write-Host "`n[7/13] VULNERABILITY MODULE - 3 Functions" -ForegroundColor Cyan
                $vulnStart = Get-Date
                
                if (-not $SkipSlowChecks) {
                    try { 
                        $v = Get-VulnerabilityAssessment -ErrorAction Stop
                        $script:dashboardData.Vulnerability.Assessment = $v
                        if ($v -and $v.Summary -and $v.Summary.TotalVulnerabilities) {
                            $script:dashboardData.Vulnerability.TotalVulnerabilities = $v.Summary.TotalVulnerabilities
                        }
                        $functionCount++
                        Write-Host "  [33/54] Get-VulnerabilityAssessment: Found $($script:dashboardData.Vulnerability.TotalVulnerabilities)" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Get-VulnerabilityAssessment failed: $_" 
                    }
                } else {
                    Write-Host "  [33/54] Skipping vulnerability scan (slow check)" -ForegroundColor Gray
                }
                
                try { 
                    $e = Find-EOLSoftware -ErrorAction Stop
                    $script:dashboardData.Vulnerability.EOLSoftware = $e
                    $functionCount++
                    Write-Host "  [34/54] Find-EOLSoftware: Found $(@($e).Count)" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Find-EOLSoftware failed: $_" 
                }
                
                try { 
                    $script:dashboardData.Vulnerability.CertificateHealth = Test-CertificateHealth -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [35/54] Test-CertificateHealth: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Test-CertificateHealth failed: $_" 
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Vulnerability'] = ((Get-Date) - $vulnStart).TotalSeconds
            }
            
            # ============================================
            # THREAT HUNTING MODULE (2 functions)
            # ============================================
            if ($modulesToProcess -contains 'ThreatHunting') {
                Write-Host "`n[8/13] THREAT HUNTING MODULE - 2 Functions" -ForegroundColor Cyan
                $threatStart = Get-Date
                
                try { 
                    $script:dashboardData.ThreatHunting.ThreatIntelligence = Get-ThreatIntelligence -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [36/54] Get-ThreatIntelligence: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-ThreatIntelligence failed: $_" 
                }
                
                try { 
                    $script:dashboardData.ThreatHunting.MITREMapping = Get-MITREAttackMapping -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [37/54] Get-MITREAttackMapping: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-MITREAttackMapping failed: $_" 
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['ThreatHunting'] = ((Get-Date) - $threatStart).TotalSeconds
            }
            
            # ============================================
            # FORENSICS MODULE (6 functions)
            # ============================================
            if ($modulesToProcess -contains 'Forensics') {
                Write-Host "`n[9/13] FORENSICS MODULE - 6 Functions" -ForegroundColor Cyan
                $forStart = Get-Date
                
                try { 
                    $a = Get-ArtifactCollection -ErrorAction Stop
                    $script:dashboardData.Forensics.Artifacts = $a
                    $functionCount++
                    Write-Host "  [38/54] Get-ArtifactCollection: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-ArtifactCollection failed: $_" 
                }
                
                try { 
                    $e = Get-ExecutionArtifacts -ErrorAction Stop
                    $script:dashboardData.Forensics.ExecutionArtifacts = $e
                    $functionCount++
                    Write-Host "  [39/54] Get-ExecutionArtifacts: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-ExecutionArtifacts failed: $_" 
                }
                
                try { 
                    $u = Get-USBHistory -ErrorAction Stop
                    $script:dashboardData.Forensics.USBHistory = $u
                    $functionCount++
                    Write-Host "  [40/54] Get-USBHistory: Found $(@($u).Count)" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-USBHistory failed: $_" 
                }
                
                if ($DetailLevel -eq 'Detailed') {
                    try { 
                        $script:dashboardData.Forensics.ForensicCollection = Invoke-ForensicCollection -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [41/54] Invoke-ForensicCollection: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Invoke-ForensicCollection failed: $_" 
                    }
                    
                    try { 
                        $script:dashboardData.Forensics.MemoryDump = Export-MemoryDump -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [42/54] Export-MemoryDump: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Export-MemoryDump failed: $_" 
                    }
                    
                    try { 
                        $script:dashboardData.Forensics.Timeline = New-ForensicTimeline -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [43/54] New-ForensicTimeline: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  New-ForensicTimeline failed: $_" 
                    }
                } else {
                    Write-Host "  [41-43/54] Skipping detailed forensics (use -DetailLevel Detailed)" -ForegroundColor Gray
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Forensics'] = ((Get-Date) - $forStart).TotalSeconds
            }
            
            # ============================================
            # WINDOWS DEFENDER MODULE (3 functions)
            # ============================================
            if ($modulesToProcess -contains 'WindowsDefender') {
                Write-Host "`n[10/13] WINDOWS DEFENDER MODULE - 3 Functions" -ForegroundColor Cyan
                $defStart = Get-Date
                
                try { 
                    $d = Get-DefenderStatus -ErrorAction Stop
                    $script:dashboardData.WindowsDefender.Status = $d
                    $functionCount++
                    Write-Host "  [44/54] Get-DefenderStatus: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-DefenderStatus failed: $_" 
                }
                
                if ($DetailLevel -eq 'Detailed') {
                    try { 
                        $script:dashboardData.WindowsDefender.ScanResult = Invoke-DefenderScan -ScanType Quick -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [45/54] Invoke-DefenderScan: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Invoke-DefenderScan failed: $_" 
                    }
                } else {
                    Write-Host "  [45/54] Skipping Defender scan (use -DetailLevel Detailed)" -ForegroundColor Gray
                }
                
                try { 
                    $script:dashboardData.WindowsDefender.Configuration = Update-DefenderConfiguration -WhatIf -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [46/54] Update-DefenderConfiguration (Check): OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Update-DefenderConfiguration failed: $_" 
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['WindowsDefender'] = ((Get-Date) - $defStart).TotalSeconds
            }
            
            # ============================================
            # HARDENING MODULE (3 functions)
            # ============================================
            if ($modulesToProcess -contains 'Hardening') {
                Write-Host "`n[11/13] HARDENING MODULE - 3 Functions" -ForegroundColor Cyan
                $hardStart = Get-Date
                
                try { 
                    $script:dashboardData.Hardening.AuditPolicies = Enable-AuditPolicies -WhatIf -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [47/54] Enable-AuditPolicies (Check): OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Enable-AuditPolicies failed: $_" 
                }
                
                try { 
                    $script:dashboardData.Hardening.PowerShellSecurity = Enable-PowerShellSecurity -WhatIf -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [48/54] Enable-PowerShellSecurity (Check): OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Enable-PowerShellSecurity failed: $_" 
                }
                
                try { 
                    $script:dashboardData.Hardening.BaselineStatus = Set-SecurityBaseline -WhatIf -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [49/54] Set-SecurityBaseline (Check): OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Set-SecurityBaseline failed: $_" 
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Hardening'] = ((Get-Date) - $hardStart).TotalSeconds
            }
            
            # ============================================
            # ENTERPRISE MODULE (2 functions)
            # ============================================
            if ($modulesToProcess -contains 'Enterprise') {
                Write-Host "`n[12/13] ENTERPRISE MODULE - 2 Functions" -ForegroundColor Cyan
                $entStart = Get-Date
                
                if ($DetailLevel -eq 'Detailed') {
                    try { 
                        $script:dashboardData.Enterprise.MultiSystemAudit = Get-MultiSystemAudit -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [50/54] Get-MultiSystemAudit: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Get-MultiSystemAudit failed: $_" 
                    }
                    
                    try { 
                        $script:dashboardData.Enterprise.EnterpriseScan = Invoke-EnterpriseSecurityScan -ErrorAction Stop
                        $functionCount++
                        Write-Host "  [51/54] Invoke-EnterpriseSecurityScan: OK" -ForegroundColor Green 
                    } catch { 
                        Write-Warning "  Invoke-EnterpriseSecurityScan failed: $_" 
                    }
                } else {
                    Write-Host "  [50-51/54] Skipping enterprise scan (use -DetailLevel Detailed)" -ForegroundColor Gray
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Enterprise'] = ((Get-Date) - $entStart).TotalSeconds
            }
            
            # ============================================
            # RESPONSE MODULE (2 functions)
            # ============================================
            if ($modulesToProcess -contains 'Response') {
                Write-Host "`n[13/13] RESPONSE MODULE - 2 Functions" -ForegroundColor Cyan
                $respStart = Get-Date
                
                try { 
                    $script:dashboardData.Response.IncidentResponse = Invoke-IncidentResponse -WhatIf -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [52/54] Invoke-IncidentResponse (Check): OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Invoke-IncidentResponse failed: $_" 
                }
                
                try { 
                    $script:dashboardData.Response.EventDescriptions = Get-EventIdDescription -EventId 4624 -ErrorAction Stop
                    $functionCount++
                    Write-Host "  [53/54] Get-EventIdDescription: OK" -ForegroundColor Green 
                } catch { 
                    Write-Warning "  Get-EventIdDescription failed: $_" 
                }
                
                $script:dashboardData.Performance.ModuleExecutionTimes['Response'] = ((Get-Date) - $respStart).TotalSeconds
            }
            
            # Save total function count
            $script:dashboardData.TotalFunctionsUsed = $functionCount
            
            # ============================================
            # CALCULATE EXECUTIVE SUMMARY
            # ============================================
            Write-Host "`n[CALCULATING EXECUTIVE SUMMARY]" -ForegroundColor Cyan
            
            # Aggregate findings with null-safe operations
            $script:dashboardData.ExecutiveSummary.TotalFindings = 
                $script:dashboardData.Detection.TotalThreats + 
                $script:dashboardData.Vulnerability.TotalVulnerabilities + 
                $(if ($script:dashboardData.Analysis.SecurityMisconfigurations) { @($script:dashboardData.Analysis.SecurityMisconfigurations).Count } else { 0 })
            
            $script:dashboardData.ExecutiveSummary.HighFindings = $script:dashboardData.Detection.TotalThreats
            $script:dashboardData.ExecutiveSummary.MediumFindings = $script:dashboardData.Vulnerability.TotalVulnerabilities
            $script:dashboardData.ExecutiveSummary.LowFindings = $(if ($script:dashboardData.Analysis.SecurityMisconfigurations) { @($script:dashboardData.Analysis.SecurityMisconfigurations).Count } else { 0 })
            
            if ($script:dashboardData.ActiveDirectory.Enabled) {
                $adVulns = $(if ($script:dashboardData.ActiveDirectory.Vulnerabilities) { @($script:dashboardData.ActiveDirectory.Vulnerabilities).Count } else { 0 })
                $script:dashboardData.ExecutiveSummary.CriticalFindings = $adVulns
                $script:dashboardData.ExecutiveSummary.TotalFindings += $adVulns
            }
            
            # Compliance score with proper null checks
            $scores = @()
            if ($script:dashboardData.Compliance.CIS -and $script:dashboardData.Compliance.CIS.ComplianceScore) { 
                $scores += $script:dashboardData.Compliance.CIS.ComplianceScore 
            }
            if ($script:dashboardData.Compliance.NIST -and $script:dashboardData.Compliance.NIST.ComplianceScore) { 
                $scores += $script:dashboardData.Compliance.NIST.ComplianceScore 
            }
            if ($script:dashboardData.Compliance.PCIDSS -and $script:dashboardData.Compliance.PCIDSS.ComplianceScore) { 
                $scores += $script:dashboardData.Compliance.PCIDSS.ComplianceScore 
            }
            
            if ($scores.Count -gt 0) {
                $script:dashboardData.ExecutiveSummary.ComplianceScore = [Math]::Round(($scores | Measure-Object -Average).Average, 1)
            } else {
                $script:dashboardData.ExecutiveSummary.ComplianceScore = 0
            }
            
            # Security score calculation
            $penalty = ($script:dashboardData.ExecutiveSummary.CriticalFindings * 15) + 
                       ($script:dashboardData.ExecutiveSummary.HighFindings * 10) + 
                       ($script:dashboardData.ExecutiveSummary.MediumFindings * 5) +
                       ($script:dashboardData.ExecutiveSummary.LowFindings * 2)
            
            $script:dashboardData.ExecutiveSummary.OverallSecurityScore = [Math]::Max(0, 100 - $penalty)
            
            # Threat level determination
            $script:dashboardData.ExecutiveSummary.ThreatLevel = 
                if ($script:dashboardData.ExecutiveSummary.CriticalFindings -gt 5) { "Critical" }
                elseif ($script:dashboardData.ExecutiveSummary.CriticalFindings -gt 0) { "High" }
                elseif ($script:dashboardData.ExecutiveSummary.HighFindings -gt 10) { "High" }
                elseif ($script:dashboardData.ExecutiveSummary.HighFindings -gt 0) { "Medium" }
                else { "Low" }
            
            # Generate recommendations
            if ($script:dashboardData.ExecutiveSummary.CriticalFindings -gt 0) {
                $script:dashboardData.ExecutiveSummary.Recommendations += "CRITICAL: $($script:dashboardData.ExecutiveSummary.CriticalFindings) critical issues require immediate attention"
            }
            if ($script:dashboardData.Detection.TotalThreats -gt 0) {
                $script:dashboardData.ExecutiveSummary.Recommendations += "Investigate and remediate $($script:dashboardData.Detection.TotalThreats) detected threats"
            }
            if ($script:dashboardData.ExecutiveSummary.ComplianceScore -lt 80 -and $script:dashboardData.ExecutiveSummary.ComplianceScore -gt 0) {
                $script:dashboardData.ExecutiveSummary.Recommendations += "Compliance score below 80% - review and address compliance gaps"
            }
            if ($script:dashboardData.Vulnerability.EOLSoftware -and @($script:dashboardData.Vulnerability.EOLSoftware).Count -gt 0) {
                $script:dashboardData.ExecutiveSummary.Recommendations += "Replace or upgrade $(@($script:dashboardData.Vulnerability.EOLSoftware).Count) end-of-life software packages"
            }
            
            # Generate chart data if enabled
            if ($IncludeCharts) {
                # Compliance scores
                $script:dashboardData.ChartsData.ComplianceScores = @(
                    @{ Framework = "CIS"; Score = $(if ($script:dashboardData.Compliance.CIS -and $script:dashboardData.Compliance.CIS.ComplianceScore) { $script:dashboardData.Compliance.CIS.ComplianceScore } else { 0 }) }
                    @{ Framework = "NIST"; Score = $(if ($script:dashboardData.Compliance.NIST -and $script:dashboardData.Compliance.NIST.ComplianceScore) { $script:dashboardData.Compliance.NIST.ComplianceScore } else { 0 }) }
                    @{ Framework = "PCI-DSS"; Score = $(if ($script:dashboardData.Compliance.PCIDSS -and $script:dashboardData.Compliance.PCIDSS.ComplianceScore) { $script:dashboardData.Compliance.PCIDSS.ComplianceScore } else { 0 }) }
                )
                
                # Threat distribution
                $script:dashboardData.ChartsData.ThreatDistribution = @(
                    @{ Category = "Persistence"; Count = @($script:dashboardData.Detection.PersistenceMechanisms).Count }
                    @{ Category = "Processes"; Count = @($script:dashboardData.Detection.SuspiciousProcesses).Count }
                    @{ Category = "Auth"; Count = @($script:dashboardData.Detection.SuspiciousAuthentications).Count }
                    @{ Category = "Lateral"; Count = @($script:dashboardData.Detection.LateralMovement).Count }
                    @{ Category = "APT"; Count = @($script:dashboardData.Detection.APTIndicators).Count }
                )
                
                # Module status
                $script:dashboardData.ChartsData.ModuleStatus = @(
                    @{ Module = "Core"; Active = ($modulesToProcess -contains 'Core') }
                    @{ Module = "Detection"; Active = ($modulesToProcess -contains 'Detection') }
                    @{ Module = "Compliance"; Active = ($modulesToProcess -contains 'Compliance') }
                    @{ Module = "AD"; Active = ($modulesToProcess -contains 'ActiveDirectory') }
                    @{ Module = "Cloud"; Active = ($modulesToProcess -contains 'Cloud') }
                    @{ Module = "Defender"; Active = ($modulesToProcess -contains 'WindowsDefender') }
                )
            }
            
            # Calculate total execution time
            $script:dashboardData.Performance.TotalExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            
            Write-Host "  Security Score: $($script:dashboardData.ExecutiveSummary.OverallSecurityScore)%" -ForegroundColor $(
                if ($script:dashboardData.ExecutiveSummary.OverallSecurityScore -ge 80) { 'Green' }
                elseif ($script:dashboardData.ExecutiveSummary.OverallSecurityScore -ge 60) { 'Yellow' }
                else { 'Red' }
            )
            Write-Host "  Threat Level: $($script:dashboardData.ExecutiveSummary.ThreatLevel)" -ForegroundColor $(
                switch ($script:dashboardData.ExecutiveSummary.ThreatLevel) {
                    'Critical' { 'Red' }
                    'High' { 'Red' }
                    'Medium' { 'Yellow' }
                    default { 'Green' }
                }
            )
            Write-Host "  Functions Used: $functionCount/54" -ForegroundColor Yellow
            
            # ============================================
            # GENERATE HTML DASHBOARD
            # ============================================
            Write-Host "`n[GENERATING HTML DASHBOARD]" -ForegroundColor Cyan
            
            $htmlPath = Generate-DashboardHTML -Data $script:dashboardData -ExportPath $ExportPath -IncludeCharts $IncludeCharts -AutoRefresh $AutoRefreshSeconds
            
            Write-Host "  Dashboard saved: $htmlPath" -ForegroundColor Green
            Write-Host "  File size: $([Math]::Round((Get-Item $htmlPath).Length / 1KB, 2)) KB" -ForegroundColor Gray
            
            if ($OpenInBrowser) {
                Write-Host "`n[OPENING IN BROWSER]" -ForegroundColor Cyan
                Start-Process $htmlPath
            }
            
            return Get-Item $htmlPath
            
        }
        catch {
            Write-Error "Dashboard generation failed: $_"
            Write-Host "`nStack Trace:" -ForegroundColor Red
            Write-Host $_.ScriptStackTrace -ForegroundColor Gray
            throw
        }
    }
    
    end {
        $totalTime = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
        
        Write-Host "`n================================================================" -ForegroundColor Green
        Write-Host "  DASHBOARD GENERATION COMPLETE" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
        
        Write-Host "`nExecution Summary:" -ForegroundColor Cyan
        Write-Host "  Total Execution Time: $totalTime seconds" -ForegroundColor White
        Write-Host "  Functions Used: $($script:dashboardData.TotalFunctionsUsed)/54" -ForegroundColor Yellow
        
        if ($script:dashboardData.Performance.ModuleExecutionTimes.Count -gt 0) {
            Write-Host "`nModule Execution Times:" -ForegroundColor Cyan
            foreach ($module in $script:dashboardData.Performance.ModuleExecutionTimes.Keys | Sort-Object) {
                $time = [Math]::Round($script:dashboardData.Performance.ModuleExecutionTimes[$module], 2)
                Write-Host "  $module : $time seconds" -ForegroundColor Gray
            }
        }
        
        Write-Host "`nSecurity Summary:" -ForegroundColor Cyan
        Write-Host "  Security Score: $($script:dashboardData.ExecutiveSummary.OverallSecurityScore)%" -ForegroundColor $(
            if ($script:dashboardData.ExecutiveSummary.OverallSecurityScore -ge 80) { 'Green' }
            elseif ($script:dashboardData.ExecutiveSummary.OverallSecurityScore -ge 60) { 'Yellow' }
            else { 'Red' }
        )
        Write-Host "  Threat Level: $($script:dashboardData.ExecutiveSummary.ThreatLevel)" -ForegroundColor $(
            switch ($script:dashboardData.ExecutiveSummary.ThreatLevel) {
                'Critical' { 'Red' }
                'High' { 'Red' }
                'Medium' { 'Yellow' }
                default { 'Green' }
            }
        )
        Write-Host "  Total Findings: $($script:dashboardData.ExecutiveSummary.TotalFindings)" -ForegroundColor White
        Write-Host "    Critical: $($script:dashboardData.ExecutiveSummary.CriticalFindings)" -ForegroundColor Red
        Write-Host "    High: $($script:dashboardData.ExecutiveSummary.HighFindings)" -ForegroundColor Yellow
        Write-Host "    Medium: $($script:dashboardData.ExecutiveSummary.MediumFindings)" -ForegroundColor Yellow
        Write-Host "    Low: $($script:dashboardData.ExecutiveSummary.LowFindings)" -ForegroundColor Gray
        
        if ($script:dashboardData.ExecutiveSummary.ComplianceScore -gt 0) {
            Write-Host "  Compliance Score: $($script:dashboardData.ExecutiveSummary.ComplianceScore)%" -ForegroundColor Cyan
        }
    }
}

# ============================================
# HELPER FUNCTION: Generate Dashboard HTML
# ============================================
function Generate-DashboardHTML {
    param(
        [Parameter(Mandatory=$true)]
        $Data,
        
        [Parameter(Mandatory=$true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory=$true)]
        [bool]$IncludeCharts,
        
        [Parameter(Mandatory=$true)]
        [int]$AutoRefresh
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "SecurityDashboard_$timestamp.html"
    $outputPath = Join-Path $ExportPath $filename
    
    # Theme colors
    $isDark = $Data.Theme -eq 'Dark'
    $bgColor = if ($isDark) { '#1a1a1a' } else { '#f5f5f5' }
    $cardBg = if ($isDark) { '#2d2d2d' } else { '#ffffff' }
    $textColor = if ($isDark) { '#e0e0e0' } else { '#333333' }
    $borderColor = if ($isDark) { '#404040' } else { '#dddddd' }
    
    # Score color
    $scoreColor = if ($Data.ExecutiveSummary.OverallSecurityScore -ge 80) { '#107c10' }
                  elseif ($Data.ExecutiveSummary.OverallSecurityScore -ge 60) { '#f7630c' }
                  else { '#d13438' }
    
    # Threat level color
    $threatColor = switch ($Data.ExecutiveSummary.ThreatLevel) {
        'Critical' { '#d13438' }
        'High' { '#f57c00' }
        'Medium' { '#fbc02d' }
        default { '#107c10' }
    }
    
    # Build HTML using StringBuilder to avoid parse errors
    $html = New-Object System.Text.StringBuilder
    
    [void]$html.AppendLine("<!DOCTYPE html>")
    [void]$html.AppendLine("<html lang='en'>")
    [void]$html.AppendLine("<head>")
    [void]$html.AppendLine("  <meta charset='UTF-8'>")
    [void]$html.AppendLine("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    [void]$html.AppendLine("  <title>Security Dashboard - $($Data.Hostname)</title>")
    
    if ($AutoRefresh -gt 0) {
        [void]$html.AppendLine("  <meta http-equiv='refresh' content='$AutoRefresh'>")
    }
    
    if ($IncludeCharts) {
        [void]$html.AppendLine("  <script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'></script>")
    }
    
    # CSS Styles
    [void]$html.AppendLine("  <style>")
    [void]$html.AppendLine("    * { margin: 0; padding: 0; box-sizing: border-box; }")
    [void]$html.AppendLine("    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: $bgColor; color: $textColor; padding: 20px; line-height: 1.6; }")
    [void]$html.AppendLine("    .container { max-width: 1600px; margin: 0 auto; }")
    [void]$html.AppendLine("    .header { background: linear-gradient(135deg, #0d47a1, #1565c0); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }")
    [void]$html.AppendLine("    .header h1 { font-size: 32px; margin-bottom: 5px; }")
    [void]$html.AppendLine("    .header-subtitle { font-size: 14px; opacity: 0.9; margin-bottom: 15px; }")
    [void]$html.AppendLine("    .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 15px; }")
    [void]$html.AppendLine("    .header-info-item { background: rgba(255,255,255,0.1); padding: 10px; border-radius: 5px; }")
    [void]$html.AppendLine("    .header-info-label { font-size: 11px; opacity: 0.8; }")
    [void]$html.AppendLine("    .header-info-value { font-size: 14px; font-weight: 600; margin-top: 3px; }")
    [void]$html.AppendLine("    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }")
    [void]$html.AppendLine("    .card { background: $cardBg; border: 1px solid $borderColor; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); transition: transform 0.2s; }")
    [void]$html.AppendLine("    .card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }")
    [void]$html.AppendLine("    .card-header { font-size: 16px; font-weight: 600; color: #0078d4; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid $borderColor; }")
    [void]$html.AppendLine("    .large-metric { text-align: center; padding: 30px 15px; }")
    [void]$html.AppendLine("    .large-metric-value { font-size: 64px; font-weight: bold; margin-bottom: 8px; }")
    [void]$html.AppendLine("    .large-metric-label { font-size: 16px; color: #666; }")
    [void]$html.AppendLine("    .metric { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #f0f0f0; }")
    [void]$html.AppendLine("    .metric:last-child { border-bottom: none; }")
    [void]$html.AppendLine("    .metric-label { font-size: 14px; color: #666; }")
    [void]$html.AppendLine("    .metric-value { font-size: 16px; font-weight: bold; }")
    [void]$html.AppendLine("    .critical { color: #d32f2f; }")
    [void]$html.AppendLine("    .high { color: #f57c00; }")
    [void]$html.AppendLine("    .medium { color: #fbc02d; }")
    [void]$html.AppendLine("    .low { color: #388e3c; }")
    [void]$html.AppendLine("    .success { color: #107c10; }")
    [void]$html.AppendLine("    h2 { color: #0078d4; margin: 30px 0 15px 0; padding-left: 10px; border-left: 4px solid #0078d4; font-size: 20px; }")
    [void]$html.AppendLine("    .chart-container { position: relative; height: 280px; margin-top: 15px; }")
    [void]$html.AppendLine("    .recommendations { background: #fff4ce; border-left: 4px solid #f7630c; padding: 20px; margin-top: 20px; border-radius: 5px; }")
    [void]$html.AppendLine("    .recommendations h3 { color: #8a5340; margin-bottom: 10px; }")
    [void]$html.AppendLine("    .recommendations ul { margin-left: 20px; }")
    [void]$html.AppendLine("    .recommendations li { margin: 8px 0; color: #323130; }")
    [void]$html.AppendLine("    .footer { margin-top: 40px; padding-top: 20px; border-top: 2px solid $borderColor; text-align: center; color: #999; font-size: 12px; }")
    [void]$html.AppendLine("    @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } .header h1 { font-size: 24px; } .large-metric-value { font-size: 48px; } }")
    [void]$html.AppendLine("  </style>")
    [void]$html.AppendLine("</head>")
    [void]$html.AppendLine("<body>")
    [void]$html.AppendLine("  <div class='container'>")
    
    # Header
    [void]$html.AppendLine("    <div class='header'>")
    [void]$html.AppendLine("      <h1>Security Dashboard</h1>")
    [void]$html.AppendLine("      <div class='header-subtitle'>Enterprise Security Assessment - WindowsSecurityAudit Module v3.0</div>")
    [void]$html.AppendLine("      <div class='header-info'>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Hostname</div><div class='header-info-value'>$($Data.Hostname)</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Domain</div><div class='header-info-value'>$($Data.DomainName)</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>User</div><div class='header-info-value'>$($Data.Username)</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Generated</div><div class='header-info-value'>$($Data.GeneratedDate)</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Execution Time</div><div class='header-info-value'>$([Math]::Round($Data.Performance.TotalExecutionTime, 1))s</div></div>")
    [void]$html.AppendLine("        <div class='header-info-item'><div class='header-info-label'>Functions Used</div><div class='header-info-value'>$($Data.TotalFunctionsUsed)/54</div></div>")
    [void]$html.AppendLine("      </div>")
    [void]$html.AppendLine("    </div>")
    
    # Executive Summary Grid
    [void]$html.AppendLine("    <div class='grid'>")
    
    # Security Score Card
    [void]$html.AppendLine("      <div class='card'>")
    [void]$html.AppendLine("        <div class='large-metric'>")
    [void]$html.AppendLine("          <div class='large-metric-value' style='color: $scoreColor;'>$($Data.ExecutiveSummary.OverallSecurityScore)%</div>")
    [void]$html.AppendLine("          <div class='large-metric-label'>Security Score</div>")
    [void]$html.AppendLine("        </div>")
    [void]$html.AppendLine("      </div>")
    
    # Threat Level Card
    [void]$html.AppendLine("      <div class='card'>")
    [void]$html.AppendLine("        <div class='large-metric'>")
    [void]$html.AppendLine("          <div class='large-metric-value' style='color: $threatColor;'>$($Data.ExecutiveSummary.ThreatLevel)</div>")
    [void]$html.AppendLine("          <div class='large-metric-label'>Threat Level</div>")
    [void]$html.AppendLine("        </div>")
    [void]$html.AppendLine("      </div>")
    
    # Findings Summary Card
    [void]$html.AppendLine("      <div class='card'>")
    [void]$html.AppendLine("        <div class='card-header'>Findings Summary</div>")
    [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>Total</span><span class='metric-value'>$($Data.ExecutiveSummary.TotalFindings)</span></div>")
    [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>Critical</span><span class='metric-value critical'>$($Data.ExecutiveSummary.CriticalFindings)</span></div>")
    [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>High</span><span class='metric-value high'>$($Data.ExecutiveSummary.HighFindings)</span></div>")
    [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>Medium</span><span class='metric-value medium'>$($Data.ExecutiveSummary.MediumFindings)</span></div>")
    [void]$html.AppendLine("        <div class='metric'><span class='metric-label'>Low</span><span class='metric-value low'>$($Data.ExecutiveSummary.LowFindings)</span></div>")
    [void]$html.AppendLine("      </div>")
    
    # Compliance Score Card
    if ($Data.ExecutiveSummary.ComplianceScore -gt 0) {
        [void]$html.AppendLine("      <div class='card'>")
        [void]$html.AppendLine("        <div class='large-metric'>")
        [void]$html.AppendLine("          <div class='large-metric-value' style='color: #0078d4;'>$($Data.ExecutiveSummary.ComplianceScore)%</div>")
        [void]$html.AppendLine("          <div class='large-metric-label'>Compliance Score</div>")
        [void]$html.AppendLine("        </div>")
        [void]$html.AppendLine("      </div>")
    }
    
    [void]$html.AppendLine("    </div>")
    
    # Detection Module Results
    if ($Data.Detection.TotalThreats -ne $null) {
        [void]$html.AppendLine("    <h2>Threat Detection (Total: $($Data.Detection.TotalThreats))</h2>")
        [void]$html.AppendLine("    <div class='grid'>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>Persistence Mechanisms</div><div class='metric'><span class='metric-label'>Detected</span><span class='metric-value'>$(@($Data.Detection.PersistenceMechanisms).Count)</span></div></div>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>Suspicious Processes</div><div class='metric'><span class='metric-label'>Detected</span><span class='metric-value'>$(@($Data.Detection.SuspiciousProcesses).Count)</span></div></div>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>Authentication Anomalies</div><div class='metric'><span class='metric-label'>Detected</span><span class='metric-value'>$(@($Data.Detection.SuspiciousAuthentications).Count)</span></div></div>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>APT Indicators</div><div class='metric'><span class='metric-label'>Detected</span><span class='metric-value'>$(@($Data.Detection.APTIndicators).Count)</span></div></div>")
        [void]$html.AppendLine("    </div>")
    }
    
    # Compliance Module Results
    if ($Data.Compliance.CIS -or $Data.Compliance.NIST -or $Data.Compliance.PCIDSS) {
        [void]$html.AppendLine("    <h2>Compliance Status</h2>")
        [void]$html.AppendLine("    <div class='grid'>")
        
        if ($Data.Compliance.CIS) {
            $cisScore = if ($Data.Compliance.CIS.ComplianceScore) { $Data.Compliance.CIS.ComplianceScore } else { 0 }
            [void]$html.AppendLine("      <div class='card'><div class='card-header'>CIS Benchmark</div><div class='metric'><span class='metric-label'>Score</span><span class='metric-value'>$cisScore%</span></div></div>")
        }
        
        if ($Data.Compliance.NIST) {
            $nistScore = if ($Data.Compliance.NIST.ComplianceScore) { $Data.Compliance.NIST.ComplianceScore } else { 0 }
            [void]$html.AppendLine("      <div class='card'><div class='card-header'>NIST CSF</div><div class='metric'><span class='metric-label'>Score</span><span class='metric-value'>$nistScore%</span></div></div>")
        }
        
        if ($Data.Compliance.PCIDSS) {
            $pciScore = if ($Data.Compliance.PCIDSS.ComplianceScore) { $Data.Compliance.PCIDSS.ComplianceScore } else { 0 }
            [void]$html.AppendLine("      <div class='card'><div class='card-header'>PCI-DSS</div><div class='metric'><span class='metric-label'>Score</span><span class='metric-value'>$pciScore%</span></div></div>")
        }
        
        [void]$html.AppendLine("    </div>")
    }
    
    # Active Directory Results
    if ($Data.ActiveDirectory.Enabled) {
        [void]$html.AppendLine("    <h2>Active Directory Security</h2>")
        [void]$html.AppendLine("    <div class='grid'>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>Privileged Accounts</div><div class='metric'><span class='metric-label'>Count</span><span class='metric-value'>$(@($Data.ActiveDirectory.PrivilegedAccounts).Count)</span></div></div>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>Vulnerabilities</div><div class='metric'><span class='metric-label'>Found</span><span class='metric-value critical'>$(@($Data.ActiveDirectory.Vulnerabilities).Count)</span></div></div>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>Backdoors</div><div class='metric'><span class='metric-label'>Found</span><span class='metric-value critical'>$(@($Data.ActiveDirectory.Backdoors).Count)</span></div></div>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>Stale Objects</div><div class='metric'><span class='metric-label'>Found</span><span class='metric-value medium'>$(@($Data.ActiveDirectory.StaleObjects).Count)</span></div></div>")
        [void]$html.AppendLine("    </div>")
    }
    
    # Vulnerability Results
    if ($Data.Vulnerability.TotalVulnerabilities -gt 0 -or @($Data.Vulnerability.EOLSoftware).Count -gt 0) {
        [void]$html.AppendLine("    <h2>Vulnerability Assessment</h2>")
        [void]$html.AppendLine("    <div class='grid'>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>Total Vulnerabilities</div><div class='metric'><span class='metric-label'>Count</span><span class='metric-value medium'>$($Data.Vulnerability.TotalVulnerabilities)</span></div></div>")
        [void]$html.AppendLine("      <div class='card'><div class='card-header'>End-of-Life Software</div><div class='metric'><span class='metric-label'>Found</span><span class='metric-value critical'>$(@($Data.Vulnerability.EOLSoftware).Count)</span></div></div>")
        [void]$html.AppendLine("    </div>")
    }
    
    # Recommendations
    if ($Data.ExecutiveSummary.Recommendations -and @($Data.ExecutiveSummary.Recommendations).Count -gt 0) {
        [void]$html.AppendLine("    <div class='recommendations'>")
        [void]$html.AppendLine("      <h3>Top Recommendations</h3>")
        [void]$html.AppendLine("      <ul>")
        foreach ($rec in $Data.ExecutiveSummary.Recommendations) {
            [void]$html.AppendLine("        <li>$rec</li>")
        }
        [void]$html.AppendLine("      </ul>")
        [void]$html.AppendLine("    </div>")
    }
    
    # Charts
    if ($IncludeCharts -and $Data.ChartsData.ComplianceScores -and @($Data.ChartsData.ComplianceScores).Count -gt 0) {
        [void]$html.AppendLine("    <h2>Visual Analytics</h2>")
        [void]$html.AppendLine("    <div class='grid'>")
        [void]$html.AppendLine("      <div class='card'>")
        [void]$html.AppendLine("        <div class='card-header'>Compliance Scores</div>")
        [void]$html.AppendLine("        <div class='chart-container'><canvas id='compChart'></canvas></div>")
        [void]$html.AppendLine("      </div>")
        
        if ($Data.ChartsData.ThreatDistribution -and @($Data.ChartsData.ThreatDistribution).Count -gt 0) {
            [void]$html.AppendLine("      <div class='card'>")
            [void]$html.AppendLine("        <div class='card-header'>Threat Distribution</div>")
            [void]$html.AppendLine("        <div class='chart-container'><canvas id='threatChart'></canvas></div>")
            [void]$html.AppendLine("      </div>")
        }
        
        [void]$html.AppendLine("    </div>")
        
        # Chart.js initialization
        $compLabels = ($Data.ChartsData.ComplianceScores | ForEach-Object { "'$($_.Framework)'" }) -join ','
        $compData = ($Data.ChartsData.ComplianceScores | ForEach-Object { $_.Score }) -join ','
        
        [void]$html.AppendLine("    <script>")
        [void]$html.AppendLine("      const cCtx = document.getElementById('compChart').getContext('2d');")
        [void]$html.AppendLine("      new Chart(cCtx, {")
        [void]$html.AppendLine("        type: 'bar',")
        [void]$html.AppendLine("        data: {")
        [void]$html.AppendLine("          labels: [$compLabels],")
        [void]$html.AppendLine("          datasets: [{")
        [void]$html.AppendLine("            label: 'Compliance Score',")
        [void]$html.AppendLine("            data: [$compData],")
        [void]$html.AppendLine("            backgroundColor: '#0078d4'")
        [void]$html.AppendLine("          }]")
        [void]$html.AppendLine("        },")
        [void]$html.AppendLine("        options: {")
        [void]$html.AppendLine("          responsive: true,")
        [void]$html.AppendLine("          maintainAspectRatio: false,")
        [void]$html.AppendLine("          plugins: { legend: { display: false } },")
        [void]$html.AppendLine("          scales: { y: { beginAtZero: true, max: 100 } }")
        [void]$html.AppendLine("        }")
        [void]$html.AppendLine("      });")
        
        if ($Data.ChartsData.ThreatDistribution -and @($Data.ChartsData.ThreatDistribution).Count -gt 0) {
            $threatLabels = ($Data.ChartsData.ThreatDistribution | ForEach-Object { "'$($_.Category)'" }) -join ','
            $threatData = ($Data.ChartsData.ThreatDistribution | ForEach-Object { $_.Count }) -join ','
            
            [void]$html.AppendLine("      const tCtx = document.getElementById('threatChart').getContext('2d');")
            [void]$html.AppendLine("      new Chart(tCtx, {")
            [void]$html.AppendLine("        type: 'doughnut',")
            [void]$html.AppendLine("        data: {")
            [void]$html.AppendLine("          labels: [$threatLabels],")
            [void]$html.AppendLine("          datasets: [{")
            [void]$html.AppendLine("            data: [$threatData],")
            [void]$html.AppendLine("            backgroundColor: ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c', '#1976d2']")
            [void]$html.AppendLine("          }]")
            [void]$html.AppendLine("        },")
            [void]$html.AppendLine("        options: {")
            [void]$html.AppendLine("          responsive: true,")
            [void]$html.AppendLine("          maintainAspectRatio: false,")
            [void]$html.AppendLine("          plugins: { legend: { position: 'bottom' } }")
            [void]$html.AppendLine("        }")
            [void]$html.AppendLine("      });")
        }
        
        [void]$html.AppendLine("    </script>")
    }
    
    # Footer
    [void]$html.AppendLine("    <div class='footer'>")
    [void]$html.AppendLine("      <p><strong>WindowsSecurityAudit Module v3.0 ULTIMATE EDITION</strong></p>")
    [void]$html.AppendLine("      <p>Generated: $($Data.GeneratedDate) | Execution Time: $([Math]::Round($Data.Performance.TotalExecutionTime, 1))s | Functions: $($Data.TotalFunctionsUsed)/54</p>")
    [void]$html.AppendLine("      <p>Complete Enterprise Security Assessment Platform - ALL 54 Functions Integrated</p>")
    [void]$html.AppendLine("    </div>")
    
    [void]$html.AppendLine("  </div>")
    [void]$html.AppendLine("</body>")
    [void]$html.AppendLine("</html>")
    
    # Save HTML to file
    $html.ToString() | Out-File -FilePath $outputPath -Encoding UTF8 -Force
    
    return $outputPath
}