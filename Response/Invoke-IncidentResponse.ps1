function Invoke-IncidentResponse {
    <#
    .SYNOPSIS
        Executes comprehensive incident response procedures
    .DESCRIPTION
        Performs automated incident response including threat containment, evidence collection,
        system isolation, and remediation actions
    .PARAMETER Severity
        Incident severity level: Low, Medium, High, Critical
    .PARAMETER IsolateSystem
        Isolate system from network (disconnect network adapters)
    .PARAMETER KillSuspiciousProcesses
        Terminate suspicious processes
    .PARAMETER CollectEvidence
        Collect forensic evidence
    .PARAMETER OutputPath
        Path to save incident response outputs
    .EXAMPLE
        Invoke-IncidentResponse -Severity High -CollectEvidence -OutputPath "C:\IR"
        Invoke-IncidentResponse -Severity Critical -IsolateSystem -KillSuspiciousProcesses -CollectEvidence
    .OUTPUTS
        PSCustomObject with incident response actions and results
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Low', 'Medium', 'High', 'Critical')]
        [string]$Severity,
        
        [Parameter()]
        [switch]$IsolateSystem,
        
        [Parameter()]
        [switch]$KillSuspiciousProcesses,
        
        [Parameter()]
        [switch]$CollectEvidence,
        
        [Parameter()]
        [string]$OutputPath = "C:\IncidentResponse_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    begin {
        Write-Host "=== INCIDENT RESPONSE INITIATED ===" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "Severity Level: $Severity" -ForegroundColor Red
        Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
        
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "Incident Response requires Administrator privileges!"
        }
        
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $results = [PSCustomObject]@{
            IncidentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Severity = $Severity
            ComputerName = $env:COMPUTERNAME
            Actions = @()
            ProcessesTerminated = @()
            NetworkIsolation = $false
            EvidenceCollected = @()
            Findings = @()
            Status = 'In Progress'
        }
        
        # Log file
        $logFile = Join-Path $OutputPath "IncidentResponse.log"
        
        function Write-IRLog {
            param([string]$Message, [string]$Level = 'INFO')
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logMessage = "[$timestamp] [$Level] $Message"
            Add-Content -Path $logFile -Value $logMessage
            
            switch ($Level) {
                'ERROR' { Write-Host $Message -ForegroundColor Red }
                'WARNING' { Write-Host $Message -ForegroundColor Yellow }
                'SUCCESS' { Write-Host $Message -ForegroundColor Green }
                default { Write-Host $Message -ForegroundColor White }
            }
        }
        
        Write-IRLog "Incident Response initiated - Severity: $Severity" 'INFO'
    }
    
    process {
        try {
            # Step 1: Quick Security Assessment
            Write-Host "`n[1/6] Running quick security assessment..." -ForegroundColor Cyan
            Write-IRLog "Running security assessment" 'INFO'
            
            try {
                $baseline = Get-SecurityBaseline
                $results.Findings += "Security Score: $($baseline.SecurityScore)/100"
                Write-IRLog "Security baseline: $($baseline.SecurityScore)/100" 'INFO'
            }
            catch {
                Write-IRLog "Could not complete security baseline: $_" 'WARNING'
            }
            
            # Step 2: Detect Active Threats
            Write-Host "`n[2/6] Detecting active threats..." -ForegroundColor Cyan
            Write-IRLog "Scanning for threats" 'INFO'
            
            $threats = @()
            
            # Scan for suspicious processes
            try {
                $suspiciousProcs = Find-SuspiciousProcesses -CheckSignatures
                if ($suspiciousProcs) {
                    $threats += $suspiciousProcs
                    $results.Findings += "$($suspiciousProcs.Count) suspicious processes detected"
                    Write-IRLog "$($suspiciousProcs.Count) suspicious processes found" 'WARNING'
                }
            }
            catch {
                Write-IRLog "Error scanning processes: $_" 'ERROR'
            }
            
            # Scan for persistence mechanisms
            try {
                $persistence = Find-PersistenceMechanisms
                if ($persistence.SuspiciousCount -gt 0) {
                    $results.Findings += "$($persistence.SuspiciousCount) persistence mechanisms detected"
                    Write-IRLog "$($persistence.SuspiciousCount) persistence mechanisms found" 'WARNING'
                }
            }
            catch {
                Write-IRLog "Error scanning persistence: $_" 'ERROR'
            }
            
            # Scan network anomalies
            try {
                $network = Find-NetworkAnomalies -IncludeEstablished
                if ($network.TotalAnomalies -gt 0) {
                    $results.Findings += "$($network.TotalAnomalies) network anomalies detected"
                    Write-IRLog "$($network.TotalAnomalies) network anomalies found" 'WARNING'
                }
            }
            catch {
                Write-IRLog "Error scanning network: $_" 'ERROR'
            }
            
            # Step 3: Network Isolation (if requested or Critical severity)
            if ($IsolateSystem -or $Severity -eq 'Critical') {
                Write-Host "`n[3/6] Isolating system from network..." -ForegroundColor Red
                
                if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Disable network adapters")) {
                    Write-IRLog "Attempting network isolation" 'WARNING'
                    
                    try {
                        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
                        foreach ($adapter in $adapters) {
                            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
                            $results.Actions += "Disabled network adapter: $($adapter.Name)"
                            Write-IRLog "Disabled adapter: $($adapter.Name)" 'SUCCESS'
                        }
                        $results.NetworkIsolation = $true
                        Write-Host "System isolated from network" -ForegroundColor Green
                    }
                    catch {
                        Write-IRLog "Failed to isolate network: $_" 'ERROR'
                        Write-Warning "Network isolation failed: $_"
                    }
                }
            }
            else {
                Write-Host "`n[3/6] Network isolation: SKIPPED" -ForegroundColor Yellow
                $results.Actions += "Network isolation skipped (not requested)"
            }
            
            # Step 4: Terminate Suspicious Processes
            if ($KillSuspiciousProcesses -and $threats) {
                Write-Host "`n[4/6] Terminating suspicious processes..." -ForegroundColor Red
                
                $highThreatProcs = $threats | Where-Object { $_.SuspicionScore -ge 60 } | Sort-Object -Property SuspicionScore -Descending
                
                foreach ($proc in $highThreatProcs) {
                    if ($PSCmdlet.ShouldProcess("Process $($proc.ProcessName) (PID: $($proc.ProcessId))", "Terminate")) {
                        try {
                            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
                            $results.ProcessesTerminated += [PSCustomObject]@{
                                ProcessName = $proc.ProcessName
                                ProcessId = $proc.ProcessId
                                SuspicionScore = $proc.SuspicionScore
                                Reason = $proc.Reasons
                            }
                            Write-IRLog "Terminated process: $($proc.ProcessName) (PID: $($proc.ProcessId))" 'SUCCESS'
                        }
                        catch {
                            Write-IRLog "Failed to terminate $($proc.ProcessName): $_" 'ERROR'
                        }
                    }
                }
                
                Write-Host "Terminated $($results.ProcessesTerminated.Count) suspicious processes" -ForegroundColor Green
            }
            else {
                Write-Host "`n[4/6] Process termination: SKIPPED" -ForegroundColor Yellow
                $results.Actions += "Process termination skipped"
            }
            
            # Step 5: Collect Forensic Evidence
            if ($CollectEvidence) {
                Write-Host "`n[5/6] Collecting forensic evidence..." -ForegroundColor Cyan
                Write-IRLog "Starting evidence collection" 'INFO'
                
                # Collect system information
                try {
                    $sysInfo = Get-SystemInfo -IncludeInstalledSoftware -IncludeHotfixes
                    $sysInfo | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "SystemInfo.json")
                    $results.EvidenceCollected += "System information"
                    Write-IRLog "Collected system information" 'SUCCESS'
                }
                catch {
                    Write-IRLog "Failed to collect system info: $_" 'ERROR'
                }
                
                # Collect running processes
                try {
                    Get-Process | Select-Object Name, Id, Path, StartTime, CPU, WorkingSet64 | 
                        Export-Csv (Join-Path $OutputPath "RunningProcesses.csv") -NoTypeInformation
                    $results.EvidenceCollected += "Running processes list"
                    Write-IRLog "Collected process list" 'SUCCESS'
                }
                catch {
                    Write-IRLog "Failed to collect processes: $_" 'ERROR'
                }
                
                # Collect network connections
                try {
                    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
                        Export-Csv (Join-Path $OutputPath "NetworkConnections.csv") -NoTypeInformation
                    $results.EvidenceCollected += "Network connections"
                    Write-IRLog "Collected network connections" 'SUCCESS'
                }
                catch {
                    Write-IRLog "Failed to collect network info: $_" 'ERROR'
                }
                
                # Collect event logs
                try {
                    $eventAnalysis = Get-EventLogAnalysis -Hours 48
                    $eventAnalysis | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "EventLogAnalysis.json")
                    $results.EvidenceCollected += "Event log analysis"
                    Write-IRLog "Collected event logs" 'SUCCESS'
                }
                catch {
                    Write-IRLog "Failed to collect event logs: $_" 'ERROR'
                }
                
                # Collect registry analysis
                try {
                    $regAnalysis = Get-RegistryAnalysis -IncludeAutoRun
                    $regAnalysis | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "RegistryAnalysis.json")
                    $results.EvidenceCollected += "Registry analysis"
                    Write-IRLog "Collected registry analysis" 'SUCCESS'
                }
                catch {
                    Write-IRLog "Failed to collect registry data: $_" 'ERROR'
                }
                
                Write-Host "Collected $($results.EvidenceCollected.Count) evidence artifacts" -ForegroundColor Green
            }
            else {
                Write-Host "`n[5/6] Evidence collection: SKIPPED" -ForegroundColor Yellow
                $results.Actions += "Evidence collection skipped"
            }
            
            # Step 6: Generate Incident Report
            Write-Host "`n[6/6] Generating incident report..." -ForegroundColor Cyan
            Write-IRLog "Generating final report" 'INFO'
            
            $results.Status = 'Completed'
            $results | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputPath "IncidentResponse_Report.json")
            
            # Create summary report
            $summary = @"
=== INCIDENT RESPONSE SUMMARY ===
Date/Time: $($results.IncidentDate)
Severity: $($results.Severity)
Computer: $($results.ComputerName)

FINDINGS:
$($results.Findings | ForEach-Object { "  - $_" } | Out-String)

ACTIONS TAKEN:
$($results.Actions | ForEach-Object { "  - $_" } | Out-String)

PROCESSES TERMINATED: $($results.ProcessesTerminated.Count)
$($results.ProcessesTerminated | ForEach-Object { "  - $($_.ProcessName) (PID: $($_.ProcessId)) - Score: $($_.SuspicionScore)" } | Out-String)

NETWORK ISOLATION: $($results.NetworkIsolation)

EVIDENCE COLLECTED: $($results.EvidenceCollected.Count) artifacts
$($results.EvidenceCollected | ForEach-Object { "  - $_" } | Out-String)

STATUS: $($results.Status)

All evidence and logs saved to: $OutputPath
"@
            
            $summary | Out-File (Join-Path $OutputPath "Summary.txt")
            Write-IRLog "Incident response completed" 'SUCCESS'
            
        }
        catch {
            $results.Status = 'Failed'
            Write-IRLog "Incident response failed: $_" 'ERROR'
            throw
        }
    }
    
    end {
        Write-Host "`n=== INCIDENT RESPONSE COMPLETE ===" -ForegroundColor Green
        Write-Host "Status: $($results.Status)" -ForegroundColor $(if ($results.Status -eq 'Completed') { 'Green' } else { 'Red' })
        Write-Host "Output directory: $OutputPath" -ForegroundColor Cyan
        Write-Host "`nReview the incident report and evidence before proceeding with remediation." -ForegroundColor Yellow
        
        return $results
    }
}