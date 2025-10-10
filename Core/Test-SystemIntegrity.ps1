function Test-SystemIntegrity {
    <#
    .SYNOPSIS
        Tests Windows system file integrity
    .DESCRIPTION
        Runs SFC and DISM commands to check and verify system file integrity
    .PARAMETER RepairFiles
        Attempt to repair corrupted files if found
    .PARAMETER DetailedScan
        Perform a more thorough system scan
    .EXAMPLE
        Test-SystemIntegrity
        Test-SystemIntegrity -RepairFiles -DetailedScan
    .OUTPUTS
        PSCustomObject with integrity check results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$RepairFiles,
        
        [Parameter()]
        [switch]$DetailedScan
    )
    
    begin {
        # Check for admin privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            throw "This function requires Administrator privileges. Please run PowerShell as Administrator."
        }
        
        Write-Host "Starting System Integrity Check..." -ForegroundColor Cyan
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            SFCResult = $null
            DISMResult = $null
            CorruptedFiles = @()
            RepairAttempted = $false
            RepairSuccessful = $false
            WindowsUpdateServices = @()  # Added this property
        }
    }
    
    process {
        try {
            # Run SFC scan
            Write-Host "Running System File Checker (SFC)..." -ForegroundColor Yellow
            $sfcOutput = & sfc /scannow 2>&1 | Out-String
            
            # Parse SFC results
            if ($sfcOutput -match "Windows Resource Protection found corrupt files") {
                $results.SFCResult = "Corrupt files found"
                
                # Get CBS log details (with error handling)
                $cbsLogPath = "$env:windir\Logs\CBS\CBS.log"
                if (Test-Path $cbsLogPath) {
                    $cbsLog = Get-Content $cbsLogPath -Tail 100 -ErrorAction SilentlyContinue | 
                        Where-Object { $_ -match "corrupt" -or $_ -match "repaired" }
                    if ($cbsLog) {
                        $results.CorruptedFiles = $cbsLog
                    }
                }
                
                if ($RepairFiles) {
                    Write-Host "Attempting to repair corrupt files..." -ForegroundColor Yellow
                    $results.RepairAttempted = $true
                }
            }
            elseif ($sfcOutput -match "Windows Resource Protection did not find any integrity violations") {
                $results.SFCResult = "No integrity violations found"
                Write-Host "SFC: No integrity violations found" -ForegroundColor Green
            }
            elseif ($sfcOutput -match "Windows Resource Protection could not perform") {
                $results.SFCResult = "SFC could not complete scan - may need to run in Safe Mode"
                Write-Warning "SFC could not complete the scan"
            }
            else {
                $results.SFCResult = "Scan completed - check CBS.log for details"
            }
            
            # Run DISM if detailed scan requested
            if ($DetailedScan) {
                Write-Host "Running DISM health check..." -ForegroundColor Yellow
                
                # Check image health
                $dismCheck = & dism /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String
                
                if ($dismCheck -match "No component store corruption detected") {
                    $results.DISMResult = "Healthy"
                    Write-Host "DISM: System image is healthy" -ForegroundColor Green
                }
                elseif ($dismCheck -match "The component store is repairable") {
                    $results.DISMResult = "Repairable corruption detected"
                    
                    if ($RepairFiles) {
                        Write-Host "Attempting DISM repair..." -ForegroundColor Yellow
                        $dismRepair = & dism /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String
                        
                        if ($dismRepair -match "The restore operation completed successfully") {
                            $results.RepairSuccessful = $true
                            $results.DISMResult = "Repaired successfully"
                            Write-Host "DISM repair completed successfully" -ForegroundColor Green
                        }
                    }
                }
                else {
                    $results.DISMResult = "Check completed"
                }
            }
            
            # Check Windows Update components
            Write-Host "Checking Windows Update components..." -ForegroundColor Yellow
            $serviceNames = @('wuauserv', 'cryptSvc', 'bits', 'msiserver')
            $services = @()
            
            foreach ($serviceName in $serviceNames) {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    $services += [PSCustomObject]@{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        Status = $service.Status
                        StartType = $service.StartType
                    }
                }
            }
            
            $results.WindowsUpdateServices = $services
            
        }
        catch {
            Write-Error "Error during system integrity check: $_"
            throw
        }
    }
    
    end {
        return $results
    }
}