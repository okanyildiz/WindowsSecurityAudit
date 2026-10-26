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
            $sfcExitCode = $LASTEXITCODE

            # SFC output text is fully localized; the exit code and the CBS.log
            # '[SR]'/'Cannot repair' tokens (written in English by the SFC engine
            # regardless of UI language) are the locale-invariant sources
            $cbsLogPath = "$env:windir\Logs\CBS\CBS.log"
            $cbsLogAvailable = Test-Path $cbsLogPath
            $cannotRepairLines = @()
            if ($cbsLogAvailable) {
                $cannotRepairLines = @(Get-Content $cbsLogPath -Tail 500 -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match '\[SR\]' -and $_ -match 'Cannot repair' })
            }

            if ($sfcExitCode -ne 0) {
                $results.SFCResult = "SFC could not complete scan - may need to run in Safe Mode"
                Write-Warning "SFC could not complete the scan (exit code $sfcExitCode)"
            }
            elseif ($cannotRepairLines.Count -gt 0 -or
                    (-not $cbsLogAvailable -and $sfcOutput -match "Windows Resource Protection found corrupt files")) {
                $results.SFCResult = "Corrupt files found"

                if ($cannotRepairLines.Count -gt 0) {
                    $results.CorruptedFiles = $cannotRepairLines
                }
                elseif ($cbsLogAvailable) {
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
            elseif ($cbsLogAvailable -or $sfcOutput -match "Windows Resource Protection did not find any integrity violations") {
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
                $dismCheckExitCode = $LASTEXITCODE

                # DISM output text is fully localized and CheckHealth returns 0 for
                # both 'healthy' and 'repairable', so the exit code alone cannot
                # separate those; servicing-stack CBS.log markers ('[SR]'/'Cannot
                # repair', component-store corruption) are written in English
                $storeCorruptionLines = @()
                if ($cbsLogAvailable) {
                    $storeCorruptionLines = @(Get-Content $cbsLogPath -Tail 500 -ErrorAction SilentlyContinue |
                        Where-Object { $_ -match '(?i)component store' -and $_ -match '(?i)corrupt' })
                }

                $repairable = ($storeCorruptionLines.Count -gt 0) -or ($dismCheck -match "The component store is repairable")

                if ($dismCheckExitCode -ne 0) {
                    $results.DISMResult = "DISM CheckHealth failed (exit code $dismCheckExitCode) - review CBS.log"
                    Write-Warning "DISM CheckHealth failed with exit code $dismCheckExitCode"
                }
                elseif ($repairable) {
                    $results.DISMResult = "Repairable corruption detected"

                    if ($RepairFiles) {
                        Write-Host "Attempting DISM repair..." -ForegroundColor Yellow
                        $null = & dism /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String
                        $dismRepairExitCode = $LASTEXITCODE

                        if ($dismRepairExitCode -eq 0) {
                            $results.RepairSuccessful = $true
                            $results.DISMResult = "Repaired successfully"
                            Write-Host "DISM repair completed successfully" -ForegroundColor Green
                        }
                        else {
                            $results.DISMResult = "Repair failed (exit code $dismRepairExitCode) - review CBS.log"
                            Write-Warning "DISM RestoreHealth failed with exit code $dismRepairExitCode"
                        }
                    }
                }
                elseif ($dismCheck -match "No component store corruption detected") {
                    $results.DISMResult = "Healthy"
                    Write-Host "DISM: System image is healthy" -ForegroundColor Green
                }
                else {
                    $results.DISMResult = "Check completed - review CBS.log"
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