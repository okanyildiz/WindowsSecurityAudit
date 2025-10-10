<#
.SYNOPSIS
    Windows Security Audit Module - Main module file
.DESCRIPTION
    Comprehensive Windows security audit toolkit for threat detection and incident response
.VERSION
    1.0.0
.AUTHOR
    Security Team
#>

# Set strict mode
Set-StrictMode -Version Latest

# Module variables
$script:ModuleRoot = $PSScriptRoot
$script:ModuleVersion = '1.0.0'

# Import all function files
$Public = @(Get-ChildItem -Path "$PSScriptRoot\Core\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\Detection\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\Analysis\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\Response\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\Enterprise\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\Hardening\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\WindowsDefender\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\ThreatHunting\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\Compliance\*.ps1" -ErrorAction SilentlyContinue)

$Public += @(Get-ChildItem -Path "$PSScriptRoot\ActiveDirectory\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\Vulnerability\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\Forensics\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\CloudSecurity\*.ps1" -ErrorAction SilentlyContinue)
$Public += @(Get-ChildItem -Path "$PSScriptRoot\Reporting\*.ps1" -ErrorAction SilentlyContinue)

$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)

# Import all function files
foreach ($import in @($Public + $Private)) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $Public.BaseName

Write-Host "Windows Security Audit Module v$script:ModuleVersion loaded successfully" -ForegroundColor Green