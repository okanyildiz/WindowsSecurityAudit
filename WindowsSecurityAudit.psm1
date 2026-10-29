<#
.SYNOPSIS
    Windows Security Audit Module - Main module file
.DESCRIPTION
    Comprehensive Windows security audit toolkit for threat detection and incident response
.VERSION
    1.6.1 (keep in sync with WindowsSecurityAudit.psd1 ModuleVersion)
.AUTHOR
    Okan YILDIZ (keep in sync with WindowsSecurityAudit.psd1 Author)
#>

# Set strict mode
Set-StrictMode -Version Latest

# Module variables
# NOTE: keep ModuleVersion in sync with the ModuleVersion field in WindowsSecurityAudit.psd1
$script:ModuleRoot = $PSScriptRoot
$script:ModuleVersion = '1.6.1'

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

# Import all function files, tracking failures so a broken file does not
# silently export a missing function
$script:FailedImports = [System.Collections.Generic.List[object]]::new()
$script:LoadedPublic = [System.Collections.Generic.List[object]]::new()
foreach ($import in @($Public + $Private)) {
    try {
        . $import.FullName
        if ($Public -contains $import) {
            $script:LoadedPublic.Add($import)
        }
    }
    catch {
        Write-Error "Failed to import function $($import.FullName): $_"
        $script:FailedImports.Add($import)
    }
}

# Export only the public functions that loaded successfully
# Backward-compatible alias for the pre-1.6.2 name. A hyphenated FUNCTION name
# triggers the 'restricted characters' import warning; an alias does not.
$aliasesToExport = @()
if (@($script:LoadedPublic.BaseName) -contains 'Test-PciDssCompliance') {
    Set-Alias -Name 'Test-PCI-DSS' -Value 'Test-PciDssCompliance' -Scope Script
    $aliasesToExport += 'Test-PCI-DSS'
}
Export-ModuleMember -Function $script:LoadedPublic.BaseName -Alias $aliasesToExport

if ($script:FailedImports.Count -gt 0) {
    $failedNames = $script:FailedImports.FullName -join ', '
    Write-Warning ("Windows Security Audit Module v$script:ModuleVersion loaded with {0} of {1} functions. Failed files: {2}" -f
        $script:LoadedPublic.Count, $Public.Count, $failedNames)
}
else {
    Write-Verbose "Windows Security Audit Module v$script:ModuleVersion loaded successfully ($($script:LoadedPublic.Count) functions)"
}