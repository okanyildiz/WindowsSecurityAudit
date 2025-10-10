# Test script to load and test the module
$ErrorActionPreference = 'Stop'

try {
    # Remove module if already loaded
    if (Get-Module -Name WindowsSecurityAudit) {
        Remove-Module WindowsSecurityAudit -Force
    }
    
    # Import the module
    Import-Module "$PSScriptRoot\WindowsSecurityAudit.psd1" -Force
    
    Write-Host "`nModule loaded successfully!" -ForegroundColor Green
    Write-Host "`nAvailable functions:" -ForegroundColor Cyan
    Get-Command -Module WindowsSecurityAudit | Format-Table -Property Name, CommandType
    
    # Test a function
    Write-Host "`nTesting Get-SecurityBaseline..." -ForegroundColor Yellow
    $baseline = Get-SecurityBaseline
    $baseline | Format-List
    
} catch {
    Write-Error "Failed to load module: $_"
}