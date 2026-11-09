function Invoke-WsaRemoteFunctionSet {
    <#
    .SYNOPSIS
        Runs a fixed curated WindowsSecurityAudit function set on the local server.
    .DESCRIPTION
        Provides a narrow server-side entry point for a preinstalled JEA endpoint.
        FunctionSet selects one of three fixed function lists. The wrapper accepts
        no function names, script blocks, module paths, or output paths, and returns
        per-function output and errors together with effective language diagnostics.
    .PARAMETER FunctionSet
        Curated set to invoke: Quick, Standard, or Deep.
    .EXAMPLE
        Invoke-WsaRemoteFunctionSet -FunctionSet Standard
        Runs the Standard curated function set with default parameters.
    .OUTPUTS
        PSCustomObject with Results, Errors, FunctionSet, EffectiveLanguageMode,
        and DynamicCompilationExpected properties.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Quick', 'Standard', 'Deep')]
        [string]$FunctionSet
    )

    $quickFunctions = @('Get-SecurityBaseline', 'Get-DefenderStatus')
    $standardFunctions = @($quickFunctions) + @('Find-SuspiciousProcesses', 'Find-PersistenceMechanisms', 'Get-SystemInfo')
    $deepFunctions = @($standardFunctions) + @('Get-CredentialAccessEvents', 'Find-DefenseEvasion', 'Find-LateralMovement', 'Get-VulnerabilityAssessment')

    $functionNames = @()
    switch ($FunctionSet) {
        'Quick' { $functionNames = $quickFunctions }
        'Standard' { $functionNames = $standardFunctions }
        'Deep' { $functionNames = $deepFunctions }
    }

    $runOutput = New-Object PSObject -Property ([ordered]@{
        Results = [ordered]@{}
        Errors = @()
        FunctionSet = $FunctionSet
        EffectiveLanguageMode = Get-WsaEffectiveLanguageMode
        DynamicCompilationExpected = Test-WsaDynamicCompilationExpected
    })

    foreach ($functionName in $functionNames) {
        try {
            $runOutput.Results[$functionName] = & $functionName
        }
        catch {
            $runOutput.Errors += ('{0}: {1}' -f $functionName, $_.Exception.Message)
        }
    }

    return $runOutput
}
