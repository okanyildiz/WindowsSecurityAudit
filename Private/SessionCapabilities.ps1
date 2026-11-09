function Get-WsaEffectiveLanguageMode {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        return [string]$ExecutionContext.SessionState.LanguageMode
    }
    catch {
        return 'Unavailable'
    }
}

function Test-WsaDynamicCompilationExpected {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return ((Get-WsaEffectiveLanguageMode) -eq 'FullLanguage')
}
