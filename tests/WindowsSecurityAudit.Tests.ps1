#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester 5 structural tests for the WindowsSecurityAudit module.
.DESCRIPTION
    Cross-platform tests (run on any OS with Pester 5+):

    * The module imports and exports exactly one function per .ps1 file found
      in the category folders dot-sourced by WindowsSecurityAudit.psm1
      (the expected count is computed from the files on disk, not hardcoded).
    * Every exported function ships comment-based help with .SYNOPSIS and at
      least one .EXAMPLE (verified through Get-Help).
    * Every .ps1 file in the repository parses without errors.
    * No function file assigns to the automatic variables $PID or $Host.
    * No file invokes Invoke-Expression (or the IEX alias).

    The module targets Windows PowerShell 5.1+, so only APIs available in
    5.1 are used here (no null-coalescing/ternary operators, no ForEach-Object -Parallel).
#>

BeforeDiscovery {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psm1"

    # Category folders dot-sourced by WindowsSecurityAudit.psm1 (kept in sync with the psm1)
    $script:CategoryFolders = @(
        'Core', 'Detection', 'Analysis', 'Response', 'Enterprise', 'Hardening',
        'WindowsDefender', 'ThreatHunting', 'Compliance', 'ActiveDirectory',
        'Vulnerability', 'Forensics', 'CloudSecurity', 'Reporting'
    )

    # One exported function is expected per .ps1 file in these folders
    $script:FunctionFiles = @(
        foreach ($folder in $script:CategoryFolders) {
            $folderPath = Join-Path -Path $script:ModuleRoot -ChildPath $folder
            if (Test-Path -Path $folderPath) {
                Get-ChildItem -Path $folderPath -Filter '*.ps1' -File
            }
        }
    )

    # Structural checks (parse / Invoke-Expression) cover every .ps1 file in the repo
    $script:AllScriptFiles = @(
        Get-ChildItem -Path $script:ModuleRoot -Filter '*.ps1' -Recurse -File |
            Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }
    )
}

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psm1"

    $script:CategoryFolders = @(
        'Core', 'Detection', 'Analysis', 'Response', 'Enterprise', 'Hardening',
        'WindowsDefender', 'ThreatHunting', 'Compliance', 'ActiveDirectory',
        'Vulnerability', 'Forensics', 'CloudSecurity', 'Reporting'
    )

    $script:FunctionFiles = @(
        foreach ($folder in $script:CategoryFolders) {
            $folderPath = Join-Path -Path $script:ModuleRoot -ChildPath $folder
            if (Test-Path -Path $folderPath) {
                Get-ChildItem -Path $folderPath -Filter '*.ps1' -File
            }
        }
    )

    Import-Module -Name $script:ModulePath -Force -DisableNameChecking
    $script:ExportedFunctions = @(Get-Command -Module $script:ModuleName -CommandType Function)

    function Get-ScriptFileAst {
        param([Parameter(Mandatory)][string]$Path)
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
        [PSCustomObject]@{ Ast = $ast; Errors = @($parseErrors) }
    }
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'Module import and exported functions' {
    It 'imports without throwing' {
        { Import-Module -Name $script:ModulePath -Force -DisableNameChecking -ErrorAction Stop } |
            Should -Not -Throw
    }

    It 'exports one function per .ps1 file in the category folders' {
        # Expected count is derived from the files on disk, never hardcoded
        $script:ExportedFunctions.Count | Should -Be $script:FunctionFiles.Count
    }

    It 'exports <Name>' -ForEach $script:FunctionFiles {
        @($script:ExportedFunctions).Name | Should -Contain $_.BaseName
    }
}

Describe 'Comment-based help' {
    It '<Name> has .SYNOPSIS and at least one .EXAMPLE' -ForEach $script:FunctionFiles {
        $help = Get-Help -Name $_.BaseName -Full

        # Without comment-based help Get-Help falls back to an auto-generated
        # syntax line ("<Name> [[-Param] ...]") as the synopsis
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -Match ('^' + [regex]::Escape($_.BaseName) + '\s*\[')

        $examples = @($help.Examples.Example | Where-Object { $null -ne $_ })
        $examples.Count | Should -BeGreaterOrEqual 1
    }
}

Describe 'Script parsing' {
    It '<Name> parses without errors' -ForEach $script:AllScriptFiles {
        $result = Get-ScriptFileAst -Path $_.FullName
        $messages = @($result.Errors | ForEach-Object { $_.Message }) -join '; '
        $result.Errors.Count | Should -Be 0 -Because $messages
    }
}

Describe 'Static safety checks' {
    It '<Name> does not assign to $PID or $Host' -ForEach $script:FunctionFiles {
        $result = Get-ScriptFileAst -Path $_.FullName
        $assignments = @($result.Ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst]
        }, $true))

        $badAssignments = @($assignments | Where-Object {
            $left = $_.Left
            $left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $left.VariablePath.UserPath -in @('PID', 'Host')
        })
        $badAssignments.Count | Should -Be 0
    }

    It '<Name> does not invoke Invoke-Expression or IEX' -ForEach $script:AllScriptFiles {
        $result = Get-ScriptFileAst -Path $_.FullName
        $commands = @($result.Ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true))

        # AST-based check: string literals mentioning IEX (e.g. detection
        # signatures) do not count, only actual command invocations
        $badCommands = @($commands | Where-Object {
            $commandName = $_.GetCommandName()
            $null -ne $commandName -and
            ($commandName -eq 'Invoke-Expression' -or $commandName -eq 'iex')
        })
        $badCommands.Count | Should -Be 0
    }
}
