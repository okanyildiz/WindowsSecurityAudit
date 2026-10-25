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

Describe 'Threat Intelligence and CVE Integration' {
    # Get-NVDCveData export and its .SYNOPSIS/.EXAMPLE help are already covered
    # dynamically by the data-driven Describes above (they iterate every .ps1
    # file on disk), so only the gaps are tested here.
    # -ForEach data must exist at discovery time, so relative paths are used
    # here and resolved against $script:ModuleRoot (set in BeforeAll) at runtime
    Context 'API key handling' {
        It '<_> never interpolates an API key value into Write-Host or Write-Verbose output' -ForEach @(
            'Vulnerability/Get-NVDCveData.ps1'
            'ThreatHunting/Get-ThreatIntelligence.ps1'
        ) {
            $Path = Join-Path -Path $script:ModuleRoot -ChildPath $_
            $result = Get-ScriptFileAst -Path $Path
            $loggingCommands = @($result.Ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true) | Where-Object {
                $commandName = $_.GetCommandName()
                $commandName -eq 'Write-Host' -or $commandName -eq 'Write-Verbose'
            })

            # A direct "$variable" interpolation shows up as a VariableExpressionAst
            # in the string's NestedExpressions. Values referenced only inside a
            # $(...) subexpression (e.g. "$(if($ApiKey){'Provided'}else{...})")
            # are SubExpressionAst nodes and never emit the key itself
            $leaks = @()
            foreach ($command in $loggingCommands) {
                $strings = @($command.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    $node.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::DoubleQuoted
                }, $true))
                foreach ($string in $strings) {
                    $leaks += @($string.NestedExpressions | Where-Object {
                        $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and
                        $_.VariablePath.UserPath -match '(?i)(apikey|secret|token|^key$|api_key)'
                    })
                }
            }
            $leaks.Count | Should -Be 0 -Because 'API keys must only travel in request headers, never in log output'
        }

        It '<_> enforces TLS 1.2 before making network calls' -ForEach @(
            'Vulnerability/Get-NVDCveData.ps1'
            'ThreatHunting/Get-ThreatIntelligence.ps1'
        ) {
            $Path = Join-Path -Path $script:ModuleRoot -ChildPath $_
            $content = Get-Content -Path $Path -Raw
            $content | Should -Match 'Tls12'
        }

        It '<_> contains no hardcoded API keys or secrets' -ForEach @(
            'Vulnerability/Get-NVDCveData.ps1'
            'ThreatHunting/Get-ThreatIntelligence.ps1'
        ) {
            $Path = Join-Path -Path $script:ModuleRoot -ChildPath $_
            $result = Get-ScriptFileAst -Path $Path
            $assignments = @($result.Ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst]
            }, $true))

            $hardcoded = @($assignments | Where-Object {
                $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $_.Left.VariablePath.UserPath -match '(?i)(apikey|secret|token|password|api_key)' -and
                $_.Right -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                -not [string]::IsNullOrWhiteSpace($_.Right.Value)
            })
            $hardcoded.Count | Should -Be 0 -Because 'credentials must come from parameters, never from string literals'
        }
    }

    Context 'Comment-based help for new parameters' {
        It 'Get-ThreatIntelligence help documents the live feed parameters' {
            $help = Get-Help -Name 'Get-ThreatIntelligence' -Full
            $parameterNames = @($help.parameters.parameter | ForEach-Object { $_.Name })
            foreach ($expected in 'UpdateFeeds', 'FeedCachePath', 'FeedMaxAgeHours', 'MaxFeedEntries', 'AbuseIPDBApiKey') {
                $parameterNames | Should -Contain $expected
            }
        }

        It 'Get-VulnerabilityAssessment help documents the NVD CVE parameters' {
            $help = Get-Help -Name 'Get-VulnerabilityAssessment' -Full
            $parameterNames = @($help.parameters.parameter | ForEach-Object { $_.Name })
            foreach ($expected in 'CheckCVEs', 'NVDApiKey', 'MaxCVEChecks') {
                $parameterNames | Should -Contain $expected
            }
        }
    }

    Context 'Offline feed behavior' {
        BeforeAll {
            $script:ThreatIntelPath = Join-Path -Path $script:ModuleRoot -ChildPath 'ThreatHunting/Get-ThreatIntelligence.ps1'
            $script:ThreatIntelAst = (Get-ScriptFileAst -Path $script:ThreatIntelPath).Ast
            $script:FeedGate = @($script:ThreatIntelAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.IfStatementAst]
            }, $true) | Where-Object {
                $conditionText = $_.Clauses[0].Item1.Extent.Text
                $conditionText -match '\$UpdateFeeds' -and
                $conditionText -match 'Test-Path\s+\$FeedCachePath'
            })
        }

        It 'gates live feed processing on -UpdateFeeds or an existing -FeedCachePath' {
            $script:FeedGate.Count | Should -BeGreaterOrEqual 1 -Because 'feed processing must be skipped entirely when -UpdateFeeds is absent and the cache directory does not exist'
        }

        It 'keeps feed downloads inside that gate (no network calls when offline)' {
            $script:FeedGate.Count | Should -BeGreaterOrEqual 1
            $downloads = @($script:ThreatIntelAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true) | Where-Object {
                $_.GetCommandName() -eq 'Invoke-WebRequest'
            })
            $downloads.Count | Should -BeGreaterOrEqual 1 -Because 'the live feed feature is expected to download feed files'
            foreach ($download in $downloads) {
                $insideGate = @($script:FeedGate | Where-Object {
                    $download.Extent.StartOffset -gt $_.Extent.StartOffset -and
                    $download.Extent.EndOffset -lt $_.Extent.EndOffset
                })
                $insideGate.Count | Should -BeGreaterOrEqual 1 -Because 'Invoke-WebRequest must only run when -UpdateFeeds is set or a feed cache exists'
            }
        }
    }
}

Describe 'v1.3 Features' {
    Context 'Comment-based help for new parameters' {
        It 'Get-VulnerabilityAssessment help documents ExactCVEMatch' {
            $help = Get-Help -Name 'Get-VulnerabilityAssessment' -Full
            $parameterNames = @($help.parameters.parameter | ForEach-Object { $_.Name })
            $parameterNames | Should -Contain 'ExactCVEMatch'
        }

        It 'Get-ThreatIntelligence help documents the MISP/TAXII/STIX parameters' {
            $help = Get-Help -Name 'Get-ThreatIntelligence' -Full
            $parameterNames = @($help.parameters.parameter | ForEach-Object { $_.Name })
            foreach ($expected in 'MISPUrl', 'MISPApiKey', 'TaxiiServerUrl', 'TaxiiCollection', 'StixFilePath') {
                $parameterNames | Should -Contain $expected
            }
        }

        It 'Resolve-CpeName help documents UseOnlineLookup and ApiKey' {
            $help = Get-Help -Name 'Resolve-CpeName' -Full
            $parameterNames = @($help.parameters.parameter | ForEach-Object { $_.Name })
            foreach ($expected in 'UseOnlineLookup', 'ApiKey') {
                $parameterNames | Should -Contain $expected
            }
        }

        It 'Invoke-SecurityRemediation help documents the remediation parameters' {
            $help = Get-Help -Name 'Invoke-SecurityRemediation' -Full
            $parameterNames = @($help.parameters.parameter | ForEach-Object { $_.Name })
            foreach ($expected in 'MaxSeverity', 'GenerateRollback', 'AssessmentPath', 'InputObject') {
                $parameterNames | Should -Contain $expected
            }
        }
    }

    Context 'Secret handling' {
        It '<_> never interpolates an API key value into Write-Host or Write-Verbose output' -ForEach @(
            'Vulnerability/Resolve-CpeName.ps1'
            'ThreatHunting/Get-ThreatIntelligence.ps1'
        ) {
            $Path = Join-Path -Path $script:ModuleRoot -ChildPath $_
            $result = Get-ScriptFileAst -Path $Path
            $loggingCommands = @($result.Ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true) | Where-Object {
                $commandName = $_.GetCommandName()
                $commandName -eq 'Write-Host' -or $commandName -eq 'Write-Verbose'
            })

            # A direct "$variable" interpolation shows up as a VariableExpressionAst
            # in the string's NestedExpressions. Values referenced only inside a
            # $(...) subexpression (e.g. "$(if($ApiKey){'Provided'}else{...})")
            # are SubExpressionAst nodes and never emit the key itself
            $leaks = @()
            foreach ($command in $loggingCommands) {
                $strings = @($command.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    $node.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::DoubleQuoted
                }, $true))
                foreach ($string in $strings) {
                    $leaks += @($string.NestedExpressions | Where-Object {
                        $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and
                        $_.VariablePath.UserPath -match '(?i)(apikey|secret|token|^key$|api_key)'
                    })
                }
            }
            $leaks.Count | Should -Be 0 -Because 'API keys must only travel in request headers, never in log output'
        }

        It 'Get-ThreatIntelligence types -TaxiiPassword as [SecureString]' {
            $Path = Join-Path -Path $script:ModuleRoot -ChildPath 'ThreatHunting/Get-ThreatIntelligence.ps1'
            $result = Get-ScriptFileAst -Path $Path
            $functionAst = $result.Ast.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Get-ThreatIntelligence'
            }, $true)
            $parameterAst = @($functionAst.Body.ParamBlock.Parameters | Where-Object {
                $_.Name.VariablePath.UserPath -eq 'TaxiiPassword'
            })
            $parameterAst.Count | Should -Be 1
            $parameterAst[0].StaticType.Name | Should -Be 'SecureString' -Because 'passwords must never be accepted as plain strings'
        }
    }

    Context 'Invoke-SecurityRemediation safety' {
        BeforeAll {
            $script:RemediationPath = Join-Path -Path $script:ModuleRoot -ChildPath 'Hardening/Invoke-SecurityRemediation.ps1'
            $script:RemediationContent = Get-Content -Path $script:RemediationPath -Raw
            $script:RemediationAst = (Get-ScriptFileAst -Path $script:RemediationPath).Ast
        }

        It 'declares SupportsShouldProcess with ConfirmImpact High in its CmdletBinding' {
            $functionAst = $script:RemediationAst.Find({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Invoke-SecurityRemediation'
            }, $true)
            $cmdletBinding = @($functionAst.Body.ParamBlock.Attributes | Where-Object {
                $_.TypeName.Name -eq 'CmdletBinding'
            })
            $cmdletBinding.Count | Should -Be 1

            $namedArguments = $cmdletBinding[0].NamedArguments

            $shouldProcess = @($namedArguments | Where-Object { $_.ArgumentName -eq 'SupportsShouldProcess' })
            $shouldProcess.Count | Should -Be 1
            # A bare 'SupportsShouldProcess' has ExpressionOmitted = $true (defaults to $true)
            $shouldProcessEnabled = $shouldProcess[0].ExpressionOmitted -or $shouldProcess[0].Argument.SafeGetValue() -eq $true
            $shouldProcessEnabled | Should -BeTrue -Because 'remediation must support -WhatIf and -Confirm'

            $confirmImpact = @($namedArguments | Where-Object { $_.ArgumentName -eq 'ConfirmImpact' })
            $confirmImpact.Count | Should -Be 1
            $confirmImpact[0].Argument.SafeGetValue() | Should -Be 'High'
        }

        It 'routes state-changing calls through ShouldProcess' {
            $occurrences = [regex]::Matches($script:RemediationContent, [regex]::Escape('$PSCmdlet.ShouldProcess('))
            $occurrences.Count | Should -BeGreaterOrEqual 2 -Because 'both remediation actions and rollback script writes must be gated behind ShouldProcess'
        }

        It 'routes unmatched findings to ManualReview' {
            $script:RemediationContent | Should -Match 'ManualReview'
        }
    }
}
