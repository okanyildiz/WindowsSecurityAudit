#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Tests live-cloud query mapping with fully mocked Graph and Azure commands.
.DESCRIPTION
    No test in this file performs a network request. Module-scope command stubs
    and mocks make the Graph, MFA, and Azure Resource Manager paths deterministic
    even on a workstation that has the complete Graph and Az modules installed.
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleName = 'WindowsSecurityAudit'
    $script:ModulePath = Join-Path -Path $script:ModuleRoot -ChildPath "$script:ModuleName.psm1"

    Import-Module -Name $script:ModulePath -Force

    InModuleScope -ModuleName $script:ModuleName {
        Set-Item -Path Function:\script:Get-MgContext -Value { param($ErrorAction) }
        Set-Item -Path Function:\script:Get-MgSecuritySecureScore -Value { param($Top, $ErrorAction) }
        Set-Item -Path Function:\script:Invoke-MgGraphRequest -Value { param($Method, $Uri, $Body, $ContentType, $ErrorAction) }
        Set-Item -Path Function:\script:Get-MgOrganization -Value { param($ErrorAction) }
        Set-Item -Path Function:\script:Get-MgIdentityConditionalAccessPolicy -Value { param($All, $ErrorAction) }
        Set-Item -Path Function:\script:Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -Value { param($ErrorAction) }
        Set-Item -Path Function:\script:Get-AzContext -Value { param($ErrorAction) }
        Set-Item -Path Function:\script:Invoke-AzRestMethod -Value { param($Method, $Path, $Payload, $ErrorAction) }
    }
}

AfterAll {
    Remove-Module -Name $script:ModuleName -Force -ErrorAction SilentlyContinue
}

Describe 'Cloud real query behavior' {
BeforeEach {
    Mock -ModuleName $script:ModuleName Get-MgContext {
        [PSCustomObject]@{ TenantId = 'tenant-test' }
    }
    Mock -ModuleName $script:ModuleName Get-MgSecuritySecureScore {
        param($Top)
        throw "Unexpected mocked Secure Score request: Top=$Top"
    }
    Mock -ModuleName $script:ModuleName Invoke-MgGraphRequest {
        param($Method, $Uri)
        throw "Unexpected mocked Graph request: $Method $Uri"
    }
    Mock -ModuleName $script:ModuleName Get-MgOrganization {
        [PSCustomObject]@{ DisplayName = 'Test Tenant' }
    }
    Mock -ModuleName $script:ModuleName Get-MgIdentityConditionalAccessPolicy {
        @([PSCustomObject]@{ State = 'enabled' })
    }
    Mock -ModuleName $script:ModuleName Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy {
        [PSCustomObject]@{ IsEnabled = $true }
    }
    Mock -ModuleName $script:ModuleName Get-AzContext { $null }
    Mock -ModuleName $script:ModuleName Invoke-AzRestMethod {
        param($Method, $Path)
        throw "Unexpected mocked Azure request: $Method $Path"
    }
}

Describe 'Get-CloudComplianceStatus real query mapping' {
    It 'maps the latest Secure Score and exposes the additive output contract' {
        Mock -ModuleName $script:ModuleName Get-MgSecuritySecureScore {
            [PSCustomObject]@{ CurrentScore = 42.5; MaxScore = 85.0 }
        }

        $script:result = $null
        { $script:result = Get-CloudComplianceStatus -Framework CIS -WarningAction SilentlyContinue 6>$null } |
            Should -Not -Throw

        $script:result.SecureScore | Should -Be 42.5
        $script:result.SecureScoreMax | Should -Be 85.0
        $script:result.SecureScorePercentage | Should -Be 50.0
        $script:result.SecureScoreStatus | Should -Be 'Evaluated'
        $script:result.EvaluatedCount | Should -Be 1
        $script:result.Source | Should -Be 'Graph'
        $script:result.ComplianceScore | Should -BeNullOrEmpty
        @($script:result.Controls | Where-Object Status -ne 'NotEvaluated').Count | Should -Be 0

        foreach ($propertyName in @(
            'SecureScore', 'SecureScoreMax', 'PolicyCompliant',
            'PolicyNonCompliant', 'EvaluatedCount', 'Source'
        )) {
            $script:result.PSObject.Properties.Name | Should -Contain $propertyName
        }

        Should -Invoke Get-MgSecuritySecureScore -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $Top -eq 1
        }
    }

    It 'counts latest policy states by assignment and preserves other states separately' {
        Mock -ModuleName $script:ModuleName Get-MgSecuritySecureScore {
            [PSCustomObject]@{ CurrentScore = 10; MaxScore = 20 }
        }
        Mock -ModuleName $script:ModuleName Invoke-AzRestMethod {
            $payload = @{
                value = @(
                    [PSCustomObject]@{ policyAssignmentId = '/assignments/A'; complianceState = 'Compliant' },
                    [PSCustomObject]@{ policyAssignmentId = '/assignments/A'; complianceState = 'NonCompliant' },
                    [PSCustomObject]@{ policyAssignmentId = '/assignments/A'; complianceState = 'Compliant' },
                    [PSCustomObject]@{ policyAssignmentId = '/assignments/B'; complianceState = 'NonCompliant' },
                    [PSCustomObject]@{ policyAssignmentId = '/assignments/B'; complianceState = 'Exempt' }
                )
            }
            [PSCustomObject]@{ Content = ($payload | ConvertTo-Json -Depth 5 -Compress) }
        }

        $script:result = Get-CloudComplianceStatus -SubscriptionId 'subscription-test' -WarningAction SilentlyContinue 6>$null

        $script:result.PolicyCompliant | Should -Be 2
        $script:result.PolicyNonCompliant | Should -Be 2
        $script:result.PolicyOther | Should -Be 1
        $script:result.PolicyComplianceStatus | Should -Be 'Evaluated'
        $script:result.PolicyTransport | Should -Be 'Invoke-AzRestMethod'
        $script:result.EvaluatedCount | Should -Be 2
        $script:result.PolicyAssignments.Count | Should -Be 2

        $assignmentA = @($script:result.PolicyAssignments | Where-Object PolicyAssignmentId -eq '/assignments/A')[0]
        $assignmentB = @($script:result.PolicyAssignments | Where-Object PolicyAssignmentId -eq '/assignments/B')[0]
        $assignmentA.Compliant | Should -Be 2
        $assignmentA.NonCompliant | Should -Be 1
        $assignmentA.Other | Should -Be 0
        $assignmentB.Compliant | Should -Be 0
        $assignmentB.NonCompliant | Should -Be 1
        $assignmentB.Other | Should -Be 1

        Should -Invoke Invoke-AzRestMethod -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'POST' -and
            $Path -like '/subscriptions/subscription-test/providers/Microsoft.PolicyInsights/*'
        }
    }

    It 'returns NotEvaluated with connect instructions and makes no requests without a Graph context' {
        Mock -ModuleName $script:ModuleName Get-MgContext { $null }

        $script:result = $null
        { $script:result = Get-CloudComplianceStatus -WarningAction SilentlyContinue 6>$null } |
            Should -Not -Throw

        $script:result.SecureScoreStatus | Should -Be 'NotEvaluated'
        $script:result.PolicyComplianceStatus | Should -Be 'NotEvaluated'
        $script:result.SecureScore | Should -BeNullOrEmpty
        $script:result.SecureScoreMax | Should -BeNullOrEmpty
        $script:result.PolicyCompliant | Should -BeNullOrEmpty
        $script:result.PolicyNonCompliant | Should -BeNullOrEmpty
        $script:result.EvaluatedCount | Should -Be 0
        $script:result.Source | Should -Be 'Graph'
        $script:result.SecureScoreNote | Should -Match 'Connect-MgGraph'
        $script:result.SecureScoreNote | Should -Match 'SecurityEvents.Read.All'
        $script:result.PolicyComplianceNote | Should -Match 'Connect-AzAccount'
        $script:result.PolicyComplianceNote | Should -Match 'Microsoft.PolicyInsights/policyStates/read'
        @($script:result.Controls | Where-Object { $_.Note -notmatch 'Connect-MgGraph' }).Count | Should -Be 0
        Should -Invoke Invoke-MgGraphRequest -ModuleName $script:ModuleName -Times 0 -Exactly
        Should -Invoke Get-MgSecuritySecureScore -ModuleName $script:ModuleName -Times 0 -Exactly
        Should -Invoke Invoke-AzRestMethod -ModuleName $script:ModuleName -Times 0 -Exactly
    }

    It 'degrades to NotEvaluated when the Secure Score endpoint fails' {
        Mock -ModuleName $script:ModuleName Get-MgSecuritySecureScore {
            throw 'Injected Secure Score denial.'
        }

        $script:result = $null
        { $script:result = Get-CloudComplianceStatus -WarningAction SilentlyContinue 6>$null } |
            Should -Not -Throw

        $script:result.SecureScoreStatus | Should -Be 'NotEvaluated'
        $script:result.SecureScore | Should -BeNullOrEmpty
        $script:result.SecureScoreMax | Should -BeNullOrEmpty
        $script:result.SecureScoreNote | Should -Match 'Injected Secure Score denial'
        $script:result.SecureScoreNote | Should -Match 'SecurityEvents.Read.All'
        $script:result.EvaluatedCount | Should -Be 0
    }

    It 'keeps Secure Score data when the Policy Insights endpoint fails' {
        Mock -ModuleName $script:ModuleName Get-MgSecuritySecureScore {
            [PSCustomObject]@{ CurrentScore = 10; MaxScore = 20 }
        }
        Mock -ModuleName $script:ModuleName Invoke-AzRestMethod {
            throw 'Injected Policy Insights denial.'
        }

        $script:result = $null
        { $script:result = Get-CloudComplianceStatus -SubscriptionId 'subscription-test' -WarningAction SilentlyContinue 6>$null } |
            Should -Not -Throw

        $script:result.SecureScoreStatus | Should -Be 'Evaluated'
        $script:result.SecureScore | Should -Be 10
        $script:result.PolicyComplianceStatus | Should -Be 'NotEvaluated'
        $script:result.PolicyCompliant | Should -BeNullOrEmpty
        $script:result.PolicyNonCompliant | Should -BeNullOrEmpty
        $script:result.PolicyComplianceNote | Should -Match 'Injected Policy Insights denial'
        $script:result.PolicyComplianceNote | Should -Match 'management.azure.com/user_impersonation'
        $script:result.EvaluatedCount | Should -Be 1
    }
}

Describe 'Test-M365SecurityPosture real MFA registration query' {
    It 'calculates MFA percentage across all Graph pages and scores evaluated checks only' {
        $nextUri = 'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?$skiptoken=page2'
        Mock -ModuleName $script:ModuleName Invoke-MgGraphRequest {
            param($Method, $Uri)
            if ($Uri -eq '/beta/reports/authenticationMethods/userRegistrationDetails') {
                return @{
                    value = @(
                        [PSCustomObject]@{ id = 'user-1'; isMfaRegistered = $true; isMfaCapable = $true },
                        [PSCustomObject]@{ id = 'user-2'; isMfaRegistered = $false; isMfaCapable = $true }
                    )
                    '@odata.nextLink' = $nextUri
                }
            }
            if ($Uri -eq $nextUri) {
                return @{
                    value = @([PSCustomObject]@{ id = 'user-3'; isMfaRegistered = $true; isMfaCapable = $false })
                }
            }
            throw "Unexpected mocked Graph request: $Method $Uri"
        }

        $script:result = $null
        { $script:result = Test-M365SecurityPosture -CheckConditionalAccess -WarningAction SilentlyContinue 6>$null } |
            Should -Not -Throw

        $script:result.MfaRegistrationPercentage | Should -Be 66.7
        $script:result.MfaRegisteredUsers | Should -Be 2
        $script:result.MfaCapableUsers | Should -Be 2
        $script:result.MfaUsersReported | Should -Be 3
        $script:result.MfaStatus | Should -Be 'Evaluated'

        $mfaFinding = @($script:result.SecurityFindings | Where-Object Name -eq 'Org-wide MFA Registration')[0]
        $mfaFinding.Status | Should -Be 'Fail'
        $mfaFinding.Actual | Should -Match '2 of 3'
        $mfaFinding.Actual | Should -Match '66.7%'
        $mfaFinding.Actual | Should -Match 'does not prove MFA is enforced'

        $script:result.EvaluatedCount | Should -Be 3
        $script:result.NotEvaluatedCount | Should -Be 1
        $script:result.OverallScore | Should -Be 66.7
        Should -Invoke Invoke-MgGraphRequest -ModuleName $script:ModuleName -Times 2 -Exactly
        Should -Invoke Invoke-MgGraphRequest -ModuleName $script:ModuleName -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'GET' -and $Uri -eq $nextUri
        }
    }

    It 'returns every check NotEvaluated with connect instructions and no requests when disconnected' {
        Mock -ModuleName $script:ModuleName Get-MgContext { $null }

        $script:result = $null
        { $script:result = Test-M365SecurityPosture -CheckConditionalAccess -WarningAction SilentlyContinue 6>$null } |
            Should -Not -Throw

        $script:result.OverallStatus | Should -Be 'NotEvaluated'
        $script:result.OverallScore | Should -BeNullOrEmpty
        $script:result.EvaluatedCount | Should -Be 0
        $script:result.MfaStatus | Should -Be 'NotEvaluated'
        $script:result.MfaRegistrationPercentage | Should -BeNullOrEmpty
        $script:result.MfaNote | Should -Match 'Connect-MgGraph'
        $script:result.MfaNote | Should -Match 'AuditLog.Read.All'
        @($script:result.SecurityFindings | Where-Object Status -ne 'NotEvaluated').Count | Should -Be 0
        @($script:result.SecurityFindings | Where-Object { $_.Actual -notmatch 'Connect-MgGraph' }).Count | Should -Be 0
        Should -Invoke Invoke-MgGraphRequest -ModuleName $script:ModuleName -Times 0 -Exactly
    }

    It 'returns MFA NotEvaluated without crashing or adding it to the score when the endpoint fails' {
        Mock -ModuleName $script:ModuleName Invoke-MgGraphRequest {
            throw 'Injected MFA report denial.'
        }

        $script:result = $null
        { $script:result = Test-M365SecurityPosture -CheckConditionalAccess -WarningAction SilentlyContinue 6>$null } |
            Should -Not -Throw

        $script:result.MfaStatus | Should -Be 'NotEvaluated'
        $script:result.MfaRegistrationPercentage | Should -BeNullOrEmpty
        $script:result.MfaNote | Should -Match 'Injected MFA report denial'
        $script:result.MfaNote | Should -Match 'AuditLog.Read.All'
        $mfaFinding = @($script:result.SecurityFindings | Where-Object Name -eq 'Org-wide MFA Registration')[0]
        $mfaFinding.Status | Should -Be 'NotEvaluated'
        $script:result.EvaluatedCount | Should -Be 2
        $script:result.OverallScore | Should -Be 100
    }

    It 'does not substitute isMfaCapable when isMfaRegistered is missing' {
        Mock -ModuleName $script:ModuleName Invoke-MgGraphRequest {
            return @{
                value = @([PSCustomObject]@{ id = 'user-1'; isMfaCapable = $true })
            }
        }

        $script:result = $null
        { $script:result = Test-M365SecurityPosture -CheckConditionalAccess -WarningAction SilentlyContinue 6>$null } |
            Should -Not -Throw

        $script:result.MfaStatus | Should -Be 'NotEvaluated'
        $script:result.MfaRegistrationPercentage | Should -BeNullOrEmpty
        $script:result.MfaRegisteredUsers | Should -BeNullOrEmpty
        $script:result.MfaCapableUsers | Should -BeNullOrEmpty
        $script:result.MfaNote | Should -Match 'isMfaCapable cannot be used as a substitute'
        $mfaFinding = @($script:result.SecurityFindings | Where-Object Name -eq 'Org-wide MFA Registration')[0]
        $mfaFinding.Status | Should -Be 'NotEvaluated'
    }
}
}
