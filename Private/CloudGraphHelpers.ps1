#requires -Version 5.1

function Get-CloudDataProperty {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $exists = $false
    $value = $null

    if ($null -ne $InputObject) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            foreach ($key in $InputObject.Keys) {
                if ([string]::Equals([string]$key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $exists = $true
                    $value = $InputObject[$key]
                    break
                }
            }
        }
        else {
            $property = $InputObject.PSObject.Properties[$Name]
            if ($null -ne $property) {
                $exists = $true
                $value = $property.Value
            }
        }
    }

    return [PSCustomObject]@{
        Exists = $exists
        Value = $value
    }
}

function Invoke-CloudPolicyInsightsQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )

    $azRestCommand = Get-Command -Name 'Invoke-AzRestMethod' -ErrorAction SilentlyContinue
    $graphRequestCommand = Get-Command -Name 'Invoke-MgGraphRequest' -ErrorAction SilentlyContinue

    if ($null -ne $azRestCommand) {
        $transport = 'Invoke-AzRestMethod'
    }
    elseif ($null -ne $graphRequestCommand) {
        $transport = 'Invoke-MgGraphRequest'
    }
    else {
        throw "No Azure Policy query transport is available. Install Az.Accounts and run Connect-AzAccount. Required Azure Resource Manager scope: https://management.azure.com/user_impersonation; required authorization: Reader or Microsoft.PolicyInsights/policyStates/read on the subscription."
    }

    $escapedSubscriptionId = [System.Uri]::EscapeDataString($SubscriptionId)
    $requestPath = "/subscriptions/$escapedSubscriptionId/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01&`$top=1000"
    $requestUri = "https://management.azure.com$requestPath"
    $states = @()
    $seenRequests = @{}

    while ($true) {
        if ($seenRequests.ContainsKey($requestUri)) {
            throw 'Azure Policy Insights returned a repeated pagination link.'
        }
        $seenRequests[$requestUri] = $true

        if ($transport -eq 'Invoke-AzRestMethod') {
            $azResponse = Invoke-AzRestMethod -Method POST -Path $requestPath -ErrorAction Stop
            $contentProperty = Get-CloudDataProperty -InputObject $azResponse -Name 'Content'
            if ($contentProperty.Exists -and $contentProperty.Value -is [string]) {
                if ([string]::IsNullOrWhiteSpace($contentProperty.Value)) {
                    throw 'Azure Policy Insights returned an empty response body.'
                }
                $page = $contentProperty.Value | ConvertFrom-Json -ErrorAction Stop
            }
            else {
                $page = $azResponse
            }
        }
        else {
            $page = Invoke-MgGraphRequest -Method POST -Uri $requestUri -ErrorAction Stop
        }

        if ($page -is [string]) {
            if ([string]::IsNullOrWhiteSpace($page)) {
                throw 'Azure Policy Insights returned an empty response body.'
            }
            $page = $page | ConvertFrom-Json -ErrorAction Stop
        }

        $valueProperty = Get-CloudDataProperty -InputObject $page -Name 'value'
        if (-not $valueProperty.Exists -or $null -eq $valueProperty.Value) {
            throw "Azure Policy Insights response did not contain a 'value' array."
        }
        $states += @($valueProperty.Value)

        $nextProperty = Get-CloudDataProperty -InputObject $page -Name '@odata.nextLink'
        if (-not $nextProperty.Exists) {
            $nextProperty = Get-CloudDataProperty -InputObject $page -Name 'nextLink'
        }

        $nextLink = [string]$nextProperty.Value
        if ([string]::IsNullOrWhiteSpace($nextLink)) {
            break
        }

        $absoluteUri = $null
        if ([System.Uri]::TryCreate($nextLink, [System.UriKind]::Absolute, [ref]$absoluteUri)) {
            $requestPath = $absoluteUri.PathAndQuery
            $requestUri = $absoluteUri.AbsoluteUri
        }
        elseif ($nextLink.StartsWith('/')) {
            $requestPath = $nextLink
            $requestUri = "https://management.azure.com$nextLink"
        }
        else {
            throw "Azure Policy Insights returned an invalid pagination link: $nextLink"
        }
    }

    return [PSCustomObject]@{
        States = $states
        Transport = $transport
    }
}
