function Get-CredentialAccessEvents {
    <#
    .SYNOPSIS
        Detects runtime credential-access activity from Windows event logs
    .DESCRIPTION
        Analyzes Windows Security (and optionally Sysmon) event logs for credential-access
        techniques: Kerberoasting (RC4 service ticket bursts), anomalous TGT request volumes,
        Kerberos pre-authentication failure spikes (brute force / password spray), a best-effort
        golden-ticket heuristic (Kerberos logons with no matching TGT request in the window),
        and optionally processes with open access handles to lsass.exe (4663 or Sysmon 10).
        Heuristic detections are labeled as such and should be validated manually.
    .PARAMETER Hours
        Number of hours to look back in event logs (default: 24)
    .PARAMETER IncludeLSASSAccess
        Also enumerate processes with open access handles to lsass.exe. Uses Security event
        4663 (requires Object Access auditing with a SACL on lsass.exe) and Sysmon event ID 10
        when the Sysmon Operational log is present
    .EXAMPLE
        Get-CredentialAccessEvents
        Get-CredentialAccessEvents -Hours 48 -IncludeLSASSAccess
    .OUTPUTS
        PSCustomObject with Events, Summary, and Recommendations
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$Hours = 24,

        [Parameter()]
        [switch]$IncludeLSASSAccess
    )

    begin {
        Write-Host "Analyzing credential-access events (last $Hours hours)..." -ForegroundColor Cyan

        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TimeRange = "$Hours hours"
            Events = @()
            Summary = @{
                RC4ServiceTicketRequests = 0
                KerberoastBursts = 0
                TGTAnomalies = 0
                KerberosFailureSpikes = 0
                GoldenTicketHeuristics = 0
                LSASSAccessEvents = 0
                SuspiciousLSASSAccess = 0
            }
            Recommendations = @()
        }

        $startTime = (Get-Date).AddHours(-$Hours)

        # Granted-access masks that are normal for DLL loads / telemetry against lsass.exe
        # (masks containing PROCESS_VM_READ 0x0010 never reach this list - the bit test
        # below classifies them as suspicious first)
        $normalAccessMasks = @('0x1000', '0x1400')
        # PROCESS_VM_READ (0x0010) or broad rights (PROCESS_ALL_ACCESS style) are suspicious
        $suspiciousAccessMasks = @('0x1010', '0x101a', '0x103a', '0x143a', '0x1f0fff', '0x1fffff')

        $getEventValue = {
            param($EventData, [string]$Name)
            if ($null -eq $EventData) { return $null }
            $node = $EventData | Where-Object { $_.Name -eq $Name }
            if ($null -ne $node) { return $node.InnerText }
            return $null
        }
    }

    process {
        # 1. Kerberoasting: RC4-encrypted service ticket requests (Event ID 4769, TicketEncryptionType 0x17)
        $rc4ByAccount = @{}
        try {
            Write-Verbose "Analyzing service ticket requests (4769)..."
            $ticketEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4769
                StartTime = $startTime
            } -ErrorAction SilentlyContinue

            foreach ($event in @($ticketEvents)) {
                if ($null -eq $event) { continue }
                $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                $targetAccount = & $getEventValue $eventData 'TargetUserName'
                $serviceName = & $getEventValue $eventData 'ServiceName'
                $encryptionType = & $getEventValue $eventData 'TicketEncryptionType'
                $sourceIP = & $getEventValue $eventData 'IpAddress'

                if ($encryptionType -ne '0x17') { continue }
                if (-not $targetAccount -or $targetAccount -match '\$$') { continue }
                if (-not $serviceName -or $serviceName -match '\$$' -or $serviceName -eq 'krbtgt') { continue }

                $results.Summary.RC4ServiceTicketRequests++

                if (-not $rc4ByAccount.ContainsKey($targetAccount)) {
                    $rc4ByAccount[$targetAccount] = [PSCustomObject]@{
                        Account = $targetAccount
                        Count = 0
                        Services = @()
                        SourceIPs = @()
                        FirstSeen = $event.TimeCreated
                        LastSeen = $event.TimeCreated
                    }
                }
                $rc4ByAccount[$targetAccount].Count++
                if ($serviceName -and $rc4ByAccount[$targetAccount].Services -notcontains $serviceName) {
                    $rc4ByAccount[$targetAccount].Services += $serviceName
                }
                if ($sourceIP -and $sourceIP -ne '-' -and $rc4ByAccount[$targetAccount].SourceIPs -notcontains $sourceIP) {
                    $rc4ByAccount[$targetAccount].SourceIPs += $sourceIP
                }
                if ($null -ne $event.TimeCreated) {
                    if ($null -eq $rc4ByAccount[$targetAccount].FirstSeen -or $event.TimeCreated -lt $rc4ByAccount[$targetAccount].FirstSeen) { $rc4ByAccount[$targetAccount].FirstSeen = $event.TimeCreated }
                    if ($null -eq $rc4ByAccount[$targetAccount].LastSeen -or $event.TimeCreated -gt $rc4ByAccount[$targetAccount].LastSeen) { $rc4ByAccount[$targetAccount].LastSeen = $event.TimeCreated }
                }
            }

            foreach ($accountName in $rc4ByAccount.Keys) {
                $rc4Info = $rc4ByAccount[$accountName]
                if ($rc4Info.Count -gt 5) {
                    $results.Summary.KerberoastBursts++
                    $results.Events += [PSCustomObject]@{
                        TimeCreated = $rc4Info.LastSeen
                        Category = 'KerberoastBurst'
                        Severity = 'High'
                        Account = $rc4Info.Account
                        Source = ($rc4Info.SourceIPs -join ', ')
                        Details = "$($rc4Info.Count) RC4-encrypted service ticket requests in window for $($rc4Info.Services.Count) distinct service(s): $($rc4Info.Services -join ', ')"
                        DetectionMethod = 'Threshold'
                        Confidence = 'High'
                    }
                }
                else {
                    $results.Events += [PSCustomObject]@{
                        TimeCreated = $rc4Info.LastSeen
                        Category = 'RC4ServiceTicketRequest'
                        Severity = 'Low'
                        Account = $rc4Info.Account
                        Source = ($rc4Info.SourceIPs -join ', ')
                        Details = "$($rc4Info.Count) RC4-encrypted service ticket request(s) for: $($rc4Info.Services -join ', ') (informational - may be legacy clients)"
                        DetectionMethod = 'Signature'
                        Confidence = 'Low'
                    }
                }
            }
        }
        catch {
            Write-Warning "Service ticket (4769) analysis not available: $_"
            $results.Recommendations += 'Service ticket auditing (4769) was not available - verify the Security log is accessible and Kerberos service ticket auditing is enabled'
        }

        # 2. Anomalous TGT request volumes (Event ID 4768) - per-account counts also feed the golden-ticket heuristic
        $tgtCountByAccount = @{}
        try {
            Write-Verbose "Analyzing TGT requests (4768)..."
            $tgtEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4768
                StartTime = $startTime
            } -ErrorAction SilentlyContinue

            foreach ($event in @($tgtEvents)) {
                if ($null -eq $event) { continue }
                $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                $targetAccount = & $getEventValue $eventData 'TargetUserName'
                if (-not $targetAccount -or $targetAccount -match '\$$') { continue }

                if (-not $tgtCountByAccount.ContainsKey($targetAccount)) {
                    $tgtCountByAccount[$targetAccount] = [PSCustomObject]@{
                        Account = $targetAccount
                        Count = 0
                        SourceIPs = @()
                        LastSeen = $event.TimeCreated
                    }
                }
                $tgtCountByAccount[$targetAccount].Count++
                $sourceIP = & $getEventValue $eventData 'IpAddress'
                if ($sourceIP -and $sourceIP -ne '-' -and $tgtCountByAccount[$targetAccount].SourceIPs -notcontains $sourceIP) {
                    $tgtCountByAccount[$targetAccount].SourceIPs += $sourceIP
                }
                if ($null -ne $event.TimeCreated -and ($null -eq $tgtCountByAccount[$targetAccount].LastSeen -or $event.TimeCreated -gt $tgtCountByAccount[$targetAccount].LastSeen)) {
                    $tgtCountByAccount[$targetAccount].LastSeen = $event.TimeCreated
                }
            }

            foreach ($accountName in $tgtCountByAccount.Keys) {
                $tgtInfo = $tgtCountByAccount[$accountName]
                if ($tgtInfo.Count -gt 20) {
                    $results.Summary.TGTAnomalies++
                    $results.Events += [PSCustomObject]@{
                        TimeCreated = $tgtInfo.LastSeen
                        Category = 'TGTAnomaly'
                        Severity = 'Medium'
                        Account = $tgtInfo.Account
                        Source = ($tgtInfo.SourceIPs -join ', ')
                        Details = "$($tgtInfo.Count) TGT requests in a $Hours-hour window (threshold: 20) - unusually high volume"
                        DetectionMethod = 'Threshold'
                        Confidence = 'Medium'
                    }
                }
            }
        }
        catch {
            Write-Warning "TGT request (4768) analysis not available: $_"
            $results.Recommendations += 'TGT auditing (4768) was not available - verify the Security log is accessible and Kerberos authentication service auditing is enabled'
        }

        # 3. Kerberos pre-authentication failure spikes (Event ID 4771) - brute force / password spray
        try {
            Write-Verbose "Analyzing Kerberos pre-authentication failures (4771)..."
            $krbFailEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4771
                StartTime = $startTime
            } -ErrorAction SilentlyContinue

            $failByAccount = @{}
            foreach ($event in @($krbFailEvents)) {
                if ($null -eq $event) { continue }
                $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                $targetAccount = & $getEventValue $eventData 'TargetUserName'
                if (-not $targetAccount -or $targetAccount -match '\$$') { continue }

                if (-not $failByAccount.ContainsKey($targetAccount)) {
                    $failByAccount[$targetAccount] = [PSCustomObject]@{
                        Account = $targetAccount
                        Count = 0
                        SourceIPs = @()
                        FailureCodes = @()
                        LastSeen = $event.TimeCreated
                    }
                }
                $failByAccount[$targetAccount].Count++
                $sourceIP = & $getEventValue $eventData 'IpAddress'
                $failureCode = & $getEventValue $eventData 'FailureCode'
                if ($sourceIP -and $sourceIP -ne '-' -and $failByAccount[$targetAccount].SourceIPs -notcontains $sourceIP) {
                    $failByAccount[$targetAccount].SourceIPs += $sourceIP
                }
                if ($failureCode -and $failByAccount[$targetAccount].FailureCodes -notcontains $failureCode) {
                    $failByAccount[$targetAccount].FailureCodes += $failureCode
                }
                if ($null -ne $event.TimeCreated -and ($null -eq $failByAccount[$targetAccount].LastSeen -or $event.TimeCreated -gt $failByAccount[$targetAccount].LastSeen)) {
                    $failByAccount[$targetAccount].LastSeen = $event.TimeCreated
                }
            }

            foreach ($accountName in $failByAccount.Keys) {
                $failInfo = $failByAccount[$accountName]
                if ($failInfo.Count -ge 5) {
                    $severity = if ($failInfo.Count -ge 10) { 'High' } else { 'Medium' }
                    $results.Summary.KerberosFailureSpikes++
                    $results.Events += [PSCustomObject]@{
                        TimeCreated = $failInfo.LastSeen
                        Category = 'KerberosFailureSpike'
                        Severity = $severity
                        Account = $failInfo.Account
                        Source = ($failInfo.SourceIPs -join ', ')
                        Details = "$($failInfo.Count) Kerberos pre-authentication failures in window (failure codes: $($failInfo.FailureCodes -join ', ')) - possible brute force or password spray"
                        DetectionMethod = 'Threshold'
                        Confidence = 'Medium'
                    }
                }
            }
        }
        catch {
            Write-Warning "Kerberos failure (4771) analysis not available: $_"
            $results.Recommendations += 'Kerberos failure auditing (4771) was not available - verify the Security log is accessible and credential validation auditing is enabled'
        }

        # 4. Golden-ticket heuristic: Kerberos logons (4624) for accounts with no matching 4768 TGT request in the window
        try {
            Write-Verbose "Correlating logons (4624) against TGT requests (golden-ticket heuristic)..."
            $logonEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = 4624
                StartTime = $startTime
            } -ErrorAction SilentlyContinue

            $flaggedAccounts = @{}
            foreach ($event in @($logonEvents)) {
                if ($null -eq $event) { continue }
                $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                $targetAccount = & $getEventValue $eventData 'TargetUserName'
                $logonType = & $getEventValue $eventData 'LogonType'
                $authPackage = & $getEventValue $eventData 'AuthenticationPackageName'
                $sourceIP = & $getEventValue $eventData 'IpAddress'
                $workstation = & $getEventValue $eventData 'WorkstationName'

                if ($logonType -ne '3' -or $authPackage -ne 'Kerberos') { continue }
                if (-not $targetAccount -or $targetAccount -match '\$$' -or $targetAccount -match '^(SYSTEM|ANONYMOUS LOGON)$') { continue }
                if ($tgtCountByAccount.ContainsKey($targetAccount)) { continue }
                if ($flaggedAccounts.ContainsKey($targetAccount)) { continue }

                $flaggedAccounts[$targetAccount] = $true
                $results.Summary.GoldenTicketHeuristics++
                $results.Events += [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated
                    Category = 'GoldenTicketHeuristic'
                    Severity = 'Medium'
                    Account = $targetAccount
                    Source = if ($sourceIP -and $sourceIP -ne '-') { $sourceIP } else { $workstation }
                    Details = 'Kerberos network logon with no matching TGT request (4768) for this account in the analysis window - HEURISTIC: may also result from log sampling gaps, cross-domain logons, or tickets issued before the window'
                    DetectionMethod = 'Heuristic'
                    Confidence = 'Medium'
                }
            }
        }
        catch {
            Write-Warning "Golden-ticket heuristic correlation not available: $_"
            $results.Recommendations += 'Logon correlation (4624/4768) was not available - verify the Security log is accessible'
        }

        # 5. LSASS access handle enumeration (optional): Security 4663 and/or Sysmon 10
        if ($IncludeLSASSAccess) {
            $lsassFound = $false

            try {
                Write-Verbose "Checking Sysmon Operational log availability..."
                $sysmonAvailable = $false
                try {
                    $null = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
                    $sysmonAvailable = $true
                }
                catch {
                    $sysmonAvailable = $false
                }

                Write-Verbose "Enumerating LSASS access events (4663)..."
                $handleEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'Security'
                    ID = 4663
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue

                foreach ($event in @($handleEvents)) {
                    if ($null -eq $event) { continue }
                    $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                    $objectName = & $getEventValue $eventData 'ObjectName'
                    if (-not $objectName -or $objectName -notmatch 'lsass\.exe$') { continue }

                    $lsassFound = $true
                    $processName = & $getEventValue $eventData 'ProcessName'
                    $subjectAccount = & $getEventValue $eventData 'SubjectUserName'
                    $accessMask = & $getEventValue $eventData 'AccessMask'

                    $classification = 'Review'
                    $severity = 'Medium'
                    $maskValue = $null
                    if ($accessMask) {
                        try { $maskValue = [Convert]::ToInt64($accessMask, 16) } catch { $maskValue = $null }
                    }
                    if ($null -ne $maskValue) {
                        if (($maskValue -band 0x10) -ne 0 -or $suspiciousAccessMasks -contains $accessMask.ToLower()) {
                            $classification = 'Suspicious'
                            $severity = 'High'
                        }
                        elseif ($normalAccessMasks -contains $accessMask.ToLower()) {
                            $classification = 'Normal'
                            $severity = 'Info'
                        }
                    }

                    if ($classification -eq 'Normal') { continue }

                    $results.Summary.LSASSAccessEvents++
                    if ($classification -eq 'Suspicious') { $results.Summary.SuspiciousLSASSAccess++ }
                    $results.Events += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        Category = 'LSASSAccess'
                        Severity = $severity
                        Account = $subjectAccount
                        Source = $processName
                        Details = "Process accessed lsass.exe with access mask $accessMask ($classification) - PROCESS_VM_READ (0x10) or broad rights may indicate credential dumping"
                        DetectionMethod = 'Signature'
                        Confidence = if ($classification -eq 'Suspicious') { 'High' } else { 'Low' }
                    }
                }

                if ($sysmonAvailable) {
                    $sysmonEvents = Get-WinEvent -FilterHashtable @{
                        LogName = 'Microsoft-Windows-Sysmon/Operational'
                        ID = 10
                        StartTime = $startTime
                    } -ErrorAction SilentlyContinue

                    foreach ($event in @($sysmonEvents)) {
                        if ($null -eq $event) { continue }
                        $eventData = ([xml]$event.ToXml()).Event.EventData.Data

                        $targetImage = & $getEventValue $eventData 'TargetImage'
                        if (-not $targetImage -or $targetImage -notmatch 'lsass\.exe$') { continue }

                        $lsassFound = $true
                        $sourceImage = & $getEventValue $eventData 'SourceImage'
                        $grantedAccess = & $getEventValue $eventData 'GrantedAccess'

                        $classification = 'Review'
                        $severity = 'Medium'
                        $maskValue = $null
                        if ($grantedAccess) {
                            try { $maskValue = [Convert]::ToInt64($grantedAccess, 16) } catch { $maskValue = $null }
                        }
                        if ($null -ne $maskValue) {
                            if (($maskValue -band 0x10) -ne 0 -or $suspiciousAccessMasks -contains $grantedAccess.ToLower()) {
                                $classification = 'Suspicious'
                                $severity = 'High'
                            }
                            elseif ($normalAccessMasks -contains $grantedAccess.ToLower()) {
                                $classification = 'Normal'
                                $severity = 'Info'
                            }
                        }

                        if ($classification -eq 'Normal') { continue }

                        $results.Summary.LSASSAccessEvents++
                        if ($classification -eq 'Suspicious') { $results.Summary.SuspiciousLSASSAccess++ }
                        $results.Events += [PSCustomObject]@{
                            TimeCreated = $event.TimeCreated
                            Category = 'LSASSAccess'
                            Severity = $severity
                            Account = ''
                            Source = $sourceImage
                            Details = "Sysmon ProcessAccess: $sourceImage opened lsass.exe with granted access $grantedAccess ($classification) - PROCESS_VM_READ (0x10) or broad rights may indicate credential dumping"
                            DetectionMethod = 'Signature'
                            Confidence = if ($classification -eq 'Suspicious') { 'High' } else { 'Low' }
                        }
                    }
                }

                if (-not $lsassFound) {
                    Write-Verbose "No LSASS access events found"
                    $results.Recommendations += 'No lsass.exe access-handle events found - enable Object Access auditing with a SACL on lsass.exe (Security 4663) or deploy Sysmon with ProcessAccess (ID 10) logging for LSASS access visibility'
                }
            }
            catch {
                Write-Warning "LSASS access analysis not available: $_"
                $results.Recommendations += 'LSASS access monitoring not available - enable Object Access auditing on lsass.exe or install Sysmon with ProcessAccess events'
            }
        }

        # Recommendations based on findings
        if ($results.Summary.KerberoastBursts -gt 0) {
            $results.Recommendations += 'Investigate accounts with RC4 service-ticket bursts (possible Kerberoasting); prefer AES for service accounts, use gMSA or long random service account passwords, and rotate exposed credentials'
        }
        if ($results.Summary.KerberosFailureSpikes -gt 0) {
            $results.Recommendations += 'Investigate Kerberos pre-authentication failure spikes for brute force or password spray; enforce lockout policies and MFA'
        }
        if ($results.Summary.TGTAnomalies -gt 0) {
            $results.Recommendations += 'Review accounts with unusually high TGT request volumes; correlate with expected application behavior before treating as malicious'
        }
        if ($results.Summary.GoldenTicketHeuristics -gt 0) {
            $results.Recommendations += 'Golden-ticket heuristic hits require manual validation - verify log coverage for 4768 on all DCs before concluding ticket forgery (heuristic, Medium confidence)'
        }
        if ($results.Summary.SuspiciousLSASSAccess -gt 0) {
            $results.Recommendations += 'Suspicious lsass.exe access detected - isolate the host, capture memory for analysis, and reset credentials that may have been exposed'
        }
    }

    end {
        Write-Host "`nCredential-Access Analysis Complete!" -ForegroundColor Green
        Write-Host "`n=== Summary ===" -ForegroundColor Cyan
        Write-Host "RC4 service ticket requests: $($results.Summary.RC4ServiceTicketRequests)" -ForegroundColor Yellow
        Write-Host "Kerberoast bursts (>5 RC4 tickets per account): $($results.Summary.KerberoastBursts)" -ForegroundColor $(if ($results.Summary.KerberoastBursts -gt 0) { 'Red' } else { 'Green' })
        Write-Host "TGT request anomalies: $($results.Summary.TGTAnomalies)" -ForegroundColor $(if ($results.Summary.TGTAnomalies -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "Kerberos failure spikes: $($results.Summary.KerberosFailureSpikes)" -ForegroundColor $(if ($results.Summary.KerberosFailureSpikes -gt 0) { 'Red' } else { 'Green' })
        Write-Host "Golden-ticket heuristic hits: $($results.Summary.GoldenTicketHeuristics)" -ForegroundColor $(if ($results.Summary.GoldenTicketHeuristics -gt 0) { 'Yellow' } else { 'Green' })

        if ($IncludeLSASSAccess) {
            Write-Host "LSASS access events flagged: $($results.Summary.LSASSAccessEvents)" -ForegroundColor Yellow
            Write-Host "Suspicious LSASS access: $($results.Summary.SuspiciousLSASSAccess)" -ForegroundColor $(if ($results.Summary.SuspiciousLSASSAccess -gt 0) { 'Red' } else { 'Green' })
        }

        if (@($results.Recommendations).Count -gt 0) {
            Write-Host "`n=== Recommendations ===" -ForegroundColor Cyan
            foreach ($recommendation in $results.Recommendations) {
                Write-Host "- $recommendation" -ForegroundColor Yellow
            }
        }

        return $results
    }
}
