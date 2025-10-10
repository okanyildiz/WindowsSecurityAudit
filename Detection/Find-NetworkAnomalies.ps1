function Find-NetworkAnomalies {
    <#
    .SYNOPSIS
        Detects suspicious network connections and activities
    .DESCRIPTION
        Identifies unusual network connections, listening ports, and network-based
        indicators of compromise
    .PARAMETER IncludeEstablished
        Include established connections in analysis
    .PARAMETER CheckDNS
        Perform DNS-based anomaly detection
    .EXAMPLE
        Find-NetworkAnomalies
        Find-NetworkAnomalies -IncludeEstablished -CheckDNS
    .OUTPUTS
        PSCustomObject with network anomaly findings
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeEstablished,
        
        [Parameter()]
        [switch]$CheckDNS
    )
    
    begin {
        Write-Host "Scanning for network anomalies..." -ForegroundColor Cyan
        
        $results = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            SuspiciousListeners = @()
            SuspiciousConnections = @()
            UnusualPorts = @()
            DNSAnomalies = @()
            TotalAnomalies = 0
        }
        
        # Known malicious ports
        $maliciousPorts = @(
            4444,  # Metasploit
            5555,  # Android Debug Bridge / Backdoors
            6666,  # IRC/Backdoors
            6667,  # IRC
            31337, # Back Orifice
            12345, # NetBus
            1337,  # Common backdoor
            8888,  # Common C2
            9999   # Common backdoor
        )
        
        # Legitimate common ports
        $legitimatePorts = @(80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389, 445, 139, 135)
    }
    
    process {
        try {
            # Check listening ports
            Write-Verbose "Checking listening ports..."
            $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
            
            foreach ($listener in $listeners) {
                $suspicious = $false
                $reasons = @()
                
                # Check if port is known malicious
                if ($maliciousPorts -contains $listener.LocalPort) {
                    $suspicious = $true
                    $reasons += "Known malicious port: $($listener.LocalPort)"
                }
                
                # Check for unusual high ports
                if ($listener.LocalPort -gt 49152 -and $listener.LocalAddress -eq '0.0.0.0') {
                    $suspicious = $true
                    $reasons += "High port number listening on all interfaces"
                }
                
                # Get process info
                $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
                
                # Check for suspicious process listening
                if ($process) {
                    $processPath = $process.Path
                    if ($processPath -match '(Temp|AppData|Users\\Public)' -and $listener.LocalAddress -eq '0.0.0.0') {
                        $suspicious = $true
                        $reasons += "Suspicious process location listening on all interfaces"
                    }
                }
                
                if ($suspicious) {
                    $results.SuspiciousListeners += [PSCustomObject]@{
                        LocalAddress = $listener.LocalAddress
                        LocalPort = $listener.LocalPort
                        ProcessName = if ($process) { $process.ProcessName } else { 'Unknown' }
                        ProcessId = $listener.OwningProcess
                        ProcessPath = if ($process) { $process.Path } else { 'Unknown' }
                        Reasons = ($reasons -join '; ')
                    }
                }
            }
            
            # Check established connections (if requested)
            if ($IncludeEstablished) {
                Write-Verbose "Checking established connections..."
                $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
                
                foreach ($conn in $connections) {
                    $suspicious = $false
                    $reasons = @()
                    
                    # Check for connections to malicious ports
                    if ($maliciousPorts -contains $conn.RemotePort) {
                        $suspicious = $true
                        $reasons += "Connection to known malicious port: $($conn.RemotePort)"
                    }
                    
                    # Check for unusual remote ports
                    if ($conn.RemotePort -notin $legitimatePorts -and $conn.RemotePort -lt 1024) {
                        $suspicious = $true
                        $reasons += "Connection to unusual low port: $($conn.RemotePort)"
                    }
                    
                    # Get process info
                    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    
                    if ($process) {
                        # Check for suspicious processes with network connections
                        if ($process.ProcessName -match '(cmd|powershell|wscript|cscript)') {
                            $suspicious = $true
                            $reasons += "Scripting engine with network connection"
                        }
                        
                        # Check process path
                        if ($process.Path -match '(Temp|AppData\\Local\\Temp|Users\\Public)') {
                            $suspicious = $true
                            $reasons += "Process from suspicious location with network connection"
                        }
                    }
                    
                    if ($suspicious) {
                        $results.SuspiciousConnections += [PSCustomObject]@{
                            LocalAddress = $conn.LocalAddress
                            LocalPort = $conn.LocalPort
                            RemoteAddress = $conn.RemoteAddress
                            RemotePort = $conn.RemotePort
                            State = $conn.State
                            ProcessName = if ($process) { $process.ProcessName } else { 'Unknown' }
                            ProcessId = $conn.OwningProcess
                            ProcessPath = if ($process) { $process.Path } else { 'Unknown' }
                            Reasons = ($reasons -join '; ')
                        }
                    }
                }
            }
            
            # Check for unusual ports in use
            Write-Verbose "Analyzing port usage patterns..."
            $allConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
            $portGroups = $allConnections | Group-Object -Property LocalPort | 
                Where-Object { $_.Count -gt 10 -and $_.Name -notin $legitimatePorts }
            
            foreach ($group in $portGroups) {
                $results.UnusualPorts += [PSCustomObject]@{
                    Port = $group.Name
                    ConnectionCount = $group.Count
                    Reason = "Unusually high number of connections on non-standard port"
                }
            }
            
            # DNS anomaly detection (if requested)
            if ($CheckDNS) {
                Write-Verbose "Checking DNS cache for anomalies..."
                try {
                    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
                    
                    foreach ($entry in $dnsCache) {
                        $suspicious = $false
                        $reasons = @()
                        
                        # Check for unusual TLDs
                        if ($entry.Name -match '\.(tk|ml|ga|cf|gq|xyz|top|work)$') {
                            $suspicious = $true
                            $reasons += "Suspicious TLD commonly used by malware"
                        }
                        
                        # Check for very long domain names (possible DGA)
                        if ($entry.Name.Length -gt 50) {
                            $suspicious = $true
                            $reasons += "Unusually long domain name (possible DGA)"
                        }
                        
                        # Check for high entropy in subdomain (possible DGA)
                        $subdomain = ($entry.Name -split '\.')[0]
                        if ($subdomain.Length -gt 15 -and $subdomain -match '[a-z]{10,}') {
                            # Simple entropy check
                            $uniqueChars = ($subdomain.ToCharArray() | Select-Object -Unique).Count
                            if ($uniqueChars -gt 10) {
                                $suspicious = $true
                                $reasons += "High entropy subdomain (possible DGA)"
                            }
                        }
                        
                        if ($suspicious) {
                            $results.DNSAnomalies += [PSCustomObject]@{
                                Name = $entry.Name
                                Type = $entry.Type
                                Data = $entry.Data
                                TTL = $entry.TimeToLive
                                Reasons = ($reasons -join '; ')
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Could not check DNS cache: $_"
                }
            }
            
            # Calculate total anomalies
            $results.TotalAnomalies = ($results.SuspiciousListeners.Count +
                                      $results.SuspiciousConnections.Count +
                                      $results.UnusualPorts.Count +
                                      $results.DNSAnomalies.Count)
            
        }
        catch {
            Write-Error "Error during network scan: $_"
            throw
        }
    }
    
    end {
        Write-Host "`nNetwork scan complete!" -ForegroundColor Green
        Write-Host "Total anomalies found: $($results.TotalAnomalies)" -ForegroundColor $(if ($results.TotalAnomalies -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host "  Suspicious listeners: $($results.SuspiciousListeners.Count)" -ForegroundColor Cyan
        Write-Host "  Suspicious connections: $($results.SuspiciousConnections.Count)" -ForegroundColor Cyan
        Write-Host "  Unusual ports: $($results.UnusualPorts.Count)" -ForegroundColor Cyan
        Write-Host "  DNS anomalies: $($results.DNSAnomalies.Count)" -ForegroundColor Cyan
        
        return $results
    }
}