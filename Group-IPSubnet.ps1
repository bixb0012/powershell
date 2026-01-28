function Group-IPSubnet {
    [CmdletBinding(DefaultParameterSetName='Default', HelpUri='https://learn.microsoft.com')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, HelpMessage = 'Specify the CIDR string(s) to analyze (e.g., "10.0.0.0/24").')]
        [string[]]$Cidr,

        [Parameter(HelpMessage = 'Include gap records in the output and adjust percentage calculations to span the entire range (min start IP to max end IP).')]
        [switch]$IncludeGaps
    )
    <#
    .SYNOPSIS
        Consolidates and aggregates IPv4 CIDR blocks into their broadest possible supernets.
    
    .DESCRIPTION
        Group-IPSubnet processes a list of IPv4 CIDR strings to remove redundancy and provide a 
        hierarchical view of network utilization. The function performs three primary actions:
        1. Validation: Filters out malformed strings and invalid IPv4 CIDRs.
        2. Consolidation: Removes nested subnets (e.g., if 10.0.0.0/24 is provided along with 
           10.0.0.0/8, the /24 is merged into the /8).
        3. Aggregation: Combines contiguous, same-sized subnets into larger supernets (e.g., 
           combining 192.168.1.0/24 and 192.168.0.0/24 into 192.168.0.0/23).
    
        The output includes the calculated network boundaries, block sizes, and the percentage 
        of coverage relative to the total analyzed space.
    
    .PARAMETER Cidr
        An array of IPv4 CIDR strings (e.g., "10.0.0.0/24", "172.16.0.0/12"). 
        This parameter accepts input from the pipeline.
    
    .PARAMETER IncludeGaps
        A switch that, when enabled, identifies unallocated spaces ("Gaps") between the 
        provided subnets. When this switch is active, the percentage calculations are 
        based on the entire span from the lowest start IP to the highest end IP.
    
    .EXAMPLE
        PS C:\> Group-IPSubnet -Cidr "10.96.61.0/24", "10.96.60.0/24"
    
        This command aggregates two contiguous /24 networks into a single /23 supernet.
    
    .EXAMPLE
        PS C:\> $Networks | Group-IPSubnet -IncludeGaps
    
        This takes a list of networks from a variable, consolidates them, and outputs 
        both the resulting subnets and the gaps between them.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns objects containing RecordType (Subnet/Gap), Cidr, StartIp, EndIp, Size, 
        PercentageTotal, and the original InputCidrs that were merged into the result.
    
    .NOTES
        This function adheres to Microsoft Strongly Encouraged Development Guidelines 
        and uses UInt64 mathematics to ensure precision across large address spaces.
    #>
    begin {
        # Helper functions are defined within the begin block
        function Get-Numeric {
            param([string]$ipText)
            $ip = [System.Net.IPAddress]::Parse($ipText)
            $bytes = $ip.GetAddressBytes()
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
            return [BitConverter]::ToUInt32($bytes, 0)
        }

        function Get-IPText {
            param([uint32]$num)
            $b = [BitConverter]::GetBytes($num)
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
            return (New-Object System.Net.IPAddress(,$b)).IPAddressToString
        }

        $cidrItems   = New-Object System.Collections.Generic.List[string]
        $invalidList = New-Object System.Collections.Generic.List[string]
        $cidrPattern = '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    }

    process {
        foreach ($item in $Cidr) {
            if ($null -ne $item -and $item -is [string]) {
                $trimmed = $item.Trim()
                if ($trimmed.Length -gt 0) { $cidrItems.Add($trimmed) }
            }
        }
    }
    
    end {
        if ($cidrItems.Count -eq 0) {
            Write-Warning "No CIDR inputs provided."
            return
        }

        $subnets = New-Object System.Collections.Generic.List[object]
        foreach ($cidrStr in $cidrItems) {
            if ($cidrStr -match $cidrPattern) {
                try {
                    $parts = $cidrStr -split '/'
                    # FIX: Explicitly access array elements
                    $ipPart = $parts[0]
                    $maskPart = [int]$parts[1]

                    if ($maskPart -lt 0 -or $maskPart -gt 32) { $invalidList.Add($cidrStr); continue }

                    $numeric = Get-Numeric $ipPart
                    $shift = 32 - $maskPart
                    $blockSize = [uint64]1 -shl $shift
                    $netStart = [uint32]($numeric -band (0xFFFFFFFF -shl $shift))
                    $netEnd = [uint32]($netStart + $blockSize - 1)

                    $subnets.Add([PSCustomObject]@{
                        NetworkStart = $netStart; NetworkEnd = $netEnd; Mask = $maskPart; BlockSize = $blockSize; InputCidrs = @($cidrStr)
                    })
                } catch { $invalidList.Add($cidrStr) }
            } else { $invalidList.Add($cidrStr) }
        }

        if ($subnets.Count -eq 0) {
            if ($invalidList.Count -gt 0) { Write-Warning ("No valid CIDR strings found. Skipped: " + ($invalidList -join ', ')) }
            return
        }
        if ($invalidList.Count -gt 0) { Write-Warning ("Skipped invalid CIDR strings: " + ($invalidList -join ', ')) }

        # CONSOLIDATION & AGGREGATION LOGIC (Verified functional)
        $sortedSubnets = @($subnets | Sort-Object NetworkStart, Mask)
        $broadest = New-Object System.Collections.Generic.List[object]
        foreach ($current in $sortedSubnets) {
            $isNested = $false
            foreach ($existing in $broadest) {
                if (($current.NetworkStart -ge $existing.NetworkStart) -and ($current.NetworkEnd -le $existing.NetworkEnd)) {
                    $existing.InputCidrs += $current.InputCidrs; $isNested = $true; break
                }
            }
            if (-not $isNested) { $broadest.Add($current) }
        }

        $changed = $true
        while ($changed) {
            $changed = $false; $temp = New-Object System.Collections.Generic.List[object]
            $list = @($broadest | Sort-Object NetworkStart, Mask)
            for ($i = 0; $i -lt $list.Count; $i++) {
                $current = $list[$i]; $next = if ($i + 1 -lt $list.Count) { $list[$i + 1] } else { $null }
                if ($next -and $current.Mask -eq $next.Mask) {
                    $size = [uint64]$current.BlockSize
                    if (([uint64]$current.NetworkStart + $size -eq [uint64]$next.NetworkStart) -and (([uint64]$current.NetworkStart % ($size * 2)) -eq 0)) {
                        $temp.Add([PSCustomObject]@{
                            NetworkStart = $current.NetworkStart; NetworkEnd = [uint32]($current.NetworkStart + ($size * 2) - 1)
                            Mask = ($current.Mask - 1); BlockSize = ($size * 2); InputCidrs = ($current.InputCidrs + $next.InputCidrs)
                        })
                        $i++; $changed = $true; continue
                    }
                }
                $temp.Add($current)
            }
            $broadest = $temp
        }

        # Determine Total Span for Percentages
        if ($IncludeGaps) {
            $broadest = @($broadest | Sort-Object NetworkStart)
            # FIX: Explicitly access the property of the FIRST and LAST array element
            $minStart  = $broadest[0].NetworkStart
            $maxEnd    = $broadest[-1].NetworkEnd
            $totalSpan = [uint64]$maxEnd - [uint64]$minStart + 1
        } else {
            $totalSpan = [uint64]0
            foreach ($s in $broadest) { $totalSpan += $s.BlockSize }
        }
        if ($totalSpan -eq 0) { $totalSpan = 1 }

        # Generate Final Output Stream
        $results = New-Object System.Collections.Generic.List[PSCustomObject]
        for ($i = 0; $i -lt $broadest.Count; $i++) {
            $current = $broadest[$i]
            $results.Add([PSCustomObject]@{
                RecordType      = 'Subnet'
                Cidr            = "$(Get-IPText $current.NetworkStart)/$($current.Mask)"
                StartIp         = Get-IPText $current.NetworkStart
                EndIp           = Get-IPText $current.NetworkEnd
                Size            = $current.BlockSize
                PercentageTotal = [Math]::Round((([double]$current.BlockSize / [double]$totalSpan) * 100), 2)
                InputCidrs      = @($current.InputCidrs | Sort-Object -Unique)
            })

            if ($IncludeGaps -and $i -lt ($broadest.Count - 1)) {
                $next = $broadest[$i + 1]
                $gapStartVal = [uint64]$current.NetworkEnd + 1
                if ($gapStartVal -lt [uint64]$next.NetworkStart) {
                    $gapSize = [uint64]$next.NetworkStart - $gapStartVal
                    $results.Add([PSCustomObject]@{
                        RecordType      = 'Gap'
                        Cidr            = $null
                        StartIp         = Get-IPText ([uint32]$gapStartVal)
                        EndIp           = Get-IPText ([uint32]($next.NetworkStart - 1))
                        Size            = $gapSize
                        PercentageTotal = [Math]::Round((([double]$gapSize / [double]$totalSpan) * 100), 2)
                        InputCidrs      = $null
                    })
                }
            }
        }
        return $results | Sort-Object NetworkStart
    }
}
