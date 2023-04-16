<#
    .Description
    Watch-Counter function continuously retrieves Windows performance counters
    and displays data as progress bar
#>
function Watch-Counter {
    [CmdletBinding()]
    [Alias("wc")]
    param(
        [Parameter(
            HelpMessage="Windows diagnostic counter"
        )]
        [string[]]
        $Counters = @(
            "\Processor(_total)\% Processor Time"
            "\Memory\% Committed Bytes In Use"
        ),
        
        [Parameter(
            HelpMessage="Interval for refreshing counter"
        )]
        [ValidateScript({$_ -ge 1})]
        [int]
        $Interval = 3
    )
    
    Write-Progress -Activity "Watch-Counter" -Status " " -Id 0
    try {
        # Load performance counters in background and wait with progress bar
        $ScriptBlock = [ScriptBlock]::Create("Get-Counter -ListSet *")
        $PowerShell = [PowerShell]::Create()
        [void]$PowerShell.AddScript($ScriptBlock)
        $Job = ([PSCustomObject]@{
            "AsyncResult" = $PowerShell.BeginInvoke()
            "PowerShell" = $PowerShell
        })
        $i = 0
        do {
            Start-Sleep -Milliseconds 500
            if ($Job.AsyncResult.IsCompleted -contains $false) {
                $i = [Math]::Min(100, ($i = $i + 20))
            } else {
                $i = 100
            }
            $ProgressArgs = @{
                "Activity" = "Loading performance counters..."
                "Status" = "$i% Complete"
                "Id" = 1
                "PercentComplete" = $i
                "CurrentOperation" = " "
                "ParentId" = 0
            }
            Write-Progress @ProgressArgs
        } while ($Job.AsyncResult.IsCompleted -contains $false)
        $CounterList = $Job.PowerShell.EndInvoke($Job.AsyncResult).Paths
        $Job.PowerShell.Dispose()
        
        # Validate performance counters
        $Counters = $Counters.ForEach({
            $Counter = $_ -replace "\(.*?\)", "(*)"
            if ($CounterList -contains $Counter) {
                $_
            } else {
                Write-Warning "Counter '$_' not found on computer."
            }
        })
        if ($Counters.Length -gt 5) {
            Write-Warning "Watching more than 5 counters may result in display issues."
        } elseif ($Counters.Length -lt 1) {
            Write-Warning "No counters to watch."
            return
        }
    } finally {
        # Cleanup job, including if CTRL+C is pressed
        $Job.PowerShell.Dispose()
    }
    
    try {
        # Create runspace pool for background processing
        $RunspacePool =  [RunspaceFactory]::CreateRunspacePool(1, [Environment]::ProcessorCount/2)
        $RunspacePool.Open()
        
        # Attach Get-Counter to runspace pool for each performance counter
        $Jobs = [Collections.ArrayList]@()
        for ($i=0; $i -lt $Counters.Length; $i++) {
            $ScriptBlock = [ScriptBlock]::Create("Get-Counter -Counter '$($Counters[$i])'")
            $PowerShell = [PowerShell]::Create()
            $PowerShell.RunspacePool = $RunspacePool
            [void]$PowerShell.AddScript($ScriptBlock)
            [void]$Jobs.Add([PSCustomObject]@{
                "AsyncResult" = $PowerShell.BeginInvoke()
                "PowerShell" = $PowerShell
            })
        }
        
        # Continuously call Get-Counter and display result as progress bar
        while ($true) {
            $WaitCounter = 0
            while ($Jobs.AsyncResult.IsCompleted -contains $false) {
                $WaitCounter++
                Start-Sleep -Milliseconds 100
            }
            for ($i=0; $i -lt $Counters.Length; $i++) {  
                $Counter = $Jobs[$i].PowerShell.EndInvoke($Jobs[$i].AsyncResult)
                $ProgressArgs = @{
                    "Activity" = $Counter.CounterSamples.Path
                    "Status" = "$($Counter.TimeStamp) : $($Counter.CounterSamples.CookedValue)"
                    "Id" = $i + 1
                    "CurrentOperation" = " "
                    "ParentId" = 0
                }
                Write-Progress @ProgressArgs
            }
            Start-Sleep -Milliseconds ($Interval * 1000 - $WaitCounter * 100)
            for ($i=0; $i -lt $Counters.Length; $i++) {  
                $Jobs[$i].AsyncResult = $Jobs[$i].PowerShell.BeginInvoke()
            }
        }
    } finally {
        # Cleanup jobs and runspace pool, including if CTRL+C is pressed
        $Jobs.ForEach({ $_.PowerShell.Dispose() })
        $RunspacePool.Close()
    }
}

