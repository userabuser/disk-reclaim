<#
.SYNOPSIS
    Invoke-DiskReclaim - Advanced Disk Reclamation, Active Workflow Monitor, and Session Churn Hunter.
.DESCRIPTION
    Specifically focused on Windows Drive C: for developer workstations.
    Reclaims disk space from system caches, package managers, development caches, and ephemeral session artifacts.
    Includes active process disk write monitoring and recent session churn analysis.
.PARAMETER Mode
    Operation mode:
    - Scan (default): Safe dry-run. Inspects all reclaimable targets without deleting anything.
    - Clean: Performs safe reclamation on selected risk tiers.
    - Monitor: Monitors active processes and real-time disk write churn.
    - FindChurn: Scans Drive C: for large recently created/modified files from recent dev sessions.
    - All: Runs Scan, Monitor, and FindChurn in sequence.
.PARAMETER Tier
    Risk tier to target during -Clean or -Scan:
    - ZeroRisk: Pure ephemeral, crash dumps, stale temp, update downloads, browser/electron caches.
    - LowRisk: Rebuildable package manager caches (npm, pip, scoop, cargo, nuget, go build).
    - All: Both ZeroRisk and LowRisk tiers.
.PARAMETER ChurnHours
    Hours lookback for session churn scan (default: 48).
.PARAMETER ChurnMinMB
    Minimum file size in MB for session churn scan (default: 25).
.PARAMETER MonitorDurationSec
    Duration in seconds to sample active process write rates (default: 5).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [ValidateSet('Scan', 'Clean', 'Monitor', 'FindChurn', 'All')]
    [string]$Mode = 'Scan',

    [ValidateSet('ZeroRisk', 'LowRisk', 'All')]
    [string]$Tier = 'All',

    [int]$ChurnHours = 48,

    [int]$ChurnMinMB = 25,

    [int]$MonitorDurationSec = 5,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ==============================================================================
# Helper Formatting Utilities
# ==============================================================================
function Write-Header([string]$Title) {
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ("  $Title") -ForegroundColor White
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host ("--- $Title ---") -ForegroundColor Yellow
}

function Write-Success([string]$Message) {
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Info([string]$Message) {
    Write-Host "[-] $Message" -ForegroundColor Gray
}

# Fast folder measurement using DirectoryInfo to bypass PowerShell pipeline overhead
function Get-FolderStats([string]$FolderPath) {
    $stats = [PSCustomObject]@{
        Exists  = $false
        SizeMB  = 0.0
        Count   = 0
        Path    = $FolderPath
    }

    if (-not (Test-Path -LiteralPath $FolderPath)) {
        return $stats
    }

    $stats.Exists = $true
    $totalBytes = 0L
    $count = 0

    try {
        $di = [System.IO.DirectoryInfo]::new($FolderPath)
        $opt = [System.IO.EnumerationOptions]@{
            RecurseSubdirectories = $true
            IgnoreInaccessible     = $true
            AttributesToSkip       = [System.IO.FileAttributes]::ReparsePoint
        }
        foreach ($file in $di.EnumerateFiles('*', $opt)) {
            $totalBytes += $file.Length
            $count++
        }
    } catch {}

    $stats.SizeMB = [math]::Round(($totalBytes / 1MB), 2)
    $stats.Count  = $count
    return $stats
}

# Purges contents of a directory while safely ignoring currently locked files
function Clear-DirectorySafely([string]$FolderPath, [int]$MinAgeHours = 0) {
    $reclaimedBytes = 0L
    $deletedFiles = 0
    $skippedLocked = 0

    if (-not (Test-Path -LiteralPath $FolderPath)) {
        return [PSCustomObject]@{ ReclaimedMB = 0.0; DeletedCount = 0; SkippedCount = 0 }
    }

    $cutoff = if ($MinAgeHours -gt 0) { (Get-Date).AddHours(-$MinAgeHours) } else { [DateTime]::MaxValue }

    try {
        $di = [System.IO.DirectoryInfo]::new($FolderPath)
        $opt = [System.IO.EnumerationOptions]@{
            RecurseSubdirectories = $true
            IgnoreInaccessible     = $true
            AttributesToSkip       = [System.IO.FileAttributes]::ReparsePoint
        }

        # Delete matching files
        foreach ($file in $di.EnumerateFiles('*', $opt)) {
            try {
                if ($MinAgeHours -gt 0 -and $file.LastWriteTime -gt $cutoff) {
                    continue
                }
                $len = $file.Length
                [System.IO.File]::Delete($file.FullName)
                $reclaimedBytes += $len
                $deletedFiles++
            } catch {
                # File is in-use / locked by an active process
                $skippedLocked++
            }
        }

        # Prune empty directories (bottom-up)
        $subDirs = Get-ChildItem -LiteralPath $FolderPath -Recurse -Directory -Force -ErrorAction SilentlyContinue |
                   Sort-Object { $_.FullName.Length } -Descending
        foreach ($dir in $subDirs) {
            try {
                if ((Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                    [System.IO.Directory]::Delete($dir.FullName)
                }
            } catch {}
        }
    } catch {}

    return [PSCustomObject]@{
        ReclaimedMB  = [math]::Round(($reclaimedBytes / 1MB), 2)
        DeletedCount = $deletedFiles
        SkippedCount = $skippedLocked
    }
}

# ==============================================================================
# TARGET DEFINITIONS WITH RISK ASSESSMENTS
# ==============================================================================
function Get-ReclamationTargets {
    $targets = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- TIER 1: ZERO RISK (Pure Ephemerals & Diagnostic Dumps) ---
    $targets.Add([PSCustomObject]@{
        Tier        = 'ZeroRisk'
        Category    = 'System Temp'
        Id          = 'UserTemp'
        Name        = 'User Temp Files ($env:TEMP)'
        Path        = [System.IO.Path]::GetTempPath().TrimEnd('\')
        Risk        = 'Zero Risk'
        Description = 'Temporary scratch files generated by programs. In-use files are automatically skipped and preserved.'
        CleanupType = 'FolderContents'
        MinAgeHours = 1  # Leave files modified within the last hour
    })

    $targets.Add([PSCustomObject]@{
        Tier        = 'ZeroRisk'
        Category    = 'System Temp'
        Id          = 'WindowsTemp'
        Name        = 'Windows System Temp'
        Path        = 'C:\Windows\Temp'
        Risk        = 'Zero Risk'
        Description = 'System-level temp files left behind by Windows services and installers.'
        CleanupType = 'FolderContents'
        MinAgeHours = 4
    })

    $targets.Add([PSCustomObject]@{
        Tier        = 'ZeroRisk'
        Category    = 'Diagnostics'
        Id          = 'CrashDumps'
        Name        = 'User Crash Dumps (*.dmp)'
        Path        = (Join-Path $env:LOCALAPPDATA 'CrashDumps')
        Risk        = 'Zero Risk'
        Description = 'Crash dump memory snapshots generated during unhandled application faults.'
        CleanupType = 'FolderContents'
        MinAgeHours = 0
    })

    $targets.Add([PSCustomObject]@{
        Tier        = 'ZeroRisk'
        Category    = 'Diagnostics'
        Id          = 'WerReports'
        Name        = 'Windows Error Reporting Archive'
        Path        = 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'
        Risk        = 'Zero Risk'
        Description = 'Archived Windows telemetry and incident error reports.'
        CleanupType = 'FolderContents'
        MinAgeHours = 0
    })

    $targets.Add([PSCustomObject]@{
        Tier        = 'ZeroRisk'
        Category    = 'Windows Update'
        Id          = 'WinUpdateCache'
        Name        = 'Windows Update Download Cache'
        Path        = 'C:\Windows\SoftwareDistribution\Download'
        Risk        = 'Zero Risk'
        Description = 'Downloaded update packages already staged or installed by Windows Update.'
        CleanupType = 'FolderContents'
        MinAgeHours = 24
    })

    $vsCodeCachePaths = @(
        (Join-Path $env:APPDATA 'Code\Cache'),
        (Join-Path $env:APPDATA 'Code\CachedData'),
        (Join-Path $env:APPDATA 'Code\Code Cache'),
        (Join-Path $env:APPDATA 'Code\GPUCache')
    )
    foreach ($vPath in $vsCodeCachePaths) {
        $namePart = [System.IO.Path]::GetFileName($vPath)
        $targets.Add([PSCustomObject]@{
            Tier        = 'ZeroRisk'
            Category    = 'Editor Cache'
            Id          = "VSCode_$namePart"
            Name        = "VS Code $namePart"
            Path        = $vPath
            Risk        = 'Zero Risk'
            Description = 'Electron runtime V8 bytecode & GPU shader cache. Safely regenerated on next editor launch.'
            CleanupType = 'FolderContents'
            MinAgeHours = 0
        })
    }

    $chromeCachePaths = @(
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Cache\Cache_Data'),
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\GPUCache'),
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\ShaderCache')
    )
    foreach ($cPath in $chromeCachePaths) {
        if (Test-Path -LiteralPath $cPath) {
            $leaf = [System.IO.Path]::GetFileName($cPath)
            $targets.Add([PSCustomObject]@{
                Tier        = 'ZeroRisk'
                Category    = 'Browser Cache'
                Id          = "Chrome_$leaf"
                Name        = "Chrome $leaf"
                Path        = $cPath
                Risk        = 'Zero Risk'
                Description = 'Web cache and GPU compiled shaders. User history, bookmarks, passwords, and sessions are untouched.'
                CleanupType = 'FolderContents'
                MinAgeHours = 0
            })
        }
    }

    # --- TIER 2: LOW RISK (Rebuildable Package Manager & Build Tool Caches) ---
    $targets.Add([PSCustomObject]@{
        Tier        = 'LowRisk'
        Category    = 'Package Manager'
        Id          = 'NpmCache'
        Name        = 'npm Download Cache'
        Path        = (Join-Path $env:LOCALAPPDATA 'npm-cache')
        Risk        = 'Low Risk'
        Description = 'Cached tarballs of npm modules. Deleting forces npm to download fresh copies if not found locally.'
        CleanupType = 'CommandOrFolder'
        CliCommand  = 'npm cache clean --force'
        MinAgeHours = 0
    })

    $targets.Add([PSCustomObject]@{
        Tier        = 'LowRisk'
        Category    = 'Package Manager'
        Id          = 'PipCache'
        Name        = 'Python pip Cache'
        Path        = (Join-Path $env:LOCALAPPDATA 'pip\cache')
        Risk        = 'Low Risk'
        Description = 'Cached python wheels and source distributions. Re-downloaded on future pip installs.'
        CleanupType = 'CommandOrFolder'
        CliCommand  = 'pip cache purge'
        MinAgeHours = 0
    })

    $targets.Add([PSCustomObject]@{
        Tier        = 'LowRisk'
        Category    = 'Package Manager'
        Id          = 'ScoopCache'
        Name        = 'Scoop Installer Cache'
        Path        = (Join-Path $env:USERPROFILE 'scoop\cache')
        Risk        = 'Low Risk'
        Description = 'Downloaded application installers stored after scoop installation.'
        CleanupType = 'CommandOrFolder'
        CliCommand  = 'scoop cache rm *'
        MinAgeHours = 0
    })

    $cargoCachePath = Join-Path $env:USERPROFILE '.cargo\registry\cache'
    $targets.Add([PSCustomObject]@{
        Tier        = 'LowRisk'
        Category    = 'Build Cache'
        Id          = 'CargoCache'
        Name        = 'Cargo Registry Cache (.crate tarballs)'
        Path        = $cargoCachePath
        Risk        = 'Low Risk'
        Description = 'Pre-downloaded .crate archives. Cargo automatically re-downloads them on next build.'
        CleanupType = 'FolderContents'
        MinAgeHours = 0
    })

    $goBuildPath = Join-Path $env:LOCALAPPDATA 'go-build'
    $targets.Add([PSCustomObject]@{
        Tier        = 'LowRisk'
        Category    = 'Build Cache'
        Id          = 'GoBuildCache'
        Name        = 'Go Build Cache'
        Path        = $goBuildPath
        Risk        = 'Low Risk'
        Description = 'Intermediate compiled object files and build action cache.'
        CleanupType = 'CommandOrFolder'
        CliCommand  = 'go clean -cache -testcache'
        MinAgeHours = 0
    })

    $nugetPath = Join-Path $env:USERPROFILE '.nuget\packages'
    $targets.Add([PSCustomObject]@{
        Tier        = 'LowRisk'
        Category    = 'Package Manager'
        Id          = 'NuGetCache'
        Name        = 'NuGet Global Packages Cache'
        Path        = $nugetPath
        Risk        = 'Low Risk'
        Description = 'Extracted global NuGet packages. dotnet restore will re-download when needed.'
        CleanupType = 'CommandOrFolder'
        CliCommand  = 'dotnet nuget locals all --clear'
        MinAgeHours = 0
    })

    $targets.Add([PSCustomObject]@{
        Tier        = 'LowRisk'
        Category    = 'Container Runtime'
        Id          = 'DockerBuilder'
        Name        = 'Docker BuildKit & Dangling Cache'
        Path        = '' # Handled via docker CLI
        Risk        = 'Low Risk'
        Description = 'Dangling container build cache layers and stopped anonymous containers.'
        CleanupType = 'CliOnly'
        CliCommand  = 'docker builder prune -f'
        MinAgeHours = 0
    })

    return $targets
}

# ==============================================================================
# SUB-ROUTINE: SCAN DISK TARGETS (DRY RUN)
# ==============================================================================
function Invoke-DiskScan {
    param([string]$TargetTier)

    Write-Header "DRIVE C: DISK SPACE SURVEY & RECLAMATION CANDIDATES"
    Write-Info "Scanning ephemeral caches, package managers, and development artifacts on C:..."

    $targets = Get-ReclamationTargets
    $matched = if ($TargetTier -eq 'All') {
        $targets
    } else {
        $targets | Where-Object { $_.Tier -eq $TargetTier }
    }

    $scanResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalReclaimableMB = 0.0

    foreach ($t in $matched) {
        $sizeMB = 0.0
        $count = 0
        $status = "Not Found"

        if ($t.CleanupType -eq 'CliOnly') {
            $cliCheck = Get-Command ($t.CliCommand.Split(' ')[0]) -ErrorAction SilentlyContinue
            if ($cliCheck) {
                $status = "Tool Present ($($t.CliCommand))"
            }
        } elseif (-not [string]::IsNullOrEmpty($t.Path)) {
            if (Test-Path -LiteralPath $t.Path) {
                $stats = Get-FolderStats -FolderPath $t.Path
                $sizeMB = $stats.SizeMB
                $count = $stats.Count
                $status = "Ready ($count files)"
                $totalReclaimableMB += $sizeMB
            }
        }

        $scanResults.Add([PSCustomObject]@{
            Tier        = $t.Tier
            Category    = $t.Category
            Target      = $t.Name
            SizeMB      = $sizeMB
            SizeGB      = [math]::Round(($sizeMB / 1024), 2)
            Count       = $count
            RiskProfile = $t.Risk
            Status      = $status
            Path        = if ($t.Path) { $t.Path } else { $t.CliCommand }
        })
    }

    $scanResults | Sort-Object SizeMB -Descending | Format-Table -Property Tier, Category, Target, SizeMB, SizeGB, Count, RiskProfile -AutoSize

    Write-Section "RECLAMATION SUMMARY"
    Write-Host ("Total Reclaimable Space on C: : {0:N2} MB (~{1:N2} GB)" -f $totalReclaimableMB, ($totalReclaimableMB / 1024)) -ForegroundColor Green
    Write-Info "Note: Running in SCAN mode does not delete any files."
    Write-Info "To safely reclaim these files, run: .\Invoke-DiskReclaim.ps1 -Mode Clean -Tier $TargetTier"
}

# ==============================================================================
# SUB-ROUTINE: EXECUTE CLEANUP
# ==============================================================================
function Invoke-DiskClean {
    param([string]$TargetTier, [bool]$Confirmed)

    Write-Header "DRIVE C: DISK CLEANUP & RECLAMATION"
    Write-Warn "Action Target Tier: $TargetTier"

    $targets = Get-ReclamationTargets
    $matched = if ($TargetTier -eq 'All') {
        $targets
    } else {
        $targets | Where-Object { $_.Tier -eq $TargetTier }
    }

    $totalReclaimedMB = 0.0
    $totalDeletedFiles = 0
    $totalSkippedFiles = 0

    foreach ($t in $matched) {
        Write-Host ""
        Write-Host ("[*] Processing: {0} [{1}]" -f $t.Name, $t.Risk) -ForegroundColor Cyan
        Write-Info $t.Description

        if ($t.CleanupType -eq 'FolderContents' -or $t.CleanupType -eq 'CommandOrFolder') {
            if (-not [string]::IsNullOrEmpty($t.Path) -and (Test-Path -LiteralPath $t.Path)) {
                $before = Get-FolderStats $t.Path
                if ($before.Count -eq 0 -and $before.SizeMB -eq 0) {
                    Write-Info "Already clean (0 MB)."
                    continue
                }

                # Attempt tool command first if specified and available
                if ($t.CleanupType -eq 'CommandOrFolder' -and $t.CliCommand) {
                    $cmdBin = $t.CliCommand.Split(' ')[0]
                    if (Get-Command $cmdBin -ErrorAction SilentlyContinue) {
                        Write-Info "Executing native CLI: $($t.CliCommand)..."
                        try {
                            Invoke-Expression $t.CliCommand | Out-Null
                        } catch {
                            Write-Warn "Native CLI execution returned non-zero, falling back to direct safe purge."
                        }
                    }
                }

                $res = Clear-DirectorySafely -FolderPath $t.Path -MinAgeHours $t.MinAgeHours
                $totalReclaimedMB += $res.ReclaimedMB
                $totalDeletedFiles += $res.DeletedCount
                $totalSkippedFiles += $res.SkippedCount

                Write-Success ("Reclaimed: {0:N2} MB across {1} files (Skipped {2} locked/active files)" -f $res.ReclaimedMB, $res.DeletedCount, $res.SkippedCount)
            } else {
                Write-Info "Directory not present or already removed."
            }
        } elseif ($t.CleanupType -eq 'CliOnly' -and $t.CliCommand) {
            $cmdBin = $t.CliCommand.Split(' ')[0]
            if (Get-Command $cmdBin -ErrorAction SilentlyContinue) {
                Write-Info "Executing CLI prune: $($t.CliCommand)..."
                try {
                    Invoke-Expression $t.CliCommand | Out-Host
                    Write-Success "Prune command completed."
                } catch {
                    Write-Warn "Prune command failed: $_"
                }
            } else {
                Write-Info "Tool '$cmdBin' is not installed or not in PATH. Skipping."
            }
        }
    }

    Write-Section "CLEANUP COMPLETE"
    Write-Host ("Reclaimed Total       : {0:N2} MB (~{1:N2} GB)" -f $totalReclaimedMB, ($totalReclaimedMB / 1024)) -ForegroundColor Green
    Write-Host ("Files Deleted         : $totalDeletedFiles") -ForegroundColor White
    Write-Host ("Files Safely Preserved: $totalSkippedFiles (active/in-use locks)") -ForegroundColor Gray

    # Refresh Drive C: free space
    $cDrive = Get-PSDrive -Name C -ErrorAction SilentlyContinue
    if ($cDrive) {
        Write-Host ("Drive C: Current Free : {0:N2} GB (of {1:N2} GB)" -f ($cDrive.Free / 1GB), (($cDrive.Used + $cDrive.Free) / 1GB)) -ForegroundColor Cyan
    }
}

# ==============================================================================
# SUB-ROUTINE: ACTIVE WORKFLOW & PROCESS DISK MONITOR
# ==============================================================================
function Invoke-ProcessDiskMonitor {
    param([int]$DurationSec)

    Write-Header "ACTIVE WORKFLOW & REAL-TIME DISK WRITE MONITOR"
    Write-Info "Analyzing active processes on this system to identify which workflows are burning disk space..."

    # Step 1: Cumulative I/O Lifetime snapshot via Win32_Process
    Write-Section "Top Processes by Cumulative Disk Writes (Lifetime of Process)"
    $wmiProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.WriteTransferCount -gt 20MB } |
                    Sort-Object WriteTransferCount -Descending |
                    Select-Object -First 15

    $cumulativeTable = foreach ($p in $wmiProcesses) {
        [PSCustomObject]@{
            PID         = $p.ProcessId
            Name        = $p.Name
            WriteMB     = [math]::Round(($p.WriteTransferCount / 1MB), 1)
            ReadMB      = [math]::Round(($p.ReadTransferCount / 1MB), 1)
            CommandLine = if ($p.CommandLine) {
                if ($p.CommandLine.Length -gt 65) { $p.CommandLine.Substring(0, 62) + '...' } else { $p.CommandLine }
            } else { '' }
        }
    }
    $cumulativeTable | Format-Table -AutoSize

    # Step 2: Real-time sampling to detect current write rate
    Write-Section ("Real-Time Disk Churn Sampling ({0} Second Window)..." -f $DurationSec)
    Write-Info "Sampling disk write velocity right now..."

    $sample1 = @{}
    Get-CimInstance Win32_Process | ForEach-Object {
        $sample1[$_.ProcessId] = [PSCustomObject]@{
            Name  = $_.Name
            Bytes = [int64]$_.WriteTransferCount
        }
    }

    Start-Sleep -Seconds $DurationSec

    $sample2 = @{}
    Get-CimInstance Win32_Process | ForEach-Object {
        $sample2[$_.ProcessId] = [PSCustomObject]@{
            Name  = $_.Name
            Bytes = [int64]$_.WriteTransferCount
        }
    }

    $deltas = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pidKey in $sample2.Keys) {
        if ($sample1.ContainsKey($pidKey)) {
            $diffBytes = $sample2[$pidKey].Bytes - $sample1[$pidKey].Bytes
            if ($diffBytes -gt 100KB) {
                $writeMBps = [math]::Round(($diffBytes / 1MB) / $DurationSec, 2)
                $deltas.Add([PSCustomObject]@{
                    PID         = $pidKey
                    ProcessName = $sample2[$pidKey].Name
                    DeltaMB     = [math]::Round(($diffBytes / 1MB), 2)
                    RateMB_s    = $writeMBps
                })
            }
        }
    }

    if ($deltas.Count -gt 0) {
        Write-Host "Active processes generating disk writes during the sample window:" -ForegroundColor Yellow
        $deltas | Sort-Object DeltaMB -Descending | Select-Object -First 12 | Format-Table -AutoSize
    } else {
        Write-Info "Disk write activity is currently quiet (< 100KB during window)."
    }
}

# ==============================================================================
# SUB-ROUTINE: SESSION CHURN & RECENT LARGE FILE HUNTER
# ==============================================================================
function Invoke-FindSessionChurn {
    param([int]$Hours, [int]$MinMB)

    Write-Header ("SESSION CHURN HUNTER: RECENT LARGE FILES ON DRIVE C:")
    Write-Info ("Looking back {0} hours for files >= {1} MB across user & dev session spaces..." -f $Hours, $MinMB)

    $cutoff = (Get-Date).AddHours(-$Hours)
    $minBytes = [int64]$MinMB * 1MB

    # Target high-velocity session directories on Drive C:
    $scanRoots = @(
        [System.IO.Path]::GetTempPath().TrimEnd('\'),
        'C:\Windows\Temp',
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:LOCALAPPDATA 'CrashDumps')
    )

    $results = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $stack = [System.Collections.Generic.Stack[string]]::new()
    foreach ($r in $scanRoots) {
        if (Test-Path -LiteralPath $r) {
            $stack.Push($r)
        }
    }

    $skipDirs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    @('.git', 'node_modules', '.venv', 'venv', 'site-packages', 'target', '.vs', 'brain') | ForEach-Object { [void]$skipDirs.Add($_) }

    while ($stack.Count -gt 0) {
        $curr = $stack.Pop()
        try {
            $di = [System.IO.DirectoryInfo]::new($curr)
            foreach ($sub in $di.EnumerateDirectories()) {
                if (-not $skipDirs.Contains($sub.Name) -and -not ($sub.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint))) {
                    $stack.Push($sub.FullName)
                }
            }
            foreach ($fi in $di.EnumerateFiles()) {
                if ($fi.Length -ge $minBytes -and $fi.LastWriteTime -ge $cutoff) {
                    $results.Add($fi)
                }
            }
        } catch {}
    }

    $displayList = foreach ($fi in $results) {
        $ext = $fi.Extension.ToLower()
        $isLikelyEphemeral = ($ext -in @('.tmp', '.log', '.dmp', '.tar', '.gz', '.zip', '.iso', '.exe', '.msi', '.cache', '.vhd', '.vhdx', '.bin'))

        [PSCustomObject]@{
            FileName     = $fi.Name
            SizeMB       = [math]::Round(($fi.Length / 1MB), 1)
            AgeHours     = [math]::Round(((Get-Date) - $fi.LastWriteTime).TotalHours, 1)
            LastModified = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
            Nature       = if ($isLikelyEphemeral) { 'Ephemeral (Stale / Dump / Cache)' } else { 'User / Project File' }
            Directory    = $fi.DirectoryName
            FullName     = $fi.FullName
        }
    }

    if ($displayList.Count -gt 0) {
        $displayList | Sort-Object SizeMB -Descending | Format-Table -Property SizeMB, Nature, AgeHours, LastModified, FileName, Directory -AutoSize
        Write-Host ""
        Write-Warn "Review above items: Ephemeral items (.tmp, .dmp, installers, archives) in Temp or Downloads can usually be purged safely."
    } else {
        Write-Success "No files exceeding $MinMB MB created in the last $Hours hours in monitored paths."
    }
}

# ==============================================================================
# MAIN ENTRY POINT DISPATCHER
# ==============================================================================
switch ($Mode) {
    'Scan' {
        Invoke-DiskScan -TargetTier $Tier
    }
    'Clean' {
        Invoke-DiskClean -TargetTier $Tier -Confirmed $Force
    }
    'Monitor' {
        Invoke-ProcessDiskMonitor -DurationSec $MonitorDurationSec
    }
    'FindChurn' {
        Invoke-FindSessionChurn -Hours $ChurnHours -MinMB $ChurnMinMB
    }
    'All' {
        Invoke-DiskScan -TargetTier $Tier
        Invoke-ProcessDiskMonitor -DurationSec $MonitorDurationSec
        Invoke-FindSessionChurn -Hours $ChurnHours -MinMB $ChurnMinMB
    }
}
