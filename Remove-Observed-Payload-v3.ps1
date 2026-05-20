#requires -RunAsAdministrator
<#
.SYNOPSIS
    Targeted cleanup script for the observed Deno/JS payload incident.

.DESCRIPTION
    Scoped to the indicators found in this case:
      - Scheduled task: \ReaderUpdate
      - Registry Run value: 563ca209 (HKCU and HKLM)
      - Startup folder shortcut (if any)
      - Payload file: 563ca209.js under any user roaming profile
      - Dropper directory: yy.exe (containing Flu_X64.exe and companions)
      - Deno runtime installed via WinGet (DenoLand.Deno)
      - Optional MSI product name: gpt

    By default runs in audit-only mode and writes a report.
    Use -Remediate to actually remove artifacts.
    Use -RemoveDenoProduct to also uninstall the WinGet/MSI Deno package.

.PARAMETER Remediate
    If specified, actually removes artifacts. Default is audit-only.

.PARAMETER RemoveDenoProduct
    If specified, attempts to uninstall Deno via winget and MSI uninstall entries.

.PARAMETER PurgeTempArtifacts
    If $true (default), includes %TEMP%\s.msi in the cleanup scope.

.PARAMETER ScanBrowserArtifacts
    If $true (default), reports browser-related artifact locations for manual review.

.NOTES
    Review before use on any other system.
    v3 fixes: switch param defaults, RemoveDenoProduct wiring, hardcoded username,
              WinGet Deno removal, HKLM Run key check, Startup folder check,
              duplicate s.msi target, unapproved verb.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Remediate,
    [switch]$RemoveDenoProduct,

    # FIX: [switch] cannot have a $true default. Use [bool] for optional-with-default params.
    [bool]$PurgeTempArtifacts = $true,
    [bool]$ScanBrowserArtifacts = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$workDir = Join-Path $env:ProgramData "IR-Cleanup-$stamp"
$null    = New-Item -ItemType Directory -Path $workDir -Force

$transcript = Join-Path $workDir 'cleanup.transcript.txt'
$auditCsv   = Join-Path $workDir 'actions.csv'
$reportMd   = Join-Path $workDir 'cleanup-report.md'
$hashCsv    = Join-Path $workDir 'hashes.csv'

Start-Transcript -Path $transcript -Force | Out-Null

$actions = [System.Collections.Generic.List[object]]::new()
$hashes  = [System.Collections.Generic.List[object]]::new()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Add-Action {
    param(
        [string]$Type,
        [string]$Target,
        [string]$Status,
        [string]$Details = ''
    )
    $actions.Add([pscustomobject]@{
        Time    = (Get-Date).ToString('s')
        Type    = $Type
        Target  = $Target
        Status  = $Status
        Details = $Details
    }) | Out-Null
}

function Add-HashRecord {
    param(
        [string]$Path,
        [string]$Algorithm,
        [string]$HashValue
    )
    $hashes.Add([pscustomobject]@{
        Time      = (Get-Date).ToString('s')
        Path      = $Path
        Algorithm = $Algorithm
        Hash      = $HashValue
    }) | Out-Null
}

function Get-PathHash {
    param(
        [string]$Path,
        [string]$Algorithm = 'SHA256'
    )
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $h = Get-FileHash -LiteralPath $Path -Algorithm $Algorithm -ErrorAction Stop
            Add-HashRecord -Path $Path -Algorithm $Algorithm -HashValue $h.Hash
            return $h.Hash
        }
    } catch {
        Add-Action -Type 'Hash' -Target $Path -Status 'Failed' -Details $_.Exception.Message
    }
    return $null
}

function Remove-PathSafe {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        if (Test-Path -LiteralPath $Path) {
            if ($Remediate) {
                if ($PSCmdlet.ShouldProcess($Path, 'Remove-Item')) {
                    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
                    Add-Action -Type 'FileSystem' -Target $Path -Status 'Removed'
                }
            } else {
                Add-Action -Type 'FileSystem' -Target $Path -Status 'WouldRemove'
            }
        } else {
            Add-Action -Type 'FileSystem' -Target $Path -Status 'NotFound'
        }
    } catch {
        Add-Action -Type 'FileSystem' -Target $Path -Status 'Failed' -Details $_.Exception.Message
    }
}

function Stop-IOCProcess {
    param([System.Management.Automation.PSObject]$Proc)
    try {
        if ($Remediate) {
            if ($PSCmdlet.ShouldProcess("$($Proc.Name) [$($Proc.ProcessId)]", 'Stop-Process')) {
                Stop-Process -Id $Proc.ProcessId -Force -ErrorAction Stop
                Add-Action -Type 'Process' -Target "$($Proc.Name) [$($Proc.ProcessId)]" -Status 'Stopped' `
                    -Details ($Proc.CommandLine -as [string])
            }
        } else {
            Add-Action -Type 'Process' -Target "$($Proc.Name) [$($Proc.ProcessId)]" -Status 'WouldStop' `
                -Details ($Proc.CommandLine -as [string])
        }
    } catch {
        Add-Action -Type 'Process' -Target "$($Proc.Name) [$($Proc.ProcessId)]" -Status 'Failed' `
            -Details $_.Exception.Message
    }
}

function Remove-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            if ($Remediate) {
                if ($PSCmdlet.ShouldProcess("$Path\$Name", 'Remove-ItemProperty')) {
                    Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
                    Add-Action -Type 'Registry' -Target "$Path\$Name" -Status 'Removed'
                }
            } else {
                Add-Action -Type 'Registry' -Target "$Path\$Name" -Status 'WouldRemove'
            }
        } else {
            Add-Action -Type 'Registry' -Target "$Path\$Name" -Status 'NotFound'
        }
    } catch {
        Add-Action -Type 'Registry' -Target "$Path\$Name" -Status 'Failed' -Details $_.Exception.Message
    }
}

# FIX: Renamed from Scan- to Get- to use an approved PowerShell verb.
function Get-BrowserArtifacts {
    $roots = @(
        Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
        Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data'
        Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
    ) | Where-Object { Test-Path -LiteralPath $_ }

    foreach ($root in $roots) {
        try {
            Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Name -match '563ca209|NativeMessagingHosts|Extensions|Preferences|Secure Preferences|Login Data|Cookies'
                } |
                ForEach-Object {
                    Add-Action -Type 'BrowserArtifact' -Target $_.FullName -Status 'Found'
                }
        } catch {
            Add-Action -Type 'BrowserScan' -Target $root -Status 'Failed' -Details $_.Exception.Message
        }
    }
}

function Get-UninstallEntries {
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    }
}

function Uninstall-ByDisplayName {
    param([string]$DisplayNamePattern)
    try {
        $entries = Get-UninstallEntries | Where-Object {
            $_.DisplayName -and $_.DisplayName -match $DisplayNamePattern
        }

        foreach ($entry in $entries) {
            $display   = $entry.DisplayName
            $uninstall = $entry.UninstallString

            if ([string]::IsNullOrWhiteSpace($uninstall)) {
                Add-Action -Type 'MSI' -Target $display -Status 'Skipped' -Details 'No uninstall string found'
                continue
            }

            if ($Remediate) {
                if ($PSCmdlet.ShouldProcess($display, 'Uninstall')) {
                    try {
                        if ($uninstall -match 'msiexec(\.exe)?') {
                            $guid = $null
                            if ($entry.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') { $guid = $entry.PSChildName }
                            elseif ($uninstall -match '\{[0-9A-Fa-f-]+\}')       { $guid = $Matches[0] }

                            if ($guid) {
                                Start-Process -FilePath msiexec.exe -ArgumentList "/x $guid /qn /norestart" -Wait -WindowStyle Hidden
                            } else {
                                Start-Process -FilePath cmd.exe -ArgumentList "/c $uninstall /qn /norestart" -Wait -WindowStyle Hidden
                            }
                        } else {
                            Start-Process -FilePath cmd.exe -ArgumentList "/c $uninstall" -Wait -WindowStyle Hidden
                        }
                        Add-Action -Type 'MSI' -Target $display -Status 'Uninstalled'
                    } catch {
                        Add-Action -Type 'MSI' -Target $display -Status 'Failed' -Details $_.Exception.Message
                    }
                }
            } else {
                Add-Action -Type 'MSI' -Target $display -Status 'WouldUninstall'
            }
        }

        if (-not $entries) {
            Add-Action -Type 'MSI' -Target $DisplayNamePattern -Status 'NotFound'
        }
    } catch {
        Add-Action -Type 'MSI' -Target $DisplayNamePattern -Status 'Failed' -Details $_.Exception.Message
    }
}

# FIX: New function - remove Deno installed via WinGet.
function Remove-DenoWinGet {
    # Try winget uninstall first (cleanest method).
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        if ($Remediate) {
            if ($PSCmdlet.ShouldProcess('DenoLand.Deno (winget)', 'Uninstall')) {
                try {
                    $result = & winget uninstall --id DenoLand.Deno --silent --accept-source-agreements 2>&1
                    Add-Action -Type 'WinGet' -Target 'DenoLand.Deno' -Status 'Uninstalled' -Details ($result -join ' ')
                } catch {
                    Add-Action -Type 'WinGet' -Target 'DenoLand.Deno' -Status 'Failed' -Details $_.Exception.Message
                }
            }
        } else {
            Add-Action -Type 'WinGet' -Target 'DenoLand.Deno' -Status 'WouldUninstall'
        }
    } else {
        Add-Action -Type 'WinGet' -Target 'winget' -Status 'NotAvailable' -Details 'winget not found in PATH'
    }

    # Also remove the WinGet packages directory for Deno if it persists.
    $wingetPkgRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
    if (Test-Path -LiteralPath $wingetPkgRoot) {
        Get-ChildItem -LiteralPath $wingetPkgRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'DenoLand.Deno*' } |
            ForEach-Object {
                Get-PathHash -Path (Join-Path $_.FullName 'deno.exe') | Out-Null
                Remove-PathSafe -Path $_.FullName
            }
    }

    # Also try MSI uninstall entries (in case it registered one).
    Uninstall-ByDisplayName -DisplayNamePattern 'deno'
}

# ---------------------------------------------------------------------------
# Dynamic profile discovery
# FIX: Enumerate actual subdirectories under C:\Users instead of treating
#      C:\Users itself as a profile root (which causes overly broad recursive scans).
# ---------------------------------------------------------------------------
function Get-UserProfileRoots {
    $roots = [System.Collections.Generic.List[string]]::new()

    # Always include the current user's profile.
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE) -and (Test-Path -LiteralPath $env:USERPROFILE)) {
        $roots.Add($env:USERPROFILE) | Out-Null
    }

    # Enumerate all user profile directories from C:\Users.
    $usersDir = Join-Path $env:SystemDrive 'Users'
    if (Test-Path -LiteralPath $usersDir) {
        Get-ChildItem -LiteralPath $usersDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
            ForEach-Object {
                if ($roots -notcontains $_.FullName) {
                    $roots.Add($_.FullName) | Out-Null
                }
            }
    }

    return $roots | Select-Object -Unique
}

# ---------------------------------------------------------------------------
# STEP 1 – Terminate IOC-matching processes
# ---------------------------------------------------------------------------
Write-Host '[*] Collecting IOC-matching processes...'
$procMatches = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    ($_.CommandLine -and $_.CommandLine -match '563ca209|Flu_X64|yy\.exe|ReaderUpdate') -or
    ($_.Name -eq 'deno.exe' -and $_.CommandLine -match '563ca209|Flu_X64|yy\.exe')
}
foreach ($p in $procMatches) { Stop-IOCProcess -Proc $p }

# ---------------------------------------------------------------------------
# STEP 2 – Remove scheduled task persistence
# ---------------------------------------------------------------------------
Write-Host '[*] Removing scheduled task persistence...'
try {
    $task = Get-ScheduledTask -TaskName 'ReaderUpdate' -ErrorAction SilentlyContinue
    if ($task) {
        if ($Remediate) {
            if ($PSCmdlet.ShouldProcess('\ReaderUpdate', 'Unregister-ScheduledTask')) {
                Unregister-ScheduledTask -TaskName 'ReaderUpdate' -Confirm:$false -ErrorAction Stop
                Add-Action -Type 'ScheduledTask' -Target '\ReaderUpdate' -Status 'Removed'
            }
        } else {
            Add-Action -Type 'ScheduledTask' -Target '\ReaderUpdate' -Status 'WouldRemove'
        }
    } else {
        Add-Action -Type 'ScheduledTask' -Target '\ReaderUpdate' -Status 'NotFound'
    }
} catch {
    Add-Action -Type 'ScheduledTask' -Target '\ReaderUpdate' -Status 'Failed' -Details $_.Exception.Message
}

# ---------------------------------------------------------------------------
# STEP 3 – Remove registry Run persistence
# FIX: Also check HKLM Run key, not only HKCU.
# ---------------------------------------------------------------------------
Write-Host '[*] Removing registry Run persistence...'
$hkcuRun  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$hklmRun  = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$hklmRun6 = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'

Remove-RegistryValueSafe -Path $hkcuRun  -Name '563ca209'
Remove-RegistryValueSafe -Path $hklmRun  -Name '563ca209'
Remove-RegistryValueSafe -Path $hklmRun6 -Name '563ca209'

# ---------------------------------------------------------------------------
# STEP 4 – Check Startup folders (FIX: new coverage)
# ---------------------------------------------------------------------------
Write-Host '[*] Checking Startup folder for IOC shortcuts...'
$startupPaths = @(
    Join-Path $env:APPDATA  'Microsoft\Windows\Start Menu\Programs\Startup'
    Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
)
foreach ($startupDir in $startupPaths) {
    if (Test-Path -LiteralPath $startupDir) {
        Get-ChildItem -LiteralPath $startupDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '563ca209|Flu_X64|yy\.exe|ReaderUpdate|deno' } |
            ForEach-Object {
                Get-PathHash -Path $_.FullName | Out-Null
                Remove-PathSafe -Path $_.FullName
            }
    }
}

# ---------------------------------------------------------------------------
# STEP 5 – Hash and remove known payload files across all user profiles
# FIX: Uses proper per-profile enumeration; s.msi removed here only if
#      PurgeTempArtifacts is false (to avoid duplicate handling below).
# ---------------------------------------------------------------------------
Write-Host '[*] Hashing and removing known payload files...'

# FIX: s.msi removed from $knownNames — handled separately in Step 6 when
#      $PurgeTempArtifacts is $true, to avoid processing it twice.
$knownNames = @(
    '563ca209.js'
    'Flu_X64.exe'
    'GPUlib.dll'
    'HardwareLib.dll'
    'Quoquoobral.cm'
    'Register.dll'
    'Somveand.oid'
)

$profileRoots = Get-UserProfileRoots

foreach ($profileRoot in $profileRoots) {
    try {
        Get-ChildItem -LiteralPath $profileRoot -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object {
                $knownNames -contains $_.Name -or
                $_.FullName -match '\\yy\.exe(\\|$)' -or
                $_.Name -match '563ca209\.js'
            } |
            ForEach-Object {
                Get-PathHash -Path $_.FullName | Out-Null
                Remove-PathSafe -Path $_.FullName
            }
    } catch {
        Add-Action -Type 'FileSystemScan' -Target $profileRoot -Status 'Failed' -Details $_.Exception.Message
    }

    # FIX: Remove yy.exe dropper directory for each discovered profile (was hardcoded to "Home").
    $dropperDir = Join-Path $profileRoot 'yy.exe'
    if (Test-Path -LiteralPath $dropperDir) {
        Remove-PathSafe -Path $dropperDir
    }
}

# ---------------------------------------------------------------------------
# STEP 6 – Temp artifacts
# ---------------------------------------------------------------------------
if ($PurgeTempArtifacts) {
    Write-Host '[*] Checking temp artifacts...'
    $tempTargets = @(
        Join-Path $env:TEMP 's.msi'
    )
    foreach ($p in $tempTargets) {
        Get-PathHash -Path $p | Out-Null
        Remove-PathSafe -Path $p
    }
}

# ---------------------------------------------------------------------------
# STEP 7 – Browser artifact report
# ---------------------------------------------------------------------------
if ($ScanBrowserArtifacts) {
    Write-Host '[*] Scanning browser artifact locations...'
    Get-BrowserArtifacts  # FIX: renamed from Scan-BrowserArtifacts
}

# ---------------------------------------------------------------------------
# STEP 8 – MSI product "gpt" and optional Deno removal
# FIX: -RemoveDenoProduct now gates Deno removal correctly.
#      MSI "gpt" uninstall is separate from Deno and runs unconditionally.
# ---------------------------------------------------------------------------
Write-Host '[*] Checking for MSI product named "gpt"...'
Uninstall-ByDisplayName -DisplayNamePattern '^gpt$'

if ($RemoveDenoProduct) {
    Write-Host '[*] Removing Deno runtime (WinGet / MSI)...'
    Remove-DenoWinGet
} else {
    Add-Action -Type 'WinGet' -Target 'DenoLand.Deno' -Status 'Skipped' `
        -Details 'Pass -RemoveDenoProduct to attempt Deno uninstall'
}

# ---------------------------------------------------------------------------
# STEP 9 – Verify no IOC processes remain
# ---------------------------------------------------------------------------
Write-Host '[*] Verifying remaining IOC processes...'
$remaining = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    ($_.CommandLine -and $_.CommandLine -match '563ca209|Flu_X64|yy\.exe|ReaderUpdate') -or
    ($_.Name -eq 'deno.exe' -and $_.CommandLine -match '563ca209|Flu_X64|yy\.exe')
}

if ($remaining) {
    foreach ($r in $remaining) {
        Add-Action -Type 'Verification' -Target "$($r.Name) [$($r.ProcessId)]" -Status 'StillPresent' `
            -Details ($r.CommandLine -as [string])
    }
} else {
    Add-Action -Type 'Verification' -Target 'IOC process check' -Status 'Clear'
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
$actions | Export-Csv -NoTypeInformation -Path $auditCsv -Force
$hashes  | Export-Csv -NoTypeInformation -Path $hashCsv  -Force

$report = @"
# Incident Cleanup Report

Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Mode: $(if ($Remediate) { 'Remediation' } else { 'Audit-only' })
Remove Deno: $(if ($RemoveDenoProduct) { 'Yes' } else { 'No (pass -RemoveDenoProduct to enable)' })

## Scope
Targeted cleanup for the observed Deno/JavaScript payload incident.

## Observed Indicators
- Scheduled task ``\ReaderUpdate`` launching ``C:\Users\<profile>\yy.exe\Flu_X64.exe``
- Registry Run value ``563ca209`` (HKCU/HKLM) launching ``conhost.exe --headless`` -> ``deno.exe -A`` -> ``563ca209.js``
- Payload file ``563ca209.js`` under user roaming profile(s)
- Deno runtime installed via WinGet (``DenoLand.Deno``)
- Temporary MSI ``s.msi``
- Dropper directory ``yy.exe`` containing ``Flu_X64.exe`` and companion files

## Steps Performed
$(if ($Remediate) {
@"
- Stopped IOC-matching processes (deno.exe, Flu_X64, etc.)
- Removed scheduled task ``\ReaderUpdate``
- Removed Registry Run value ``563ca209`` from HKCU and HKLM
- Checked Startup folder for IOC-named items
- Removed known payload files and dropper directory across all user profiles
- Removed temporary MSI from %TEMP% (if PurgeTempArtifacts enabled)
- Attempted MSI cleanup for product ``gpt``
$(if ($RemoveDenoProduct) { '- Attempted Deno uninstall via WinGet and MSI' } else { '- Deno uninstall skipped (use -RemoveDenoProduct to enable)' })
"@
} else {
@"
- Audit-only mode: no changes were applied.
- All targeted IOCs were enumerated and logged as WouldRemove/WouldStop/WouldUninstall.
- Re-run with -Remediate to apply changes.
"@
})

## Verification
IOC process check performed against: 563ca209, Flu_X64, yy.exe, ReaderUpdate

## Recommended Follow-Up
- Rotate passwords and revoke active sessions for email, GitHub, and other sensitive accounts.
- Review browser extensions, native messaging hosts, and OAuth app access.
- Run Microsoft Defender Full Scan or Offline Scan.
- Review the generated CSV files in $workDir for a forensic trail.
"@

$report | Set-Content -Path $reportMd -Encoding UTF8

Write-Host '[+] Done.'
Write-Host "    Transcript : $transcript"
Write-Host "    Actions CSV: $auditCsv"
Write-Host "    Hashes CSV : $hashCsv"
Write-Host "    Report     : $reportMd"

Stop-Transcript | Out-Null
