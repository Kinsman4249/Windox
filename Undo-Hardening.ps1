#requires -RunAsAdministrator
<#
.SYNOPSIS
  Fully reverts Harden-Windows.ps1 using HardenBackup.json (same folder).
  Restores: registry values, services, scheduled tasks, removed Appx packages,
  Defender ASR rules, execution policy, firewall defaults, TelemetryGuard startup entry.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Undo-Hardening.ps1
#>

[CmdletBinding()]
param([switch]$KeepTelemetryGuard)

# 'Continue' instead of 'SilentlyContinue': unexpected failures print and land
# in the transcript instead of vanishing.
$ErrorActionPreference = 'Continue'
$Root       = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackupFile = Join-Path $Root 'HardenBackup.json'

if (-not (Test-Path $BackupFile)) { Write-Host "No HardenBackup.json found in $Root - nothing to undo."; exit 1 }
$Backup = Get-Content $BackupFile -Raw | ConvertFrom-Json
function Write-Log { param([string]$Msg) Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Msg) }

# Transcript: captures everything for troubleshooting; share it when reporting.
$LogPath = Join-Path $Root ('Undo-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
try { Start-Transcript -Path $LogPath -Force | Out-Null } catch { $LogPath = $null; Write-Log 'WARN: could not start transcript logging.' }
Write-Log '== Undo starting =='

# ---------------------------------------------------------------- registry
Write-Log '== Restoring registry values =='
foreach ($e in @($Backup.Registry)) {
    if (-not $e) { continue }
    $fullPath = if ($e.Hive -eq 'HKLM') { "HKLM:\$($e.Path)" } else { "HKCU:\$($e.Path)" }
    if ($e.Existed) {
        Set-ItemProperty -Path $fullPath -Name $e.Name -Value $e.Data -Type $e.Type
    } else {
        Remove-ItemProperty -Path $fullPath -Name $e.Name -EA SilentlyContinue
    }
}

# ---------------------------------------------------------------- services
Write-Log '== Restoring services =='
foreach ($s in @($Backup.Services)) {
    if (-not $s) { continue }
    if ($null -ne $s.Start) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" -Name Start -Value $s.Start
        Write-Log "  service restored: $($s.Name) (Start=$($s.Start))"
    }
}

# ---------------------------------------------------------------- tasks
Write-Log '== Restoring scheduled tasks =='
foreach ($t in @($Backup.Tasks)) {
    if (-not $t) { continue }
    if ($t.State -in @('Ready','Running','Queued')) {
        Enable-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -EA SilentlyContinue | Out-Null
        Write-Log "  task re-enabled: $($t.Name)"
    }
}

# ---------------------------------------------------------------- appx
Write-Log '== Re-registering removed Appx packages =='
foreach ($a in @($Backup.Apps)) {
    if (-not $a) { continue }
    if (Get-AppxPackage -Name $a.Name -EA SilentlyContinue) { continue }
    $manifest = Join-Path $a.Loc 'AppxManifest.xml'
    if ($a.Loc -and (Test-Path $manifest)) {
        Add-AppxPackage -Register $manifest -DisableDevelopmentMode -EA SilentlyContinue
        if ($?) { Write-Log "  re-registered: $($a.Name)"; continue }
    }
    Write-Log "  NOT restored (reinstall from Store): $($a.Name)"
}

# ---------------------------------------------------------------- defender ASR
if ($Backup.Defender) {
    Write-Log '== Restoring Defender ASR + cloud settings =='
    $oldIds = @($Backup.Defender.ASRIds); $oldActs = @($Backup.Defender.ASRAction)
    if ($oldIds.Count -gt 0 -and $oldIds[0]) {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $oldIds -AttackSurfaceReductionRules_Actions $oldActs
    } else {
        Set-MpPreference -AttackSurfaceReductionRules_Ids @() -AttackSurfaceReductionRules_Actions @()
    }
    # Restore simple scalar Defender settings to baseline defaults
    if (Get-Command Set-MpPreference -EA SilentlyContinue) {
        $cbl  = if ($null -ne $Backup.Defender.CloudBlockLevel)       { $Backup.Defender.CloudBlockLevel }       else { 0 }
        $cet  = if ($null -ne $Backup.Defender.CloudExtendedTimeout)  { $Backup.Defender.CloudExtendedTimeout }  else { 0 }
        $enp  = if ($null -ne $Backup.Defender.EnableNetworkProtection) { $Backup.Defender.EnableNetworkProtection } else { 0 }
        $pua  = if ($null -ne $Backup.Defender.PUAProtection)         { $Backup.Defender.PUAProtection }         else { 0 }
        try { Set-MpPreference -CloudBlockLevel $cbl } catch {}
        try { Set-MpPreference -CloudExtendedTimeout $cet } catch {}
        try { Set-MpPreference -EnableNetworkProtection $enp } catch {}
        try { Set-MpPreference -PUAProtection $pua } catch {}
    }
}

# ---------------------------------------------------------------- exec policy
if ($null -ne $Backup.ExecutionPol -and $Backup.ExecutionPol -ne '') {
    Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy $Backup.ExecutionPol -Force
    Write-Log "Execution policy restored: $($Backup.ExecutionPol)"
}

# ---------------------------------------------------------------- firewall
Write-Log '== Restoring firewall defaults (allow inbound) =='
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow

# ---------------------------------------------------------------- misc
[Environment]::SetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT', $null, 'Machine')

if (-not $KeepTelemetryGuard) {
    Write-Log '== Removing TelemetryGuard (task + files) =='
    Unregister-ScheduledTask -TaskName 'TelemetryGuard' -Confirm:$false -EA SilentlyContinue
    Remove-Item (Join-Path $env:LOCALAPPDATA 'TelemetryGuard') -Recurse -Force -EA SilentlyContinue
    $startup = [Environment]::GetFolderPath('Startup')
    Remove-Item (Join-Path $startup 'TelemetryGuard.ps1') -Force -EA SilentlyContinue
    Remove-Item (Join-Path $startup 'TelemetryGuard.lnk') -Force -EA SilentlyContinue
    Remove-Item (Join-Path $startup 'TelemetryGuard.log') -Force -EA SilentlyContinue
}

# Rename the backup so a re-run of Harden starts a fresh baseline
try {
    $ErrorActionPreference = 'Stop'
    Move-Item $BackupFile (Join-Path $Root ('HardenBackup-undone-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')) -Force
    $ErrorActionPreference = 'Continue'
} catch {
    $ErrorActionPreference = 'Continue'
    Write-Log ("ERROR: could not rename HardenBackup.json (" + $_.Exception.Message + "). Rename it by hand before running Harden-Windows.ps1 again, or the old backup will be merged into the new one.")
}
Write-Log '== Undo complete. NOTE: provisioned-app changes for NEW user profiles are not reverted; run Windows Update + Store to refresh app provisioning if needed. =='
if ($Error.Count -gt 0 -and $LogPath) {
    Write-Log "NOTE: $($Error.Count) error record(s) were logged during this run - review $LogPath"
}
Stop-Transcript
exit 0
