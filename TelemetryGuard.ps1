<#
.SYNOPSIS
  TelemetryGuard - re-applies telemetry hardening after Windows updates.
  Runs at logon via a scheduled task (highest privileges, hidden).
  Silent when the system is clean; re-applies without prompting when
  Windows Update has re-enabled telemetry.
#>

$ErrorActionPreference = 'SilentlyContinue'
$guardDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logFile  = Join-Path $guardDir 'TelemetryGuard.log'

function Write-Guard { param([string]$Msg)
    try { Add-Content -Path $logFile -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Msg) } catch {}
}

function Test-Admin {
    $i = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $i.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- drift checks (read-only) ----------------------------------------------
$diagKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
$diagTrack = Get-Service DiagTrack -EA SilentlyContinue
$allowTelemetry = (Get-ItemProperty $diagKey -Name AllowTelemetry -EA SilentlyContinue).AllowTelemetry

$autologgerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener'
$loggerStart = $null
if (Test-Path $autologgerKey) { $loggerStart = (Get-ItemProperty $autologgerKey -Name Start -EA SilentlyContinue).Start }

# Drift = telemetry policy reset, DiagTrack enabled, or autologger present AND enabled.
# (An absent autologger key means it was already killed by an earlier hardening - not drift.)
# Exit codes: 0 = clean or re-applied, 1 = drift found but could not fix it.
$drift = ($null -eq $allowTelemetry) -or ($allowTelemetry -ne 0) -or
         ($diagTrack -and $diagTrack.StartType -ne 'Disabled') -or
         ($null -ne $loggerStart -and $loggerStart -ne 0)

# --- per-user settings: always re-apply (no elevation needed) --------------
$hkcu = @(
    @{P='HKCU:\SOFTWARE\Microsoft\Siuf\Rules';                                                    N='NumberOfSIUFInPeriod'; V=0},
    @{P='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo';                       N='Enabled';               V=0},
    @{P='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent';                                N='DisableTailoredExperiencesWithDiagnosticData'; V=1},
    @{P='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent';                                N='DisableSoftLanding';    V=1}
)
foreach ($r in $hkcu) {
    if (-not (Test-Path $r.P)) { New-Item -Path $r.P -Force | Out-Null }
    Set-ItemProperty -Path $r.P -Name $r.N -Value $r.V -Type DWord
}

if (-not $drift) { exit 0 }   # clean -> stay silent

if (-not (Test-Admin)) {
    Write-Guard 'Drift detected but not elevated - scheduled task should handle this.'
    exit 1
}

Write-Guard 'Drift detected -> re-applying telemetry hardening.'

try {

# Registry policies
$reg = @(
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                                                  N='AllowTelemetry';                V=0},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                                                  N='DoNotShowFeedbackNotifications';V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                                                  N='DisableOneSettingsDownloads';   V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                                                  N='LimitDiagnosticLogCollection';  V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                                                  N='LimitDumpCollection';           V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                                                  N='AllowDeviceNameInTelemetry';    V=0},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows';                                                       N='CEIPEnable';                    V=0},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat';                                                       N='AITEnable';                     V=0},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat';                                                       N='DisableInventory';              V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat';                                                       N='DisableUAR';                    V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting';                                          N='Disabled';                     V=1},
    @{P='HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting';                                                   N='Disabled';                     V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent';                                                    N='DisableWindowsConsumerFeatures';V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent';                                                    N='DisableSoftLanding';            V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent';                                                    N='DisableCloudOptimizedContent';  V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent';                                                    N='DisableConsumerAccountStateContent'; V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI';                                                       N='DisableAIDataAnalysis';         V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice';                                                            N='AllowFindMyDevice';             V=0},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                                                  N='AllowCortana';                  V=0},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                                                  N='DisableWebSearch';              V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                                                  N='ConnectedSearchUseWeb';         V=0},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications';                                N='NoCloudApplicationNotification';V=1},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Dsh';                                                                     N='AllowNewsAndInterests';         V=0},
    @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer';                                                        N='HideRecommendedSection';        V=1},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener';                        N='Start';                        V=0},
    @{P='HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger';                                            N='Start';                        V=0}
)
foreach ($r in $reg) {
    if (-not (Test-Path $r.P)) { New-Item -Path $r.P -Force | Out-Null }
    Set-ItemProperty -Path $r.P -Name $r.N -Value $r.V -Type DWord
}

# Services
foreach ($s in 'DiagTrack','dmwappushservice') {
    $sv = Get-Service $s -EA SilentlyContinue
    if ($sv) {
        if ($sv.Status -eq 'Running') { Stop-Service $s -Force -EA SilentlyContinue }
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4
    }
}

# Scheduled tasks (the ones Windows Update re-enables)
$tasks = @(
    @{P='\Microsoft\Windows\Application Experience\';N='Microsoft Compatibility Appraiser'},
    @{P='\Microsoft\Windows\Application Experience\';N='ProgramDataUpdater'},
    @{P='\Microsoft\Windows\Customer Experience Improvement Program\';N='Consolidator'},
    @{P='\Microsoft\Windows\Customer Experience Improvement Program\';N='UsbCeip'},
    @{P='\Microsoft\Windows\Autochk\';N='Proxy'},
    @{P='\Microsoft\Windows\Windows Error Reporting\';N='QueueReporting'},
    @{P='\Microsoft\Windows\Feedback\Siuf\';N='DmClient'},
    @{P='\Microsoft\Windows\Feedback\Siuf\';N='DmClientOnScenarioDownload'}
)
foreach ($t in $tasks) {
    Get-ScheduledTask -TaskPath $t.P -TaskName $t.N -EA SilentlyContinue | Disable-ScheduledTask -EA SilentlyContinue | Out-Null
}

Get-ChildItem "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\*.etl" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
} catch {
    Write-Guard ("ERROR re-applying telemetry hardening: " + $_.Exception.Message)
    exit 1
}
# SilentlyContinue keeps this script quiet, but error records still collect in
# $Error - so a partially failed run is visible in the log instead of silent.
if ($Error.Count -gt 0) {
    Write-Guard "Finished with $($Error.Count) suppressed error(s); some settings may not exist on this build."
}
Write-Guard 'Telemetry hardening re-applied.'
exit 0