#requires -RunAsAdministrator
<#
.SYNOPSIS
  Windows hardening / debloat / telemetry-kill script.
  Tailored for Windows 10/11 Pro in hostile or enterprise environments.
  Keeps working: Microsoft Store, Quick Assist, Proton Drive, printing, VPN, Windows Update, Defender.
  Creates/uses HardenBackup.json in the script folder for full undo (Undo-Hardening.ps1).
  Installs TelemetryGuard.ps1 as an elevated scheduled task that runs at logon
  (re-applies telemetry hardening after Windows updates, only elevating when drift is detected).
  Asks for a one-time YES confirmation about the GPL-3 NO WARRANTY terms before
  changing anything; pass -NoConfirm for scripted installs.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Harden-Windows.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Harden-Windows.ps1 -NoConfirm -SkipAppx
#>

[CmdletBinding()]
param(
    [switch]$SkipServices,
    [switch]$SkipAppx,
    [switch]$SkipNetwork,
    [switch]$SkipCleanup,
    [switch]$NoConfirm   # skips the interactive safety confirmation (scripted installs)
)

# 'Continue' instead of 'SilentlyContinue': unexpected failures now print and
# land in the transcript instead of vanishing. Sites that are expected to be
# absent on some systems already pass -EA SilentlyContinue individually.
$ErrorActionPreference = 'Continue'
$Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackupFile = Join-Path $Root 'HardenBackup.json'

# ---------------------------------------------------------------- helpers
function Write-Log { param([string]$Msg) Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Msg) }

# ---------------------------------------------------------------- safety gate
# Runs interactively before anything is changed. Skippable with -NoConfirm
# for scripted installs; the README one-liner relies on this prompt.
if (-not $NoConfirm) {
    Write-Host 'Windox will now change Windows settings: telemetry, services, apps, network.' -ForegroundColor Yellow
    Write-Host 'Everything it changes is recorded in HardenBackup.json, and Undo-Hardening.ps1 can revert it.'
    Write-Host 'Windox ships under GPL-3 with NO WARRANTY: it is provided as-is, with no guarantee of'
    Write-Host 'correctness or fitness, and the authors are not liable for any damage. See the LICENSE file.'
    $answer = Read-Host 'Have you read the NO WARRANTY section, and do you want to continue? Type YES to proceed'
    if ($answer -cne 'YES') {
        Write-Host 'No confirmation received - nothing was changed. Exiting.'
        exit 1
    }
}

# ---------------------------------------------------------------- transcript
# Captures every log line and error record for troubleshooting. Share this
# file when reporting a problem.
$LogPath = Join-Path $Root ('Harden-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
try { Start-Transcript -Path $LogPath -Force | Out-Null } catch { $LogPath = $null; Write-Log 'WARN: could not start transcript logging.' }
Write-Log '== Windox hardening starting =='

# Backup container ---------------------------------------------------------
$Backup = [ordered]@{
    Metadata   = @{ Created = (Get-Date -Format o); Computer = $env:COMPUTERNAME }
    Registry   = @()
    Services   = @()
    Tasks      = @()
    Apps       = @()
    Firewall   = $null
    Defender   = $null
    ExecutionPol = $null
    AuditPolFile = $null
    SecPolFile   = $null
    PSv2         = $null
    PSOpLogSize  = $null
    TranscriptionDirCreated = $false
    GuestEnabled = $null
    FirewallLog  = @{}
}
if (Test-Path $BackupFile) {
    try { $Backup = Get-Content $BackupFile -Raw | ConvertFrom-Json } catch { Write-Log "WARN: backup unreadable, starting fresh backup."; $Backup.Registry = @(); $Backup.Services = @(); $Backup.Tasks = @(); $Backup.Apps = @() }
    foreach ($f in @('AuditPolFile','SecPolFile','PSv2','PSOpLogSize','TranscriptionDirCreated','GuestEnabled','FirewallLog')) {
        if ($null -eq $Backup.$f) { $Backup | Add-Member -NotePropertyName $f -NotePropertyValue ($(if ($f -eq 'TranscriptionDirCreated') { $false } elseif ($f -eq 'FirewallLog') { @{} } else { $null })) -Force }
    }
}
function Save-Backup {
    $json = ConvertTo-Json -InputObject ([pscustomobject]$Backup) -Depth 6
    [System.IO.File]::WriteAllText($BackupFile, $json)
}

function Test-BackupHasReg { param($Hive,$Path,$Name)
    foreach ($e in @($Backup.Registry)) {
        if ($e.Hive -eq $Hive -and $e.Path -eq $Path -and $e.Name -eq $Name) { return $true }
    }
    return $false
}

# Records the ORIGINAL value (only on first run) then writes the hardened value.
function Set-Reg {
    param([string]$Hive,[string]$Path,[string]$Name,$Value,[string]$Type='DWord')
    $key = $null
    if ($Hive -eq 'HKLM') { $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($Path) }
    else                  { $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($Path) }
    if (-not $key) { Write-Log "  SKIP reg $Hive\$Path\$Name"; return }
    $exists = $key.GetValueNames() -contains $Name
    if (-not (Test-BackupHasReg -Hive $Hive -Path $Path -Name $Name)) {
        $entry = [ordered]@{ Hive=$Hive; Path=$Path; Name=$Name; Existed=$exists }
        if ($exists) {
            $entry.Type  = [string]$key.GetValueKind($Name)
            $entry.Data  = $key.GetValue($Name)
        }
        $Backup.Registry += (New-Object psobject -Property $entry)
    }
    $key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]$Type)
    $key.Close()
}

function Disable-ServiceSafe {
    param([Parameter(Mandatory)][string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    $already = @($Backup.Services) | Where-Object { $_.Name -eq $Name }
    if (-not $already) {
        $Backup.Services += (New-Object psobject -Property @{ Name=$Name; Start=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -EA SilentlyContinue).Start })
    }
    if ($svc.Status -eq 'Running') { Stop-Service -Name $Name -Force -WarningAction SilentlyContinue }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -Value 4
    Write-Log "  service disabled: $Name"
}

# Disables a per-user (suffixed) service family: the template key and every live instance (_xxxx).
function Disable-ServiceFamily {
    param([Parameter(Mandatory)][string]$Base)
    Disable-ServiceSafe $Base
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like "$Base`_*" } | ForEach-Object {
            $inst = $_.PSChildName
            $already = @($Backup.Services) | Where-Object { $_.Name -eq $inst }
            if (-not $already) {
                $Backup.Services += (New-Object psobject -Property @{ Name=$inst; Start=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$inst" -Name Start -EA SilentlyContinue).Start })
            }
            Stop-Service -Name $inst -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$inst" -Name Start -Value 4
            Write-Log "  service disabled: $inst"
        }
}

# Reclassifies a service from Automatic to Manual (on-demand) without breaking function.
function Set-ServiceManualSafe {
    param([Parameter(Mandatory)][string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.StartType -eq 'Manual') { return }
    $already = @($Backup.Services) | Where-Object { $_.Name -eq $Name }
    if (-not $already) {
        $Backup.Services += (New-Object psobject -Property @{ Name=$Name; Start=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -EA SilentlyContinue).Start })
    }
    if ($svc.Status -eq 'Running') { Stop-Service -Name $Name -Force -WarningAction SilentlyContinue }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -Value 3
    Write-Log "  service set to Manual: $Name"
}

# Captures the current Defender state exactly once (used by the network section
# and the defense-in-depth section) so undo can restore it fully.
function Backup-DefenderState {
    if ($null -ne $Backup.Defender) { return }
    $asr = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $asr) { return }
    $Backup.Defender = New-Object psobject -Property @{
        ASRIds    = @($asr.AttackSurfaceReductionRules_Ids)
        ASRAction = @($asr.AttackSurfaceReductionRules_Actions)
        CloudBlockLevel    = $asr.CloudBlockLevel
        CloudExtendedTimeout = $asr.CloudExtendedTimeout
        EnableNetworkProtection = $asr.EnableNetworkProtection
        PUAProtection      = $asr.PUAProtection
        SubmitSamplesConsent = $asr.SubmitSamplesConsent
        CFA = $asr.EnableControlledFolderAccess
        CFAApps = @($asr.ControlledFolderAccessAllowedApplications)
        ScanAvgCPULoadFactor = $asr.ScanAvgCPULoadFactor
        EnableLowCpuPriority = $asr.EnableLowCpuPriority
        CheckForSignaturesBeforeRunningScan = $asr.CheckForSignaturesBeforeRunningScan
    }
}

# Removes anonymous named-pipe/share lists entirely (an absent list is a blank
# list). Only backs up the value when it exists, so undo restores exactly.
function Clear-NullSessionList {
    param([Parameter(Mandatory)][string]$Name)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', $true)
    if (-not $key) { return }
    $exists = $key.GetValueNames() -contains $Name
    if ($exists) {
        if (-not (Test-BackupHasReg -Hive 'HKLM' -Path 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name $Name)) {
            $entry = [ordered]@{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name=$Name; Existed=$true; Type=[string]$key.GetValueKind($Name); Data=$key.GetValue($Name) }
            $Backup.Registry += (New-Object psobject -Property $entry)
        }
        $key.DeleteValue($Name)
        Write-Log "  cleared anonymous $Name"
    }
    $key.Close()
}

# ---------------------------------------------------------------- 1. telemetry
Write-Log '== 1. Telemetry =='

# HKLM policy keys (the ones Windows Update resets -- guarded by TelemetryGuard)
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DoNotShowFeedbackNotifications' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableOneSettingsDownloads' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDiagnosticLogCollection' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDumpCollection' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowDeviceNameInTelemetry' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\SQMClient\Windows' 'CEIPEnable' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'AITEnable' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableInventory' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\AppCompat' 'DisableUAR' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableSoftLanding' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableCloudOptimizedContent' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerAccountStateContent' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\FindMyDevice' 'AllowFindMyDevice' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Edge' 'DiagnosticData' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Edge' 'PersonalizationReportingEnabled' 0

# DiagTrack autologger (re-created by updates -> also re-applied by TelemetryGuard)
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' 'Start' 0
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger' 'Start' 0
Get-ChildItem "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\*.etl" -EA SilentlyContinue | Remove-Item -Force

# Per-user privacy
Set-Reg HKCU 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableSoftLanding' 1
Set-Reg HKCU 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableTailoredExperiencesWithDiagnosticData' 1
Set-Reg HKCU 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsSpotlightFeatures' 1
Set-Reg HKCU 'SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 0
Set-Reg HKCU 'SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' 'DisabledByGroupPolicy' 1
Set-Reg HKCU 'SOFTWARE\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 1
Set-Reg HKCU 'SOFTWARE\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 1
Set-Reg HKCU 'SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' 'HarvestContacts' 0
Set-Reg HKCU 'SOFTWARE\Microsoft\Personalization\Settings' 'AcceptedPrivacyPolicy' 0
Set-Reg HKCU 'SOFTWARE\Microsoft\Siuf\Rules' 'NumberOfSIUFInPeriod' 0
Set-Reg HKCU 'SOFTWARE\Microsoft\Siuf\Rules' 'PeriodInNanoSeconds' 0
Set-Reg HKCU 'SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 1
Set-Reg HKCU 'SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 1
Set-Reg HKCU 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' 0

# Content delivery / tips / suggested apps
$cdm = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
foreach ($v in 'SilentInstalledAppsEnabled','OemPreInstalledAppsEnabled','PreInstalledAppsEnabled','SoftLandingEnabled','SystemPaneSuggestionsEnabled','RotatingLockScreenOverlayEnabled','ContentDeliveryAllowed','FeatureManagementEnabled','PreInstalledAppsEverEnabled','SubscribedContentEnabled','SubscribedContent-310093Enabled','SubscribedContent-338387Enabled','SubscribedContent-338388Enabled','SubscribedContent-338393Enabled','SubscribedContent-353694Enabled','SubscribedContent-353696Enabled','SubscribedContent-353698Enabled') {
    Set-Reg HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $v 0
}

# Microsoft "manage connections to Microsoft services" registry cutoffs
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowCortana' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'AllowSearchToUseLocation' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'DisableWebSearch' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' 'ConnectedSearchUseWeb' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Device Metadata' 'PreventDeviceMetadataFromNetwork' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\System' 'EnableFontProviders' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' 'AllowBuildPreview' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' 'NoCloudApplicationNotification' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows Mail' 'ManualLaunchAllowed' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' 'NoActiveProbe' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' 'DisablePassivePolling' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\SettingSync' 'DisableSettingSync' 2
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\SettingSync' 'DisableSettingSyncUserOverride' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\System' 'AllowCrossDeviceClipboard' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Dsh' 'AllowNewsAndInterests' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Explorer' 'HideRecommendedSection' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' 'LetAppsActivateWithVoiceAboveLock' 2
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' 'DODownloadMode' 0
# Teredo off (preserve other IPv6 component bits)
$teredo = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents -EA SilentlyContinue).DisabledComponents
if ($null -eq $teredo) { $teredo = 0 }
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents' ($teredo -bor 0x20)

# Error reporting + services
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\Windows Error Reporting' 'Disabled' 1
Disable-ServiceSafe 'DiagTrack'
Disable-ServiceSafe 'dmwappushservice'
Disable-ServiceSafe 'WerSvc'

# Telemetry scheduled tasks
$tasks = @(
    @{P='\Microsoft\Windows\Application Experience\';N='Microsoft Compatibility Appraiser'},
    @{P='\Microsoft\Windows\Application Experience\';N='ProgramDataUpdater'},
    @{P='\Microsoft\Windows\Application Experience\';N='PcaPatchDbTask'},
    @{P='\Microsoft\Windows\Application Experience\';N='SdbinstMergeDbTask'},
    @{P='\Microsoft\Windows\Customer Experience Improvement Program\';N='Consolidator'},
    @{P='\Microsoft\Windows\Customer Experience Improvement Program\';N='UsbCeip'},
    @{P='\Microsoft\Windows\Customer Experience Improvement Program\';N='Sqm-Tasks'},
    @{P='\Microsoft\Windows\Autochk\';N='Proxy'},
    @{P='\Microsoft\Windows\Windows Error Reporting\';N='QueueReporting'},
    @{P='\Microsoft\Windows\DiskDiagnostic\';N='Microsoft-Windows-DiskDiagnosticDataCollector'},
    @{P='\Microsoft\Windows\Maps\';N='MapsToastTask'},
    @{P='\Microsoft\Windows\Maps\';N='MapsUpdateTask'},
    @{P='\Microsoft\Windows\Feedback\Siuf\';N='DmClient'},
    @{P='\Microsoft\Windows\Feedback\Siuf\';N='DmClientOnScenarioDownload'},
    @{P='\Microsoft\Windows\Application Experience\';N='Microsoft Compatibility Appraiser'}
)
foreach ($t in $tasks) {
    $o = Get-ScheduledTask -TaskPath $t.P -TaskName $t.N -EA SilentlyContinue | Select-Object -First 1
    if ($o) {
        if (-not (@($Backup.Tasks) | Where-Object { $_.Path -eq $t.P -and $_.Name -eq $t.N })) {
            $Backup.Tasks += (New-Object psobject -Property @{ Path=$t.P; Name=$t.N; State=$o.State })
        }
        Disable-ScheduledTask -TaskPath $t.P -TaskName $t.N | Out-Null
        Write-Log "  task disabled: $($t.N)"
    }
}

# ---------------------------------------------------------------- 2. bloat services
if (-not $SkipServices) {
    Write-Log '== 2. Disabling non-essential consumer services =='
    # HARD PROTECTIONS - never touched, always stay available:
    #   WHfB/Windows Hello stack: NgcSvc, NgcCtnrSvc, WbioSrvc, KeyIso, VaultSvc
    #   Store stack: InstallService, wlidsvc, ClipSVC, TokenBroker, AppXSvc, camsvc, DoSvc(->manual)
    #   Networking/core: BFE, Dhcp, Dnscache, nsi, netprofm, RpcSs, EventSystem, gpsvc, SENS, Schedule
    #   Print stack: Spooler, PrintWorkflowUserSvc_*;  Defender: WinDefend, WdNisSvc, SecurityHealthService, webthreatdef*
    $svcList = 'MapsBroker','WMPNetworkSvc','lfsvc','RetailDemo','SharedAccess','PhoneSvc','TapiSrv',
               'XblAuthManager','XblGameSave','XboxNetApiSvc','XboxGipSvc','SEMgrSvc','wisvc',
               'TrkWks','SysMain','WpcMonSvc','SSDPSRV','upnphost','WinRM','SmsRouter','WalletService',
               'MessagingService','PimIndexMaintenanceSvc','PcaSvc',
               'whesvc','WSAIFabricSvc','InventorySvc','SensorService','wcncsvc','lmhosts','LicenseManager'
    foreach ($s in $svcList) { Disable-ServiceSafe $s }
    # Per-user service families (disable template + live _xxxx instances)
    foreach ($f in 'MessagingService','PimIndexMaintenanceSvc','cbdhsvc','DevicesFlowUserSvc','CloudBackupRestoreSvc') {
        Disable-ServiceFamily $f
    }
    # Delivery Optimization: keep functional, but on-demand only (Store still triggers it)
    Set-ServiceManualSafe 'DoSvc'
}

# ---------------------------------------------------------------- 3. appx bloat
if (-not $SkipAppx) {
    Write-Log '== 3. Removing consumer app bundles (Store / Quick Assist / Proton / media kept) =='
    $kill = @(
        'Microsoft.BingNews','Microsoft.BingSearch','Microsoft.BingWeather','Microsoft.BingFinance',
        'Microsoft.GamingApp','Microsoft.GetHelp','Microsoft.Getstarted','Microsoft.Todos',
        'Microsoft.PowerAutomateDesktop','Microsoft.WidgetsPlatformRuntime','Microsoft.WindowsFeedbackHub',
        'Microsoft.Windows.DevHome','Microsoft.Xbox.TCUI','Microsoft.XboxGameCallableUI',
        'Microsoft.XboxGamingOverlay','Microsoft.XboxIdentityProvider','Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.YourPhone','Clipchamp.Clipchamp','Microsoft.MicrosoftSolitaireCollection',
        'Microsoft.WindowsPhone','Microsoft.3DBuilder','Microsoft.Microsoft3DViewer',
        'Microsoft.ConnectedWidgetsPlatformRuntime','Microsoft.Copilot'
    )
    # hard protections: never touch these
    $protect = 'QuickAssist','WindowsStore','StorePurchaseApp','DesktopAppInstaller','SecHealthUI','ProtonDrive','NotepadPlusPlus'
    foreach ($name in $kill) {
        if ($protect | Where-Object { $name -like "*$_*" }) { continue }
        $pkgs = Get-AppxPackage -Name $name -AllUsers
        foreach ($p in $pkgs) {
            if (-not (@($Backup.Apps) | Where-Object { $_.FullName -eq $p.PackageFullName })) {
                $Backup.Apps += (New-Object psobject -Property @{ Name=$name; FullName=$p.PackageFullName; Loc=$p.InstallLocation })
            }
            Remove-AppxPackage -Package $p.PackageFullName -AllUsers | Out-Null
            Write-Log "  removed appx: $name"
        }
        $prov = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $name
        foreach ($pp in $prov) { Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction SilentlyContinue | Out-Null }
    }
}

# ---------------------------------------------------------------- 4. network hardening
if (-not $SkipNetwork) {
    Write-Log '== 4. Network hardening =='
    # SMBv1 off (WannaCry / EternalBlue family)
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Set-SmbServerConfiguration -EnableSMB2Protocol $true  -Force
    # LLMNR off (poisoning/relay attacks)
    Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0
    # mDNS off (CIS 18.6.4.1) - the third name-resolution poison vector after LLMNR/NetBIOS
    Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMDNS' 0
    # NetBIOS over TCP off on all interfaces
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object {
        $sub = $_.Name -replace '^HKEY_LOCAL_MACHINE\\',''
        Set-Reg HKLM $sub 'NetbiosOptions' 2
    }
    # Disable admin/default shares (hostile-network best practice)
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks' 0
    # Disable WPAD
    Set-Reg HKCU 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' 'WpadOverride' 1
    # Disable insecure TLS protocols
    foreach ($proto in 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1') {
        foreach ($side in 'Client','Server') {
            Set-Reg HKLM "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\$side" 'Enabled' 0
            Set-Reg HKLM "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\$side" 'DisabledByDefault' 1
        }
    }
    # Credential / auth hardening
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'UseLogonCredential' 0
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
    Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2
    Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorUser' 0
    # Disable Remote Assistance pointer (does NOT affect Quick Assist)
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0
    # RDP: disable if enabled
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
    # Firewall: default-deny inbound
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    # Defender: MS-baseline cloud/PUA/network settings + full ASR set
    Backup-DefenderState
    $asr = Get-MpPreference
    # id -> action: 1 = block, 2 = audit
    $asrMap = [ordered]@{
        '7674ba52-37eb-4664-abf5-4c0f867f5ccc' = 1  # Office child processes
        'd4f940ab-401b-4efc-aadc-ad5f3c729774' = 1  # Office macro Win32 API
        'a8f58c8b-6a40-4566-a874-9c99a1a43a53' = 1  # Office code injection
        '3b576869-a4ec-4529-8536-b80a7769e899' = 1  # Office executable content
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 1  # Office loader validation
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 1  # email exploit
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 1  # JS/VBS downloader
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 1  # obfuscated code
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 1  # LSASS credential access
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 1  # ransomware
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 1  # USB untrusted process
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 1  # Adobe Reader child proc
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 2  # PSExec/WMI (audit, MS baseline)
    }
    $ids = @(); $acts = @()
    foreach ($id in ($asrMap.Keys + @($asr.AttackSurfaceReductionRules_Ids | ForEach-Object { "$_".Trim('{}') }) | Sort-Object -Unique)) {
        $ids += $id
        if ($asrMap.Contains($id)) { $acts += $asrMap[$id] } else { $acts += 1 }
    }
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $acts
    Set-MpPreference -CloudBlockLevel High
    Set-MpPreference -CloudExtendedTimeout 50
    Set-MpPreference -EnableNetworkProtection Enabled
    Set-MpPreference -PUAProtection Enabled
    # PowerShell hardening
    $Backup.ExecutionPol = (Get-ExecutionPolicy -Scope LocalMachine)
    Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force
    Set-Reg HKLM 'SOFTWARE\Microsoft\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
    Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'EnableBalloonTips' 0
    [Environment]::SetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT','1','Machine')
    Write-Log '  network + auth hardening applied'
}

# ---------------------------------------------------------------- 4b. Microsoft Intune MDM security baseline equivalents
Write-Log '== 4b. Intune security baseline (local equivalents) =='
# MS Security Guide
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' 0   # UAC restrict local accounts on network logon
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*' 'DisableExceptionChainValidation' 0  # SEHOP
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting' 2
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting' 2
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 0
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NoNameReleaseOnDemand' 1
# Hardened UNC paths (SYSVOL/NETLOGON tamper protection)
$hup = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths')
if (-not (Test-BackupHasReg -Hive 'HKLM' -Path 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL')) { $Backup.Registry += (New-Object psobject -Property @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; Name='\\*\SYSVOL'; Existed=($null -ne $hup.GetValue('\\*\SYSVOL')) }) }
$hup.SetValue('\\*\SYSVOL','RequireMutualAuthentication=1,RequireIntegrity=1',[Microsoft.Win32.RegistryValueKind]::String)
if (-not (Test-BackupHasReg -Hive 'HKLM' -Path 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON')) { $Backup.Registry += (New-Object psobject -Property @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; Name='\\*\NETLOGON'; Existed=($null -ne $hup.GetValue('\\*\NETLOGON')) }) }
$hup.SetValue('\\*\NETLOGON','RequireMutualAuthentication=1,RequireIntegrity=1',[Microsoft.Win32.RegistryValueKind]::String)
$hup.Close()
# SMB hardening (client + server)
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
# NTLM minimum session security: require NTLMv2 + 128-bit
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'NtlmMinClientSec' 537395200
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'NtlmMinServerSec' 537395200
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictRemoteSAM' 'O:BAG:BAD:(A;;RC;;;BA)' -Type String
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows NT\Rpc' 'RestrictRemoteClients' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'DisablePasswordSaving' 1
# CredSSP encryption oracle remediation
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' 'ProtectionLevel' 2
# WinRM policies (service stays disabled)
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowBasic' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowUnencryptedTraffic' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowDigest' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic' 0
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'DisableRunAs' 1
# Audit: process creation with command line
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
# Event log minimum sizes
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' 'MaxSize' 32768
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\EventLog\System' 'MaxSize' 32768
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' 'MaxSize' 196608
# Early launch antimalware: good, unknown and bad but critical
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch' 'DriverLoadPolicy' 3
# Printers: admin-only driver installs, Redirection Guard, no HTTP print drivers
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'RestrictDriverInstallationToAdministrators' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'RedirectionGuard' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows NT\Printers' 'DisableHTTPPrinting' 1
# Autoplay / AutoRun off
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255
# Credential UI: do not enumerate admin accounts on elevation
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnumerateAdministrators' 0
# Lock screen camera + slideshow
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenCamera' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Personalization' 'NoLockScreenSlideshow' 1
# SmartScreen: warn and prevent bypass
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Block' -Type String
# Block SBP-2 (IEEE 1394 storage) device class - exfiltration vector
$di = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions')
if (-not (Test-BackupHasReg -Hive 'HKLM' -Path 'SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' -Name 'DenyDeviceClasses')) {
    $Backup.Registry += (New-Object psobject -Property @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'; Name='DenyDeviceClasses'; Existed=($null -ne $di.GetValue('DenyDeviceClasses')) })
}
$di.SetValue('DenyDeviceClasses',1,[Microsoft.Win32.RegistryValueKind]::DWord)
$di.SetValue('DenyDeviceClassesRetroactive',1,[Microsoft.Win32.RegistryValueKind]::DWord)
$di.SetValue('DenyDeviceClassesList',@('{d48179be-ec20-11d1-b6b8-00c04fa372a7}'),[Microsoft.Win32.RegistryValueKind]::MultiString)
$di.Close()
# Sudo disabled (Win11 24H2+)
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\Sudo' 'Enabled' 0
# Machine inactivity limit: lock after 15 min idle
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs' 900
Write-Log '  baseline settings applied'

# ---------------------------------------------------------------- 4c. defense-in-depth (CIS / ACSC / NSA / STIG)
Write-Log '== 4c. Defense-in-depth (CIS / ACSC / NSA / STIG) =='

# --- PowerShell deep logging (NSA/CISA "Keeping PowerShell" 2022, CCCS ITSP.70.012,
#     CIS 18.10.88) - logging only; does not restrict the local admin's shell. ---
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1
$ml = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames')
if (-not (Test-BackupHasReg -Hive 'HKLM' -Path 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*')) {
    $Backup.Registry += (New-Object psobject -Property @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name='*'; Existed=($null -ne $ml.GetValue('*')) })
}
$ml.SetValue('*', '*', [Microsoft.Win32.RegistryValueKind]::String)
$ml.Close()
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 1
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableInvocationHeader' 1
$transDir = 'C:\Windows\Logs\PSTranscripts'
if (-not (Test-Path $transDir)) {
    New-Item -ItemType Directory -Path $transDir -Force | Out-Null
    icacls $transDir /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
    $Backup.TranscriptionDirCreated = $true
}
Set-Reg HKLM 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory' $transDir -Type String
Write-Log '  PowerShell module logging + transcription enabled (transcripts: C:\Windows\Logs\PSTranscripts)'

# PowerShell v2 engine: deprecated, unneeded, and a favorite attack surface (NSA/CISA; STIG).
$psv2 = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -EA SilentlyContinue
if ($psv2 -and $psv2.State -ne 'Disabled') {
    if ($null -eq $Backup.PSv2) { $Backup.PSv2 = $psv2.State }
    Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart | Out-Null
    Write-Log '  PowerShell v2 engine disabled'
}
# PowerShell Operational log: sized for the new logging (NSA/CISA).
$psLogSize = (wevtutil gl 'Microsoft-Windows-PowerShell/Operational' 2>$null | Select-String 'maxSize:\s+(\d+)').Matches.Groups[1].Value
if ($psLogSize) {
    if ($null -eq $Backup.PSOpLogSize) { $Backup.PSOpLogSize = $psLogSize }
    wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:104857600 | Out-Null
    Write-Log '  PowerShell Operational log sized to 100 MB'
}

# --- Exploit Protection system defaults (MITRE M1050, ACSC, CCCS ITSP.70.012) ---
# Safe system-wide set only; the app-breaking mitigations (BlockNonMicrosoftBinaries,
# DisableNonSystemFonts, DisableWin32kSystemCalls, EAF) are deliberately not set.
foreach ($epPath in @('SYSTEM\CurrentControlSet\Control\Session Manager\kernel','SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*')) {
    $epKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($epPath, $true)
    if (-not $epKey) { continue }
    if (-not (Test-BackupHasReg -Hive 'HKLM' -Path $epPath -Name 'MitigationOptions')) {
        $epExisted = $null -ne $epKey.GetValue('MitigationOptions')
        $epEntry = [ordered]@{ Hive='HKLM'; Path=$epPath; Name='MitigationOptions'; Existed=$epExisted }
        if ($epExisted) { $epEntry.Type = [string]$epKey.GetValueKind('MitigationOptions'); $epEntry.Data = $epKey.GetValue('MitigationOptions') }
        $Backup.Registry += (New-Object psobject -Property $epEntry)
    }
    $epKey.Close()
}
if (Get-Command Set-ProcessMitigation -EA SilentlyContinue) {
    Set-ProcessMitigation -System -Enable DEP,EmulateAtlThunks,SEHOP,ForceRelocateImages,BottomUp,HighEntropy,StrictHandle,CFG,DisableExtensionPoints
    Write-Log '  Exploit Protection system defaults applied (DEP, SEHOP, CFG, ASLR, handle validation)'
} else {
    Write-Log '  WARN: Set-ProcessMitigation unavailable - Exploit Protection skipped'
}

# --- Controlled Folder Access (ACSC, CIS Defender benchmark, vendor ransomware guidance) ---
# PowerShell/pwsh are allow-listed so the local admin's scripts can still write
# to protected folders; every other untrusted write is blocked.
Backup-DefenderState
$cfaAllow = @("$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe")
$pwshSrc = (Get-Command pwsh.exe -EA SilentlyContinue).Source
if ($pwshSrc) { $cfaAllow += $pwshSrc }
if (Get-Command Set-MpPreference -EA SilentlyContinue) {
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled
        Set-MpPreference -ControlledFolderAccessAllowedApplications $cfaAllow
        Write-Log '  Controlled Folder Access: Block mode (powershell/pwsh allow-listed)'
    } catch { Write-Log ("  WARN: Controlled Folder Access could not be enabled: " + $_.Exception.Message) }
    # Scheduled-scan optimization (MS Set-MpPreference docs): keep scans out of the way.
    try { Set-MpPreference -ScanAvgCPULoadFactor 30 } catch {}
    try { Set-MpPreference -EnableLowCpuPriority $true } catch {}
    try { Set-MpPreference -CheckForSignaturesBeforeRunningScan $true } catch {}
}
# Tamper Protection + real-time status: report, because Tamper Protection can
# silently reject local changes to cloud-delivered protection settings.
$mpStat = Get-MpComputerStatus -EA SilentlyContinue
if ($mpStat) {
    $tpVal = $null
    if ($null -ne $mpStat.IsTamperProtected) { $tpVal = $mpStat.IsTamperProtected }
    elseif ($null -ne $mpStat.TamperProtection) { $tpVal = ($mpStat.TamperProtection -match 'On|Enabled') }
    if ($tpVal -eq $true) {
        Write-Log '  Tamper Protection: ON (if any Set-MpPreference call reported an error, verify the affected value in Windows Security)'
    } elseif ($tpVal -eq $false) {
        Write-Log '  WARN: Tamper Protection is OFF - enable it in Windows Security > Virus & threat protection > Settings'
    }
    if (-not $mpStat.RealTimeProtectionEnabled) { Write-Log '  WARN: Defender real-time protection is OFF' }
}

# --- Credential hardening (CIS 2.3.x, DISA STIG WN11-SO-*) ---
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'DisableDomainCreds' 1            # no stored network credentials
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1         # blank passwords only at the console
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictNullSessAccess' 1        # no anonymous named-pipe/share access
Clear-NullSessionList 'NullSessionPipes'
Clear-NullSessionList 'NullSessionShares'
Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 1  # DLL hijack hardening
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLastUserName' 1
Set-Reg HKLM 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon' '0' -Type String

# Guest account disabled (CIS 2.3.1.1; STIG WN11-SO-000010)
if (Get-Command Get-LocalUser -EA SilentlyContinue) {
    $guestAcct = Get-LocalUser -Name 'Guest' -EA SilentlyContinue
    if ($guestAcct) {
        if ($null -eq $Backup.GuestEnabled) { $Backup.GuestEnabled = $guestAcct.Enabled }
        if ($guestAcct.Enabled) {
            Disable-LocalUser -Name 'Guest'
            Write-Log '  Guest account disabled'
        }
    }
}

# --- Account lockout (ACSC high priority; CIS 1.2.x) ---
$secPolFile = Join-Path $Root 'SecPolBackup.inf'
if (-not (Test-Path $secPolFile)) {
    secedit /export /cfg $secPolFile /areas SECURITYPOLICY | Out-Null
    if (Test-Path $secPolFile) { if ($null -eq $Backup.SecPolFile) { $Backup.SecPolFile = $secPolFile } }
    else { Write-Log '  WARN: could not export security policy - account lockout NOT applied' }
}
if (Test-Path $secPolFile) {
    net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null
    Write-Log '  account lockout: 5 invalid attempts, 15 min reset (ACSC / CIS 1.2.x)'
}

# --- Advanced audit policy (CIS 17.x, DISA STIG WN11-AU-*) ---
$auditPolFile = Join-Path $Root 'AuditPolBackup.pol'
if (-not (Test-Path $auditPolFile)) {
    auditpol /backup /file:$auditPolFile | Out-Null
    if (Test-Path $auditPolFile) { if ($null -eq $Backup.AuditPolFile) { $Backup.AuditPolFile = $auditPolFile } }
    else { Write-Log '  WARN: could not back up audit policy - audit subcategories NOT set' }
}
if (Test-Path $auditPolFile) {
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
    $auditOnBoth = @('Logon','Credential Validation','User Account Management','Other System Events','System Integrity','Removable Storage')
    $auditSuccess = @('Logoff','Process Creation','Audit Policy Change','Security State Change','Special Logon')
    $auditFailures = 0
    foreach ($c in $auditOnBoth) { auditpol /set /subcategory:$c /success:enable /failure:enable  | Out-Null; if ($LASTEXITCODE -ne 0) { $auditFailures++ } }
    foreach ($c in $auditSuccess) { auditpol /set /subcategory:$c /success:enable /failure:disable | Out-Null; if ($LASTEXITCODE -ne 0) { $auditFailures++ } }
    auditpol /set /subcategory:'Account Lockout' /success:disable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { $auditFailures++ }
    if ($auditFailures -eq 0) { Write-Log '  audit policy: key subcategories enabled (logon, credential validation, policy change, integrity)' }
    else { Write-Log "  WARN: $auditFailures auditpol call(s) failed - check transcript" }
}

# --- Firewall logging (CIS 9.x; SANS) ---
$fwProfiles = Get-NetFirewallProfile -Profile Domain,Public,Private -EA SilentlyContinue
if ($fwProfiles -and $Backup.FirewallLog -is [System.Collections.IDictionary] -and $Backup.FirewallLog.Count -eq 0) {
    foreach ($p in $fwProfiles) {
        $Backup.FirewallLog[$p.Name] = [ordered]@{ LogBlocked=$p.LogBlocked; LogAllowed=$p.LogAllowed; LogMaxSizeKilobytes=$p.LogMaxSizeKilobytes }
    }
}
Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 16384 -EA SilentlyContinue
Write-Log '  firewall logging enabled (blocked + allowed connections, 16 MB log)'

# --- VBS / Memory Integrity / Credential Guard (ACSC, NSA, CIS 18.9.5.x, STIG) ---
# Requires CPU virtualization, TPM and Secure Boot; becomes active after the
# next reboot. UEFI-locked per ACSC, so disablement needs the Core isolation UI.
$vbsOk = $false
try {
    $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $tpmInfo = Get-Tpm -ErrorAction SilentlyContinue
    $sbInfo  = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($cpuInfo.VirtualizationFirmwareEnabled -and $tpmInfo.TpmPresent -and $sbInfo) { $vbsOk = $true }
    else { Write-Log ("  SKIP VBS: hardware missing (cpu-virt=" + $cpuInfo.VirtualizationFirmwareEnabled + " tpm=" + $tpmInfo.TpmPresent + " secureboot=" + $sbInfo + ")") }
} catch { Write-Log '  SKIP VBS: could not verify hardware support' }
if ($vbsOk) {
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 1
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\DeviceGuard' 'RequirePlatformSecurityFeatures' 1
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\DeviceGuard' 'Locked' 1
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled' 1
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' 'Enabled' 1
    Set-Reg HKLM 'SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 1
    Write-Log '  VBS + Memory Integrity + Credential Guard enabled (UEFI-locked; active after reboot)'
    Write-Log '  NOTE: check Windows Security > Device security after reboot for incompatible drivers'
}
Write-Log '  defense-in-depth settings applied'

# ---------------------------------------------------------------- 5. file cleanup
if (-not $SkipCleanup) {
    Write-Log '== 5. Cleaning junk files =='
    foreach ($f in @("$env:TEMP\*",'C:\Windows\Temp\*','C:\Windows\Prefetch\*')) {
        Remove-Item -Path $f -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -EA SilentlyContinue
    Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue
    # Windows.old / update leftovers logged but NOT auto-deleted (user safety)
    foreach ($f in @('C:\Windows.old','C:\$WinREAgent')) {
        if (Test-Path $f) { Write-Log "  NOTE: large leftover found (not deleted): $f" }
    }
}

# ---------------------------------------------------------------- 6. TelemetryGuard as a scheduled task
Write-Log '== 6. Installing TelemetryGuard (scheduled task) =='
# Copy guard into place (outside any synced/script folder so it survives updates)
$guardSrc = Join-Path $Root 'TelemetryGuard.ps1'
$guardDir = Join-Path $env:LOCALAPPDATA 'TelemetryGuard'
$guardDst = Join-Path $guardDir 'TelemetryGuard.ps1'
if (Test-Path $guardSrc) {
    try {
        $ErrorActionPreference = 'Stop'
        New-Item -ItemType Directory -Path $guardDir -Force | Out-Null
        Copy-Item $guardSrc $guardDst -Force
        $ErrorActionPreference = 'Continue'
    } catch {
        $ErrorActionPreference = 'Continue'
        Write-Log ("WARN: could not install TelemetryGuard files: " + $_.Exception.Message)
    }
} else {
    Write-Log 'WARN: TelemetryGuard.ps1 not found next to this script - guard will not be installed.'
}

# Remove the old broken Startup-folder entry (shortcut + unassociated .ps1/.log)
# (the guard itself runs as a scheduled task; the Startup shortcut was legacy)
$startup = [Environment]::GetFolderPath('Startup')
foreach ($f in 'TelemetryGuard.lnk','TelemetryGuard.ps1','TelemetryGuard.log') {
    Remove-Item (Join-Path $startup $f) -Force -ErrorAction SilentlyContinue
}

# Register an elevated, hidden, at-logon task (no UAC prompt, no Notepad issue)
try {
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $guardDst + '"'
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName 'TelemetryGuard' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null
    Write-Log "  TelemetryGuard task registered: $guardDst"
} catch {
    Write-Log ("ERROR: TelemetryGuard task registration FAILED: " + $_.Exception.Message)
    Write-Log 'Windows Update will be able to re-enable telemetry until this task is registered. Re-run Harden-Windows.ps1.'
    exit 1
}

# ---------------------------------------------------------------- done
try {
    $ErrorActionPreference = 'Stop'
    Save-Backup
    Write-Log '== Hardening complete. Backup saved to HardenBackup.json =='
    Write-Log '== Run Undo-Hardening.ps1 (as admin) to fully revert. =='
    if ($Error.Count -gt 0 -and $LogPath) {
        Write-Log "NOTE: $($Error.Count) error record(s) were logged during this run - review $LogPath"
    }
    Stop-Transcript
    exit 0
} catch {
    Write-Log ("FATAL: could not save HardenBackup.json - " + $_.Exception.Message)
    Write-Log 'Without that file Undo-Hardening.ps1 cannot revert. Do not reboot before fixing the problem.'
    Stop-Transcript
    exit 1
}
