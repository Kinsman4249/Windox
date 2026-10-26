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
}
if (Test-Path $BackupFile) {
    try { $Backup = Get-Content $BackupFile -Raw | ConvertFrom-Json } catch { Write-Log "WARN: backup unreadable, starting fresh backup."; $Backup.Registry = @(); $Backup.Services = @(); $Backup.Tasks = @(); $Backup.Apps = @() }
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
    $asr = Get-MpPreference
    if ($null -eq $Backup.Defender) {
        $Backup.Defender = New-Object psobject -Property @{
            ASRIds    = @($asr.AttackSurfaceReductionRules_Ids)
            ASRAction = @($asr.AttackSurfaceReductionRules_Actions)
            CloudBlockLevel    = $asr.CloudBlockLevel
            CloudExtendedTimeout = $asr.CloudExtendedTimeout
            EnableNetworkProtection = $asr.EnableNetworkProtection
            PUAProtection      = $asr.PUAProtection
            SubmitSamplesConsent = $asr.SubmitSamplesConsent
        }
    }
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
