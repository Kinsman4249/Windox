# References

Windox does not harden by habit. Every setting the scripts touch is here,
with the reason, the outside-Microsoft baseline that recommends it, and -
where we stopped short of a stronger measure - the project requirement that
blocked it.

This file is the companion to the scripts. If a change is not listed here,
it was not intended, and you should open an issue before trusting it.

## Project requirements (the constraints every decision must satisfy)

These are the limits the hardening has to fit inside. Whenever the table
below says "blocked by requirement", it means one of these:

- The local admin must still be able to run PowerShell interactively
  (unsigned and ad-hoc scripts included).
- The Microsoft Store must keep working.
- Quick Assist must keep working.
- Printing must keep working.
- VPNs must keep working.
- Windows Update must keep working.
- Windows Defender must keep working and stay in control.
- Proton Drive and Notepad++ are protected app surfaces (script comment).
- Everything Windox changes is backed up to `HardenBackup.json` and is
  fully reversible with `Undo-Hardening.ps1`.
- No telemetry, ever (CONTRIBUTING.md).
- Power-plan changes must go through the Windows 11 Settings UI. The legacy
  Control Panel power options are deprecated and Windox does not touch them.

## Sources consulted

| Source | What it is used for here |
| --- | --- |
| CIS Microsoft Windows 11 Enterprise Benchmark v5.1.0 / Windows 11 Stand-alone v5.0.0 | The main hardening checklist outside Microsoft; section numbers cited as 18.x / 2.3.x / 1.2.x / 9.x / 17.x |
| ACSC "Hardening Microsoft Windows 10 and Windows 11 Workstations" (Jul 2024) and "Hardening Microsoft Windows 11 workstations" (Sep 2025, Jan 2026) | Government hardening guide; the source for lockout, CFA, exploit protection, LSASS protection, VBS/Credential Guard |
| NSA/CISA "Keeping PowerShell: Security Measures to Use and Embrace" (Jun 2022) | PowerShell logging and PowerShell v2 removal |
| NSA/CISA "Top Ten Cybersecurity Misconfigurations" (AA23-278A, Oct 2023) | LLMNR/NetBIOS/mDNS, insecure SMB, unrestricted code execution |
| CCCS ITSP.70.012 "Guidance for Hardening Microsoft Windows 10 Enterprise" | Canadian baseline; PowerShell module logging, exploit protection, auditing |
| DISA Windows 11 STIG | US DoD baseline; rule IDs cited as WN11-SO-* / WN11-AU-* / WN11-CC-* where relevant |
| MITRE ATT&CK Mitigation M1050 | Exploit Protection as a defense-in-depth layer |
| Microsoft Defender Exploit Protection / Controlled Folder Access / Tamper Protection / Memory Integrity documentation | The exact cmdlets and registry values behind the Defender-focused settings |
| Microsoft Security Compliance Toolkit baselines | The Microsoft baseline Windox already implemented as section 4b |
| Vendor posture: CrowdStrike, SentinelOne, Sophos hardening and ransomware guidance; HotCakeX Harden-Windows-Security | Community and vendor consensus on the Defender-centric controls (ASR, CFA, VBS) |

URLs:

- https://www.cisecurity.org/cis-benchmarks
- https://learn.cisecurity.org/benchmarks
- https://ncp.nist.gov/checklist/1184 (CIS Windows 11 Enterprise)
- https://ncp.nist.gov/checklist/1186 (CIS Windows 11 Stand-alone)
- https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/system-hardening/hardening-microsoft-windows-11-workstations
- https://media.defense.gov/2022/Jun/22/2003016731/-1/-1/0/CSI_KEEPING_POWER_SHELL_SECURITY_MEASURES_TO_USE_AND_EMBRACE_20220622.PDF
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a
- https://www.cyber.gc.ca/en/guidance/hardening-microsoft-windows-10-enterprise
- https://attack.mitre.org/mitigations/M1050/
- https://learn.microsoft.com/en-us/defender-endpoint/enable-exploit-protection
- https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/controlled-folders-antivirus
- https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/prevent-changes-to-security-settings-with-tamper-protection
- https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard
- https://aka.ms/securitybaselines
- https://github.com/HotCakeX/Harden-Windows-Security

## How to read the tables

Each section mirrors a section of `Harden-Windows.ps1`. "Key" columns list
registry paths under `HKLM\` (or `HKCU\` where noted) with the value name.
"Value" is what Windox writes. "Why" is the threat or behavior being
addressed. "Source" names the baseline behind it. Every value is backed up
on first run and restored by `Undo-Hardening.ps1`.

---

## Section 1 - Telemetry

Goal: stop Windows, Edge, and the bundled services from phoning home, while
leaving the update pipeline and Defender alone.

### 1.1 Diagnostic data policies (HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection)

| Key | Value | Why |
| --- | --- | --- |
| AllowTelemetry | 0 | Security-level diagnostic data: no telemetry to Microsoft. Source: CIS; STIG WN11-CC-000205 |
| DoNotShowFeedbackNotifications | 1 | No feedback prompts that double as engagement telemetry. Source: CIS |
| DisableOneSettingsDownloads | 1 | Prevents download of settings content that reports device state. Source: CIS |
| LimitDiagnosticLogCollection | 1 | Caps the diagnostic logs Windows collects. Source: CIS |
| LimitDumpCollection | 1 | Caps crash/minidump upload. Source: CIS |
| AllowDeviceNameInTelemetry | 0 | Keeps the device name out of telemetry. Source: CIS |

These are the values Windows Update and feature updates reset most often,
which is why `TelemetryGuard.ps1` re-applies them at logon.

### 1.2 Error reporting, app compat, and SQM (HKLM\SOFTWARE\...)

| Key | Value | Why |
| --- | --- | --- |
| SOFTWARE\Policies\Microsoft\SQMClient\Windows\CEIPEnable | 0 | Turns off the Customer Experience Improvement Program. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\AppCompat\AITEnable | 0 | Disables Application Impact Telemetry. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableInventory | 1 | No app-compat inventory uploads. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableUAR | 1 | Disables User Action Reporting. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Disabled | 1 | WER off. Source: CIS |
| SOFTWARE\Microsoft\Windows\Windows Error Reporting\Disabled | 1 | Same, non-policy copy that some builds read. Source: CIS |

### 1.3 Cloud content and consumer features (HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent)

| Key | Value | Why |
| --- | --- | --- |
| DisableWindowsConsumerFeatures | 1 | Kills consumer-feature cloud content (suggestions, ads). Source: CIS |
| DisableSoftLanding | 1 | No sponsored "soft landing" content. Source: CIS |
| DisableCloudOptimizedContent | 1 | No cloud-optimized content delivery. Source: CIS |
| DisableConsumerAccountStateContent | 1 | No account-state driven content. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis | 1 | Stops AI features sending data for model training. Source: CIS (Windows AI) |
| SOFTWARE\Policies\Microsoft\FindMyDevice\AllowFindMyDevice | 0 | Device location tracking off. Source: CIS |
| SOFTWARE\Policies\Microsoft\Edge\DiagnosticData | 0 | Edge sends no diagnostic data. Source: CIS |
| SOFTWARE\Policies\Microsoft\Edge\PersonalizationReportingEnabled | 0 | Edge personalization reporting off. Source: CIS |

### 1.4 DiagTrack autologgers (HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger)

| Key | Value | Why |
| --- | --- | --- |
| AutoLogger-Diagtrack-Listener\Start | 0 | Stops the DiagTrack kernel autologger. Source: CIS |
| SQMLogger\Start | 0 | Stops the SQM autologger. Source: CIS |

Plus deletion of `C:\ProgramData\Microsoft\Diagnosis\ETLLogs\*.etl` to drop
already-collected traces. Windows Update recreates the autologgers; the guard
re-disables them.

### 1.5 Per-user privacy (HKCU)

| Key | Value | Why |
| --- | --- | --- |
| HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableSoftLanding | 1 | Same as 1.3, user scope. Source: CIS |
| HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableTailoredExperiencesWithDiagnosticData | 1 | Stops personalized ads driven by diagnostics. Source: CIS |
| HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsSpotlightFeatures | 1 | Stops Spotlight cloud content. Source: CIS |
| HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo\Enabled | 0 | Advertising ID off. Source: CIS |
| HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy | 1 | Advertising ID locked off. Source: CIS |
| HKCU\SOFTWARE\Microsoft\InputPersonalization\RestrictImplicitInkCollection | 1 | No handwriting data collection. Source: CIS |
| HKCU\SOFTWARE\Microsoft\InputPersonalization\RestrictImplicitTextCollection | 1 | No typing data collection. Source: CIS |
| HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore\HarvestContacts | 0 | No contact harvesting for the input model. Source: CIS |
| HKCU\SOFTWARE\Microsoft\Personalization\Settings\AcceptedPrivacyPolicy | 0 | Declines the personalization privacy policy. Source: CIS |
| HKCU\SOFTWARE\Microsoft\Siuf\Rules\NumberOfSIUFInPeriod | 0 | No Silent Inactivity Upload Feedback. Source: CIS |
| HKCU\SOFTWARE\Microsoft\Siuf\Rules\PeriodInNanoSeconds | 0 | Same, period zeroed. Source: CIS |
| HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer\DisableSearchBoxSuggestions | 1 | No search-box web suggestions. Source: CIS |
| HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot | 1 | Copilot off (privacy + AI telemetry). Source: CIS |
| HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis | 1 | User-scope AI data analysis off. Source: CIS |

### 1.6 Activity and connectivity (HKLM)

| Key | Value | Why |
| --- | --- | --- |
| SOFTWARE\Policies\Microsoft\Windows\System\PublishUserActivities | 0 | Stops publishing activity to the cloud. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\System\UploadUserActivities | 0 | Stops activity upload. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\System\EnableActivityFeed | 0 | Disables the activity feed. Source: CIS |

### 1.7 ContentDeliveryManager (HKCU)

All of `SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager`:
SilentInstalledAppsEnabled, OemPreInstalledAppsEnabled, PreInstalledAppsEnabled,
SoftLandingEnabled, SystemPaneSuggestionsEnabled, RotatingLockScreenOverlayEnabled,
ContentDeliveryAllowed, FeatureManagementEnabled, PreInstalledAppsEverEnabled,
SubscribedContentEnabled, and the SubscribedContent-3xxxxxxx toggles -> all 0.

Why: every one of these installs, suggests, or rotates sponsored content and
reports back. Source: CIS.

### 1.8 Search, metadata, and misc connectivity cutoffs (HKLM)

| Key | Value | Why |
| --- | --- | --- |
| SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortana | 0 | Cortana off (voice/telemetry surface). Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowSearchToUseLocation | 0 | Search location off. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\Windows Search\DisableWebSearch | 1 | No web results in local search. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\Windows Search\ConnectedSearchUseWeb | 0 | No connected search. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork | 1 | No device metadata downloads. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\System\EnableFontProviders | 0 | No remote font providers. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview | 0 | No Insider preview builds. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoCloudApplicationNotification | 1 | No cloud notification routing. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows Mail\ManualLaunchAllowed | 0 | Mail not auto-launched. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\NoActiveProbe | 1 | No active NCSI probes to Microsoft. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\DisablePassivePolling | 1 | No passive NCSI polling. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC | 1 | OneDrive sync client off. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\SettingSync\DisableSettingSync | 2 | Settings not synced to the account. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\SettingSync\DisableSettingSyncUserOverride | 1 | And the user cannot re-enable it. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\System\AllowCrossDeviceClipboard | 0 | Cloud clipboard off. Source: CIS |
| SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests | 0 | News and Interests (widgets content) off. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\Explorer\HideRecommendedSection | 1 | No recommended apps in Start. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR | 0 | Game DVR (background recording + telemetry) off. Source: CIS |
| SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\LetAppsActivateWithVoiceAboveLock | 2 | No voice activation above the lock screen. Source: CIS |
| SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\DODownloadMode | 0 | Delivery Optimization off (no P2P uploads). Source: CIS |
| SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents (set bit 0x20) | - | Teredo off; other IPv6 components preserved. Source: CIS |

### 1.9 Telemetry services and tasks

Services set to Disabled: DiagTrack (telemetry), dmwappushservice (device
metadata push), WerSvc (Windows Error Reporting). Source: CIS; the guard
re-checks DiagTrack and dmwappushservice at logon.

Scheduled tasks disabled: Microsoft Compatibility Appraiser, ProgramDataUpdater,
PcaPatchDbTask, SdbinstMergeDbTask, Consolidator, UsbCeip, Sqm-Tasks, Autochk
Proxy, QueueReporting, DiskDiagnosticDataCollector, MapsToastTask, MapsUpdateTask,
DmClient, DmClientOnScenarioDownload. These upload compatibility, CEIP, maps,
and feedback data. Source: CIS.

Could we have gone further? ACSC recommends disabling ALL non-required tasks,
but the Microsoft Store and Windows Update depend on several maintenance
tasks, so Windox disables only the ones proven telemetry carriers.

---

## Section 2 - Services (debloat)

Goal: stop consumer services that track, advertise, or do nothing useful,
without touching the hard protections.

Hard protections - never touched, always available:
- Windows Hello stack: NgcSvc, NgcCtnrSvc, WbioSrvc, KeyIso, VaultSvc
- Store stack: InstallService, wlidsvc, ClipSVC, TokenBroker, AppXSvc, camsvc,
  DoSvc (set to Manual instead)
- Networking/core: BFE, Dhcp, Dnscache, nsi, netprofm, RpcSs, EventSystem,
  gpsvc, SENS, Schedule
- Printing: Spooler, PrintWorkflowUserSvc_*
- Defender: WinDefend, WdNisSvc, SecurityHealthService, webthreatdef*

Disabled as bloat: MapsBroker, WMPNetworkSvc, lfsvc, RetailDemo, SharedAccess,
PhoneSvc, TapiSrv, XblAuthManager, XblGameSave, XboxNetApiSvc, XboxGipSvc,
SEMgrSvc, wisvc, TrkWks, SysMain, WpcMonSvc, SSDPSRV, upnphost, WinRM,
SmsRouter, WalletService, MessagingService, PimIndexMaintenanceSvc, PcaSvc,
whesvc, WSAIFabricSvc, InventorySvc, SensorService, wcncsvc, lmhosts,
LicenseManager, plus the per-user families MessagingService,
PimIndexMaintenanceSvc, cbdhsvc, DevicesFlowUserSvc, CloudBackupRestoreSvc.

Why (per family): MapsBroker/lfsvc/wisvc = location and web services;
Xbox*/Xbl* = console integration; WpcMonSvc = family-safety monitoring;
SSDPSRV/upnphost = UPnP exposure; WinRM = remote-management attack surface
(see also 4b); SysMain = Superfetch, an SSD-era memory cache that causes
constant disk churn; RetailDemo = demo-storeware; PcaSvc/whesvc/InventorySvc/
WSAIFabricSvc = telemetry-adjacent compatibility collectors. Source: CIS
(service recommendations) plus the debloat rationale of the Windows
hardening community.

Could we have gone further? The Windows Search indexing service (WSearch),
the print spooler, and the Store install stack could all be disabled for a
quieter machine, but each one breaks a project requirement (search is used by
Store and Start; Spooler = printing; InstallService = Store). They stay on.

---

## Section 3 - Appx removal

Removed packages (Store / Quick Assist / Proton Drive / media never touched):
BingNews, BingSearch, BingWeather, BingFinance, GamingApp, GetHelp, Getstarted,
Todos, PowerAutomateDesktop, WidgetsPlatformRuntime, WindowsFeedbackHub,
DevHome, Xbox.TCUI, XboxGameCallableUI, XboxGamingOverlay, XboxIdentityProvider,
XboxSpeechToTextOverlay, YourPhone, Clipchamp, SolitaireCollection, WindowsPhone,
3DBuilder, 3DViewer, ConnectedWidgetsPlatformRuntime, Copilot.

Why: consumer app bundles that idle in the background, telemetry-laden, and
mostly ad-supported. Source: community debloat consensus; the Copilot/Widgets
removals align with CIS Windows AI and ACSC widget controls.

Protected (never removed): QuickAssist, WindowsStore, StorePurchaseApp,
DesktopAppInstaller, SecHealthUI, ProtonDrive, NotepadPlusPlus.

Could we have gone further? ACSC's Jan 2026 guide includes "Remove default
Store packages from the system" as a hardening measure. That direction - and
the MSIX/Store-package restrictions that go with it - would break the
Microsoft Store requirement, so Windox removes only the non-store bloat and
keeps the Store surface intact. Quick Assist removal (a Store app) is also a
known hardening step (kiosk baselines) but would break the Quick Assist
requirement.

---

## Section 4 - Network hardening

| Setting | Value | Why | Source |
| --- | --- | --- | --- |
| SMBv1 server | Disabled | EternalBlue/WannaCry family. SMBv2 kept (Vista+ requirement) | CIS; NSA/CISA AA23-278A |
| LLMNR (EnableMulticast) | 0 | Name-resolution poisoning/relay | CIS; NSA/CISA AA23-278A |
| mDNS (EnableMDNS) | 0 | Third multicast name-resolution vector | CIS 18.6.4.1 |
| NetBIOS over TCP/IP (per-interface NetbiosOptions) | 2 | NBT-NS poisoning/relay | CIS; NSA/CISA AA23-278A |
| Admin/default shares (AutoShareWks) | 0 | Reduces file-sharing attack surface on hostile networks | CIS |
| WPAD (WpadOverride, HKCU) | 1 | WPAD hijacking/LLMNR-of-WPAD | CIS |
| SCHANNEL SSL 2.0/3.0, TLS 1.0/1.1 (Client+Server) | 0 | Deprecated/insecure protocols; TLS 1.2+ only | CIS |
| Lsa\RunAsPPL | 1 | LSASS protected process (credential theft) | ACSC; STIG; CIS |
| Lsa\UseLogonCredential | 0 | WDigest clear-text cache off | ACSC; STIG |
| Lsa\NoLMHash | 1 | No LAN Manager hashes stored | CIS; STIG |
| Lsa\RestrictAnonymous / RestrictAnonymousSAM | 1 | No anonymous enumeration | CIS; STIG |
| Lsa\LmCompatibilityLevel | 5 | NTLMv2-only, no LM/NTLMv1 responses | CIS; STIG |
| WDigest\UseLogonCredential | 0 | WDigest clear-text logon material off | ACSC; STIG |
| UAC EnableLUA | 1 | Admin Approval Mode on | CIS |
| UAC ConsentPromptBehaviorAdmin | 2 | Prompt for consent on secure desktop | CIS; ACSC |
| UAC ConsentPromptBehaviorUser | 0 | Standard users: deny elevation (see below) | CIS |
| Remote Assistance fAllowToGetHelp | 0 | No unsolicited remote assistance | CIS; ACSC |
| RDP fDenyTSConnections | 1 | Remote Desktop off | CIS; ACSC |
| Firewall default inbound | Block | Default-deny inbound on all profiles | CIS; NSA/CISA |
| Defender cloud block level | High | Max cloud verdict strength | CIS Defender benchmark |
| Defender cloud timeout | 50 s | Long cloud lookups | CIS Defender benchmark |
| Defender network protection | Enabled | Blocks malicious network content | CIS Defender benchmark |
| Defender PUA protection | Enabled | Blocks potentially unwanted apps | CIS Defender benchmark |
| Defender ASR rules (full set) | Block | Ransomware/macro/script/LSASS/PSEXEC exploitation | ACSC; CIS; vendor consensus |
| Execution policy (LocalMachine) | RemoteSigned | Only signed or local scripts run | NSA/CISA; CIS |
| ScriptBlockLogging | 1 | Deobfuscated command logging | NSA/CISA; CIS |
| DOTNET_CLI_TELEMETRY_OPTOUT | 1 | .NET CLI telemetry off | community |

Notes:

- ConsentPromptBehaviorUser = 0 is the MS-baseline value (auto-deny for
  standard users). The local admin account is not a standard user, so this
  does not block admin PowerShell.
- Execution policy RemoteSigned keeps the admin able to run local scripts;
  an AllSigned policy (ACSC's recommendation) would force signing of every
  local script and break the admin workflow, so RemoteSigned is the line.
- The PSExec/WMI ASR rule is set to Audit (2) per the Microsoft baseline
  rather than Block, because remote admin tooling and some legitimate
  software trigger it; it is still monitored.

Could we have gone further?

- Block outbound firewall connections: would break VPNs, Windows Update,
  the Store, and Defender cloud lookups. Not done.
- Disable IPv6: deprecated practice; breaks modern networking. Not done.
- FIPS 140 compliant algorithms: breaks TLS stacks and several VPN clients.
  Not done.
- Credential Guard here would be the stronger LSASS story; it lives in 4c
  because it needs the VBS stack.

---

## Section 4b - Microsoft Intune / security baseline equivalents

These are the Microsoft Security Compliance Toolkit baseline values applied
locally. Source: aka.ms/securitybaselines (the "MS Security Guide" ADMX).

| Setting | Value | Why |
| --- | --- | --- |
| LocalAccountTokenFilterPolicy | 0 | UAC applies to local accounts on network logons (pass-the-hash) |
| IFEO\*\DisableExceptionChainValidation | 0 | SEHOP enforced (0 = not disabled) |
| Tcpip DisableIPSourceRouting (v4+v6) | 2 | Highest source-routing protection |
| Tcpip EnableICMPRedirect | 0 | No ICMP redirects |
| NetBT NoNameReleaseOnDemand | 1 | No name-release on demand (smurf) |
| Hardened UNC paths SYSVOL/NETLOGON | RequireMutualAuthentication, RequireIntegrity | Blocks tampered group-policy shares |
| SMB client/server signing required | True | MITM protection |
| Insecure guest logons | False | No guest-only SMB |
| NtlmMinClientSec / NtlmMinServerSec | 537395200 | NTLMv2 + 128-bit minimum |
| RestrictRemoteSAM | SDDL (admin only) | No remote SAM access |
| Rpc RestrictRemoteClients | 1 | RPC unmarshaled client hardening |
| Terminal Services DisablePasswordSaving | 1 | RDP creds not saved |
| CredSSP ProtectionLevel | 2 | Encryption oracle remediation (CVE-2018-0886) |
| WinRM client/service policies | Hardened | Basic/digest/unencrypted off, no RunAs |
| ProcessCreationIncludeCmdLine_Enabled | 1 | Command lines in 4688 events |
| Event log MaxSize (App/System/Sec) | 32/32/192 MB | Enough log for the audit settings in 4c |
| EarlyLaunch DriverLoadPolicy | 3 | ELAM: good, unknown, bad-but-critical |
| Printer PointAndPrint restriction | 1 | Admin-only driver installs (PrintNightmare) |
| Printer RedirectionGuard | 1 | Print redirection guard |
| Printer DisableHTTPPrinting | 1 | No HTTP print drivers |
| Autoplay NoAutorun / NoDriveTypeAutoRun | 1 / 255 | No autorun at all |
| EnumerateAdministrators | 0 | Do not enumerate admins on UAC prompts |
| Lock screen camera/slideshow | 1 | Privacy on lock screen |
| SmartScreen (Enable + Block) | 1 / Block | Warn and prevent bypass |
| DeviceInstall Restrictions (SBP-2 class) | Deny | IEEE 1394 storage blocked (DMA theft) |
| Sudo Enabled | 0 | Win11 sudo disabled (24H2+) |
| InactivityTimeoutSecs | 900 | Auto-lock after 15 min idle |

Could we have gone further? The full MS Security Guide also restricts
anonymous enum and requires SMB encryption; both are already in 4. The
remaining guide items are server-side (NPS/IPsec) and do not apply to a
workstation.

---

## Section 4c - Defense-in-depth (the non-Microsoft additions)

This is the new layer: what CIS, ACSC, NSA/CISA, and the STIG recommend
beyond the Microsoft baseline. Nothing in this section restricts the local
admin's PowerShell.

### 4c.1 PowerShell deep logging (NSA/CISA "Keeping PowerShell" 2022; CCCS ITSP.70.012; CIS 18.10.88)

| Setting | Value | Why |
| --- | --- | --- |
| ModuleLogging\EnableModuleLogging + ModuleNames | 1 / * | Logs every module load (Event 4103); attacker tooling loads modules |
| Transcription\EnableTranscripting + EnableInvocationHeader | 1 | Full session transcripts to C:\Windows\Logs\PSTranscripts |
| Transcription\OutputDirectory | C:\Windows\Logs\PSTranscripts | Where transcripts land (Users granted write) |
| PowerShell v2 engine (optional feature) | Disabled | PSv2 is deprecated, unpatched-surface, and a malware favorite |
| PowerShell/Operational log size | 100 MB | Big enough to hold the new logging |

These are logging controls. They record; they do not block. That is the
deliberate line: Constrained Language Mode (CLM) and App Control would block
or cripple the admin's own PowerShell, so Windox stops at logging. Source:
NSA/CISA June 2022, CCCS ITSP.70.012, CIS 18.10.88.1/.2, STIG.

Privacy note: transcripts capture what the admin types, including passwords
typed into prompts. That is the point (accountability and forensic value);
keep the folder admin-only.

### 4c.2 Exploit Protection system defaults (MITRE M1050; ACSC; CCCS ITSP.70.012)

| Mitigation | Value | Why |
| --- | --- | --- |
| DEP + EmulateAtlThunks | On | Data execution prevention for 32-bit processes too |
| SEHOP | On | Exception-chain validation |
| CFG | On | Control-flow guard |
| ForceRelocateImages (Mandatory ASLR) | On | Every image randomized, even without /DYNAMICBASE |
| BottomUp + HighEntropy ASLR | On | Strongest address randomization |
| StrictHandle | On | Validate handle usage |
| DisableExtensionPoints | On | Blocks extension-point injection |

Applied with `Set-ProcessMitigation -System`. Deliberately NOT set:
BlockNonMicrosoftBinaries, DisableNonSystemFonts, DisableWin32kSystemCalls,
DisallowChildProcessCreation, EAF/IAF - each of those breaks real software
(third-party apps, fonts, GUI processes, child processes, debuggers/DRM), so
they are per-app mitigations, not system defaults. Source: MITRE M1050;
Microsoft Exploit Protection reference (which mitigations are system-safe).

### 4c.3 Controlled Folder Access (ACSC; CIS Defender benchmark; vendor ransomware guidance)

| Setting | Value | Why |
| --- | --- | --- |
| EnableControlledFolderAccess | Block | Untrusted processes cannot modify user folders (ransomware) |
| ControlledFolderAccessAllowedApplications | powershell.exe + pwsh.exe | The admin's shells stay able to write to protected folders |

CFA is the single ransomware control every vendor (SentinelOne, Sophos,
CrowdStrike) points at first, and it requires Defender as the active AV -
which Windox guarantees. The allow-list is the requirement accommodation:
without it, PowerShell-launched scripts that write to Documents/Pictures/etc.
are blocked, which would break the admin workflow.

### 4c.4 Tamper Protection check (Microsoft Tamper Protection docs)

Windox reports whether Tamper Protection is on. It does not try to set it,
because it is a Windows Security setting and because Tamper Protection
deliberately rejects local changes to cloud-delivered protection (which is
why `Set-MpPreference -CloudBlockLevel` and friends in section 4 may be
ignored on fully-updated systems - the log now says so instead of silently
failing). Real-time protection state is reported the same way.

### 4c.5 Credential hardening (CIS 2.3.x; DISA STIG WN11-SO-*)

| Setting | Value | Why |
| --- | --- | --- |
| Lsa\DisableDomainCreds | 1 | No storage of network credentials (Credential Manager savings blocked) |
| Lsa\LimitBlankPasswordUse | 1 | Blank passwords only at the console |
| Lsa\RestrictNullSessAccess | 1 | No anonymous named-pipe/share access |
| LanmanServer NullSessionPipes / NullSessionShares | cleared | Anonymous pipe/share lists empty (STIG CAT I) |
| Session Manager\SafeDllSearchMode | 1 | DLL hijacking hardened |
| Policies\System\DontDisplayLastUserName | 1 | Last user name not shown at logon |
| Winlogon\AutoAdminLogon | 0 | No auto-logon (stored plaintext password) |
| Guest account | Disabled | No anonymous guest logon |

The only user-visible effect is that Windows no longer saves network/domain
credentials (`net use /savecred`, RDP saved creds). That is the point; it is
also the reason a note exists in the README troubleshooting area.

### 4c.6 Account lockout (ACSC high priority; CIS 1.2.x)

| Setting | Value |
| --- | --- |
| Lockout threshold | 5 invalid attempts |
| Lockout duration | 15 minutes |
| Reset lockout counter | 15 minutes |

Applied with `net accounts`; the pre-change security policy is exported with
`secedit /export` to `SecPolBackup.inf` for a clean restore. ACSC: 5/15
"will prevent any brute force attempt while being unlikely to lock out a
legitimate user." The built-in Administrator lockout (CIS 1.2.3, Manual
rating) is NOT enabled: on a personal machine it risks self-lockout with no
recovery path.

### 4c.7 Advanced audit policy (CIS 17.x; DISA STIG WN11-AU-*)

| Subcategory | Setting |
| --- | --- |
| Logon, Credential Validation, User Account Management, Other System Events, System Integrity, Removable Storage | Success + Failure |
| Logoff, Process Creation, Audit Policy Change, Security State Change, Special Logon | Success |
| Account Lockout | Failure |

Plus `SCENoApplyLegacyAuditPolicy = 1` (advanced policy wins over legacy
category policy). The pre-change policy is backed up with
`auditpol /backup` to `AuditPolBackup.pol` for a clean restore.

Deliberately omitted (documented tailoring): File Share, Detailed File Share,
and Sensitive Privilege Use - they generate enough volume to fill the 192 MB
security log in a week of normal use, drowning the logon evidence. CIS lists
them; Windox trades them for a usable log.

### 4c.8 Firewall logging (CIS 9.x; SANS)

| Setting | Value |
| --- | --- |
| LogBlocked / LogAllowed | True |
| LogMaxSizeKilobytes | 16384 (16 MB) |

Dropped and allowed connections logged for detection and troubleshooting.
No behavioral impact; the firewall posture (default-deny inbound) is
unchanged.

### 4c.9 Scheduled-scan optimization (Microsoft Set-MpPreference docs)

| Setting | Value |
| --- | --- |
| ScanAvgCPULoadFactor | 30 |
| EnableLowCpuPriority | True |
| CheckForSignaturesBeforeRunningScan | True |

Scheduled scans stop eating CPU during work. This is the "optimization" half
of the request, chosen because it is sourced, reversible, and does not touch
power plans (power is the Windows 11 Settings UI's job - see the rejected
list).

### 4c.10 VBS / Memory Integrity / Credential Guard (ACSC; NSA; CIS 18.9.5.x; STIG)

| Setting | Value |
| --- | --- |
| DeviceGuard\EnableVirtualizationBasedSecurity | 1 |
| DeviceGuard\RequirePlatformSecurityFeatures | 1 (Secure Boot) |
| DeviceGuard\Locked | 1 (UEFI lock) |
| DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled | 1 |
| DeviceGuard\Scenarios\CredentialGuard\Enabled | 1 |
| Lsa\LsaCfgFlags | 1 (Credential Guard, UEFI lock) |

Why: VBS isolates the kernel, Memory Integrity (HVCI) stops unsigned/incompatible
kernel drivers and kernel code injection, and Credential Guard isolates
LSASS secrets - the three highest-value mitigations every outside-Microsoft
baseline (ACSC, NSA, CIS, STIG) agrees on.

Guards and caveats:

- Applied only when the hardware proves out: CPU virtualization enabled, TPM
  present, Secure Boot on. Otherwise skipped with a log line.
- Requires a reboot before it is active. The script says so.
- UEFI lock (per ACSC) means registry changes alone cannot disable it later;
  Undo restores the values and explains that Core isolation must be cleared.
- Incompatible kernel drivers (some old VPN clients) may fail to load. The
  README requirement says VPNs must work, which is why the script prints a
  check-the-Device-security-page note after applying.
- RequirePlatformSecurityFeatures is 1 (Secure Boot), not 3 (Secure Boot +
  DMA protection). ACSC prefers 3; value 3 fails on hardware without an IOMMU
  and can silently keep VBS off. 1 works on every Secure Boot machine and is
  the STIG minimum. Going further here would cost boot reliability on
  ordinary hardware.

---

## Section 5 - Cleanup

Temp folders, Prefetch, thumbnails, and the Delivery Optimization cache are
cleared. `C:\Windows.old` and `$WinREAgent` are only reported, never deleted,
because removing them destroys the rollback path for a bad feature update.
The script does not run a disk cleaner or touch hibernation files - power
and space politics are the user's call (and power is Settings-UI-only).

Could we have gone further? Disabling hibernation (`powercfg /h off`) frees
disk and reduces credential remnants in RAM image files, but it is a power
setting (Settings UI only) and breaks Fast Startup, which is a usability
default. Not done, by requirement.

---

## Section 6 - TelemetryGuard

An elevated, hidden scheduled task that runs at logon, checks the settings
Windows Update likes to reset (AllowTelemetry, DiagTrack, autologgers, CEIP,
feedback tasks, per-user privacy), and re-applies them silently when it finds
drift. It is the "survives feature updates" layer for section 1.

Could we have gone further? A resident service could re-check every N minutes,
but a logon task is invisible, dependency-free, and enough in practice; a
service would need to be written, signed, and installed, which contradicts the
no-dependencies project rule.

---

## Could have gone further, but a requirement stopped us

This is the complete list of measures that were researched, seriously
considered, and rejected. Each row names the requirement that blocked it.

| Measure | Recommended by | Requirement that blocks it |
| --- | --- | --- |
| Constrained Language Mode for PowerShell | NSA/CISA (via App Control), CCCS | Admin must run ad-hoc/unsigned PowerShell; CLM blocks Add-Type, COM, .NET types for everyone |
| WDAC / AppLocker enforcement | NSA/CISA, MITRE M1050 | Same as CLM: enforced policies push PowerShell into CLM and block unsigned tooling |
| Smart App Control | Microsoft / HotCakeX | Blocks unsigned scripts and portable tools; one-way wash-out to Off is permanent without reinstall |
| Remove default Store packages / MSIX non-admin install limits | ACSC Jan 2026 | Microsoft Store must keep working |
| Remove Quick Assist | kiosk/analyst baselines | Quick Assist must keep working |
| Windows LAPS for the admin account | CIS 18.9.26 | Requires AD or Entra ID join; Windox targets standalone machines |
| Block outbound firewall traffic | SANS, some vendors | Breaks VPNs, Windows Update, Store, Defender cloud |
| FIPS 140 compliant algorithms | CCCS, some STIG lines | Breaks TLS stacks and several VPN clients |
| Disable crash dumps (CrashDumpEnabled=0) | debloat folklore, memory-theft argument | Not in current CIS/STIG; destroys post-crash forensics for a marginal privacy gain |
| Block command prompt / registry editor (ACSC user config) | ACSC | The admin needs cmd, .bat/.cmd scripts, and regedit |
| Power plan / high-performance via classic control | n/a (optimization) | Legacy Control Panel power options cause problems; Windows 11 Settings UI only |
| Disable hibernation / Fast Startup | debloat folklore | Power setting (Settings UI only); breaks Fast Startup |
| Account lockout for the built-in Administrator | CIS 1.2.3 (Manual) | Self-lockout risk with no recovery on a personal machine |
| LSASS PPL with UEFI lock (RunAsPPLBoot) | ACSC | Requires firmware variable support and is irreversible from Windows; the non-locked PPL already in 4 blocks software credential theft |
| Full audit volume (File Share / Sensitive Privilege Use) | CIS 17.6/17.8, STIG | Fills the 192 MB security log; logon evidence drowned |
| MAPS Advanced + auto sample submission | CIS Defender benchmark | Contradicts the no-telemetry project rule (samples go to Microsoft) |
| OneDrive full removal | debloat consensus | OneDrive is off via policy (4b); removing the app breaks Office OneDrive integration users rely on |

Two of the "gone further" items above are really "gone further differently":
BitLocker (data at rest) and the Store-app purge. BitLocker is recommended by
ACSC and the UK NCSC and is intentionally left to the user - it needs a TPM,
writes a recovery key you must keep somewhere safe, and is the one change in
this whole project that can lock you out of your own disk if it goes wrong.
Windox does not auto-enable it, and Undo cannot undo a forgotten recovery
key.

---

## Backup and undo contract

`Undo-Hardening.ps1` restores, from `HardenBackup.json`:

- every registry value above (with type fidelity, including binary values)
- service start types, scheduled task states, removed Appx packages
- Defender ASR/cloud/CFA/scan settings
- execution policy, firewall defaults and logging
- the exported security policy (`SecPolBackup.inf`), audit policy
  (`AuditPolBackup.pol`), PowerShell v2 feature state, PowerShell log size,
  transcript directory ACL, and guest account state

Limits of the undo (stated in the script's own output): provisioned-app
changes for brand-new user profiles are not reverted, and UEFI-locked VBS
settings only return after the Core isolation lock is cleared. Neither is a
silent failure - the script prints both.

## Maintenance

Baselines move. The version numbers in the Sources section are the ones this
file was written against; when you refresh a script section, update the
source table and the affected rows in the same change. The ASCII-only lint
(the CI workflow) applies to this file too.