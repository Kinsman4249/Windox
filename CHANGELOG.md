# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- New defense-in-depth section (4c) in Harden-Windows.ps1, sourced from
  CIS, ACSC, NSA/CISA, CCCS ITSP.70.012, and DISA STIG:
  - PowerShell module logging, transcription (to
    C:\Windows\Logs\PSTranscripts), and PowerShell v2 engine removal.
  - Exploit Protection system defaults (DEP, SEHOP, CFG, mandatory/bottom-up
    ASLR, handle validation, extension-point blocking).
  - Controlled Folder Access in Block mode, with powershell.exe and pwsh.exe
    allow-listed so the local admin's scripts still write to protected folders.
  - Tamper Protection and real-time protection status reporting.
  - Credential hardening: DisableDomainCreds, LimitBlankPasswordUse,
    RestrictNullSessAccess, cleared NullSessionPipes/Shares, SafeDllSearchMode,
    DontDisplayLastUserName, AutoAdminLogon off, Guest account disabled.
  - Account lockout (5 attempts / 15 min) with secedit export for restore.
  - Advanced audit policy subcategories with auditpol /backup for restore.
  - Firewall logging (blocked + allowed connections, 16 MB).
  - VBS, Memory Integrity (HVCI), and Credential Guard with UEFI lock,
    applied only when CPU virtualization + TPM + Secure Boot are present.
  - mDNS disabled (CIS 18.6.4.1) alongside LLMNR/NetBIOS.
- references.md documenting every change, its source baseline, and the
  "could have gone further but it would break a requirement" decisions.

### Changed

- Defender state is now captured once by a shared helper and includes
  Controlled Folder Access and scheduled-scan settings; Undo restores them.
- Undo-Hardening.ps1 restores the new 4c items (PSv2 feature, PowerShell log
  size, transcript ACL, guest account, security policy, audit policy,
  firewall logging) and decodes base64 binary registry data on restore.

### Deprecated

### Removed

### Fixed

### Security

- ScriptBlockLogging now pairs with module logging and transcription so
  PowerShell activity is fully recorded (NSA/CISA 2022, CCCS ITSP.70.012).
- VBS/Memory Integrity/Credential Guard add kernel- and credential-isolation
  defenses that no registry-only hardening can provide (ACSC, NSA, CIS, STIG).

## [0.1.0] - 2026-10-26

First release.

### Changed

- Scripts log unexpected failures to transcript files and report an error summary
  at the end, instead of discarding error records; individually guarded commands
  are unchanged.

### Added

- Harden-Windows.ps1: Windows 10/11 hardening, debloat, and telemetry removal.
  Backs up every original setting to HardenBackup.json; supports -SkipServices,
  -SkipAppx, -SkipNetwork, and -SkipCleanup; writes a transcript log and an
  end-of-run error summary.
- Interactive safety gate in Harden-Windows.ps1: requires typing YES to confirm
  the GPL-3 NO WARRANTY terms before any change; -NoConfirm skips it for
  scripted installs.
- TelemetryGuard.ps1: installed as an elevated scheduled task that runs at logon
  and re-applies telemetry hardening when drift is detected; logs to
  TelemetryGuard.log.
- Undo-Hardening.ps1: full revert from HardenBackup.json covering registry
  values, services, scheduled tasks, Appx packages, Defender settings, firewall
  defaults, and the TelemetryGuard task.
- README with a PowerShell quick-start one-liner and a troubleshooting guide,
  plus CONTRIBUTING, SECURITY, and CODE_OF_CONDUCT.
- GitHub Actions: release workflow publishing on vX.Y.Z tags and an ASCII-only
  markdown lint.
- LICENSE: GNU General Public License v3.0.
