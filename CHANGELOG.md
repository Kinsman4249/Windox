# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

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
