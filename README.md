# Windox

Windows hardening, debloat, and telemetry removal scripts for Windows 10/11 Pro.
Kills telemetry, disables tracking services, removes bloat, and hardens defaults - while keeping things that should keep working: the Microsoft Store, Quick Assist, printing, VPN, Windows Update, and Defender.

## Install

No installation. Grab the scripts from this repo (clone, download the release archive, or just save the `.ps1` files into a folder you control).

## Usage

**Warning:** these scripts change system configuration. Everything they change is backed up to `HardenBackup.json` in the script folder and can be fully reverted with `Undo-Hardening.ps1`, but you run them at your own risk. The GPL-3 license under which this project ships contains a **NO WARRANTY** section - please read it before running anything here.

### The one-liner

Run this from an **elevated** PowerShell (Run as Administrator):

```powershell
irm https://raw.githubusercontent.com/Kinsman4249/Windox/main/Harden-Windows.ps1 -OutFile .\Harden-Windows.ps1; powershell -ExecutionPolicy Bypass -File .\Harden-Windows.ps1
```

Before it changes anything, the script shows a safety notice and asks you to confirm that you have read the NO WARRANTY section of the license. Typing anything other than exactly YES aborts with no changes made. Scripted installs can pass `-NoConfirm` to skip that prompt.

### Manual

From an elevated PowerShell, in the folder holding the scripts:

```powershell
powershell -ExecutionPolicy Bypass -File .\Harden-Windows.ps1
```

To undo everything:

```powershell
powershell -ExecutionPolicy Bypass -File .\Undo-Hardening.ps1
```

### What the scripts do

| Script | Purpose |
| --- | --- |
| `Harden-Windows.ps1` | The main hardening pass: registry policies, services, scheduled tasks, Appx removal, network hardening, cleanup. Backs up every original setting to `HardenBackup.json` first, and installs TelemetryGuard. |
| `TelemetryGuard.ps1` | Installed by the main script to run at logon. Silent when the system is clean; re-applies telemetry hardening when Windows Update has restored it. |
| `Undo-Hardening.ps1` | Full revert using `HardenBackup.json`: restores registry values, services, scheduled tasks, removed Appx packages, Defender ASR rules, execution policy, firewall defaults, and removes TelemetryGuard. |

## Configuration

Skip individual parts of the main script with switches:

```powershell
powershell -ExecutionPolicy Bypass -File .\Harden-Windows.ps1 -SkipServices -SkipAppx -SkipNetwork -SkipCleanup
```

- `-SkipServices` - leave Windows services alone
- `-SkipAppx` - do not remove Store apps
- `-SkipNetwork` - leave network hardening alone
- `-SkipCleanup` - skip cleanup steps
- `-NoConfirm` - skip the interactive safety confirmation (scripted installs)

`Undo-Hardening.ps1` accepts `-KeepTelemetryGuard` to revert the hardening but leave the telemetry guard in place.

## Troubleshooting

- `Harden-Windows.ps1` and `Undo-Hardening.ps1` write a transcript log next to the script (`Harden-<timestamp>.log`, `Undo-<timestamp>.log`) and print an error summary when finishing. Attach that log when reporting a problem.
- `TelemetryGuard.ps1` appends to `TelemetryGuard.log` in `%LOCALAPPDATA%\TelemetryGuard`.
- Exit codes: `0` success, `1` aborted or a failure that needs attention (e.g. backup could not be saved, TelemetryGuard task could not be registered).

## Development

Scripts are plain PowerShell with no dependencies. Open an issue before larger changes; see [CONTRIBUTING.md](./CONTRIBUTING.md) for the full workflow and local testing instructions below.

Verify a change locally on a Windows 10/11 machine or VM:

1. Run `Harden-Windows.ps1` from an elevated prompt.
2. Confirm `HardenBackup.json` was created in the script folder.
3. Run `TelemetryGuard.ps1` directly and confirm it exits silently on a hardened system.
4. Run `Undo-Hardening.ps1` and spot-check a few registry values, services, and tasks to confirm they were restored.
5. Re-run the whole cycle once more before submitting.

Markdown in this repo is linted to stay ASCII-only (see `.github/workflows/lint-ascii.yml`).

## Releases

Push a tag matching `vX.Y.Z` to `main` (`git tag -a vX.Y.Z -m "Release vX.Y.Z" && git push origin vX.Y.Z`). CI builds and publishes the GitHub Release automatically - nothing else to do.

## License

This project is licensed under [GPL-3.0](./LICENSE). The license includes a NO WARRANTY section - if you are running Windox via the one-liner above, you confirm there that you have read it.

## Community

- [CONTRIBUTING.md](./CONTRIBUTING.md) - how to report bugs, propose features, and submit changes.
- [SECURITY.md](./SECURITY.md) - how to report a vulnerability.
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) - the standards this project holds contributors to.
