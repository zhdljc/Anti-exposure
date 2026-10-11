# Anti-exposure
A privacy tool for Windows that counters GDID, telemetry, and other security measures to prevent data uploads or leaks.

# ANTI: A Lightweight Tool Against Windows Privacy Tracking

## Privacy Issues on Windows

Windows, by default, functions as a telemetry terminal that continuously reports data to Microsoft.

Even if you use only a local account, the system still runs in the background:

- **DiagTrack** — packages and uploads system events
- **dmwappushservice** — receives remote configuration
- **SQMClient** — generates a machine ID and reports it
- **CompatTelRunner** — periodically scans installed programs
- **DeviceCensus** — collects a daily hardware inventory

More critically, Windows assigns multiple unique identifiers to your device:

- **LID** — Microsoft account identity
- **MachineGuid** — system-level hardware fingerprint
- **MachineId** — telemetry machine ID
- **DeviceId** — shared by OneDrive, Office, Xbox
- **Advertising ID** — tracks user behavior
- **GDID** (post-2024) — global device identifier, cross-account, cross-app, cloud-bound

Most of these are **enabled by default and deeply integrated**. The toggles you turn off under *Settings → Privacy* often only affect the UI; the underlying services keep running. GDID is even more problematic—it is registered in the cloud. As long as you are online and signed in with a Microsoft account, the server assigns it immediately, and deleting it locally will simply sync back.

## ANTI Features

ANTI is a single-file C++ tool that does exactly three things:

1. **Scan** — checks registry, services, processes, credentials, scheduled tasks, and the hosts file, listing all identity markers by severity: CRIT/HIGH/MED/LOW.
2. **Block** — cuts off data exfiltration channels via hosts blocking, policy writes, service disabling, and scheduled task deactivation.
3. **Clean** — precisely deletes LID, DeviceId, advertising ID, telemetry machine ID, and similar markers without harming critical system items (e.g., MachineGuid is only flagged, never deleted).

## ANTI Principles

- **Local-first**: never connects to the internet, never uploads any data.
- **Reversible**: checks for existence before every action, never creates fake registry keys; `[4] UNBLOCK` fully rolls back changes.
- **Transparent**: open source, every rule is auditable, and the user decides what to delete and what to keep.

ANTI does not promise absolute anonymity. It does one thing: **give you the ability to say "no" to Microsoft.**

## In ANTI.md, you can see the addresses of some related projects.
