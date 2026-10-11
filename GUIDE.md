# Windows Privacy Hardening Guide (2026)

This guide provides a layered, reversible approach to reducing data collection on Windows 10 and Windows 11. Every step is designed to be auditable and undoable. No third-party drivers, no permanent system modification without a backup path.

---
Before we go again, please note that we strongly recommend using a local account for increased security.
On normal Windows systems, no access protection measures can be effectively implemented with Microsoft services.
## We highly recommend using the ANTI tool rather than the guide below.

## Layer 1: Account & System Foundation

**Use a local account.** Microsoft account login automatically binds your device to a server-side identity and enables cross-device telemetry correlation. During OOBE, choose "Offline account" or "Domain join instead." If already signed in, go to **Settings → Accounts → Your info → Sign in with a local account instead**.

**Disable sync.** Navigate to **Settings → Accounts → Windows backup** and turn off "Remember my preferences." Then go to **Settings → Accounts → Sync your settings** and disable all toggles (passwords, language, accessibility, etc.).

**Create a restore point** before making any registry or policy changes:
```powershell
Checkpoint-Computer -Description "Before Hardening" -RestorePointType MODIFY_SETTINGS
```


## Layer 2: Telemetry & Diagnostic Data

### Settings Level (minimum viable)

Go to **Settings → Privacy & security → Diagnostics & feedback**:
- Set "Send optional diagnostic data" to **Off**
- Set "Diagnostic data" to **Required only** (on Pro/Enterprise, set to **0 — Security**)
- Disable "Improve inking and typing," "Tailored experiences," and "View diagnostic data"

**Important:** The Settings toggle only controls the **optional** tier. Required diagnostic data continues to flow regardless. Policy-level enforcement is needed.

### Registry / Policy Level (enforced)

Open an elevated Command Prompt or PowerShell:

```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
```

On Windows Home, this key may not exist. Create it first:
```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
```

Setting `AllowTelemetry=0` enforces the lowest diagnostic level your edition supports and **grays out the Settings toggle**, preventing Windows Update from silently resetting it.

### Service Level (the actual upload pipeline)

```cmd
sc config DiagTrack start= disabled
sc config dmwappushservice start= disabled
sc stop DiagTrack
sc stop dmwappushservice
```

`DiagTrack` (Connected User Experiences and Telemetry) is the service that **actually packages and uploads** the data. Disabling it is what makes the "Required" floor moot in practice.

### Scheduled Tasks (periodic uploaders)

```cmd
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks /Change /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\PI\Sqm-Tasks" /Disable
```

These tasks run periodically in the background and upload telemetry data even when the Settings toggle is off.


## Layer 3: Identity & Device Identifier Cleanup

### Advertising ID

Go to **Settings → Privacy & security → General** and disable "Let apps show me personalized ads by using my advertising ID." Then delete the stored GUID:

```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Id /f
```

### Activity History

**Settings → Privacy & security → Activity history**: uncheck "Store my activity history on this device" and "Send my activity history to Microsoft."

### Diagnostic ID Cache (DiagTrack subkeys)

```cmd
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
```

### GDID (Global Device Identifier) — Critical

GDID is a server-assigned 64-bit Device PUID that Windows mints through Microsoft's `DeviceAdd` infrastructure. **A local account does not prevent this.** The GDID is retained across several local identity stores and is sent to Microsoft with activity reports. Even after deleting it locally, a reboot or server connection will cause it to be silently re-minted.

**Use deGDID** — a free, open-source PowerShell script by Windscribe:

```powershell
# Check current status (read-only, no admin needed)
.\degdid.ps1 -Status

# Apply full protection (requires elevated PowerShell)
.\degdid.ps1 -Protect

# Verify
.\degdid.ps1 -Status
# Expected result: ProtectedNoRealGdid
```

`Protect` does four things:
1. Applies a dual-stack hosts block and verifies the DeviceAdd path
2. Refreshes firewall rules for defense-in-depth
3. Clears known GDID copies from the target user, `.DEFAULT`, and SYSTEM stores
4. Waits and rechecks — refuses to report success if identity state returns

**Trade-off:** After deGDID protection, **login.live.com is blocked in all browsers**, and some Microsoft account-dependent apps (Xbox, Outlook, Microsoft Store) will fail to connect. Other applications are unaffected.


## Layer 4: Network-Level Blocking

### Hosts File

Edit `C:\Windows\System32\drivers\etc\hosts` with an elevated text editor. Append:

```
# ==== PRIVACY BLOCK BEGIN ====
0.0.0.0 vortex.data.microsoft.com
0.0.0.0 vortex-win.data.microsoft.com
0.0.0.0 telecommand.telemetry.microsoft.com
0.0.0.0 telemetry.microsoft.com
0.0.0.0 settings-win.data.microsoft.com
0.0.0.0 v10.events.data.microsoft.com
0.0.0.0 v20.events.data.microsoft.com
0.0.0.0 self.events.data.microsoft.com
0.0.0.0 browser.events.data.microsoft.com
0.0.0.0 mobile.events.data.microsoft.com
0.0.0.0 pipe.aria.microsoft.com
0.0.0.0 feedback.windows.com
0.0.0.0 watson.live.com
# ==== PRIVACY BLOCK END ====
```

After saving, flush DNS:
```cmd
ipconfig /flushdns
```

**Note:** Windows Defender may flag this as `SettingsModifier:Win32/PossibleHostsFileHijack`. This is a **heuristic false positive** — add `C:\Windows\System32\drivers\etc\hosts` and your hardening tools to Defender exclusions to prevent silent rollback.

### Firewall Outbound Rules

Block telemetry executables at the network layer. Using PowerShell:

```powershell
New-NetFirewallRule -DisplayName "Block Telemetry - CompatTelRunner" `
  -Direction Outbound -Program "C:\Windows\System32\CompatTelRunner.exe" `
  -Action Block -Profile Any

New-NetFirewallRule -DisplayName "Block Telemetry - DeviceCensus" `
  -Direction Outbound -Program "C:\Windows\System32\DeviceCensus.exe" `
  -Action Block -Profile Any
```

For a comprehensive, community-maintained rule set, use **WindowsSpyBlocker**:

```powershell
# Clone and run
git clone https://github.com/crazy-max/WindowsSpyBlocker.git
cd WindowsSpyBlocker
# Run WindowsSpyBlocker.exe → Telemetry → Firewall → Add spy rules
```

WindowsSpyBlocker deploys 347+ outbound rules covering telemetry, update, and third-party tracking domains as Windows Firewall rules.


## Layer 5: Edge & Browser Privacy

**Disable Copilot and AI features.** Navigate to **Settings → Privacy & security → Copilot** (or **Windows AI**) and disable all AI integration toggles. On Pro editions, use Group Policy:

```cmd
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f
```

**Edge telemetry.** Open Edge → **Settings → Privacy, search, and services**:
- Turn off "Optional diagnostic data"
- Turn off "Personalization & advertising"
- Set "Search engine used in the address bar" to a non-Microsoft option
- Disable "Show suggestions from Microsoft"

For automated Edge hardening, use **privacy.sexy Revamped** (web-based script builder) to generate Edge-specific policies covering 24 v151 baseline settings plus 7 privacy values.


## Layer 6: Recommended Open-Source Tools

| Tool | Function | Reversible? |
|---|---|---|
| **deGDID** | Clears and blocks GDID device tracking | ✅ `-Unblock` |
| **noid-privacy** | 630+ hardening decisions, 7 modules, BAVR pattern | ✅ Full restore from backup |
| **TelemetryGuard** | Services + registry + tasks, timestamped backup | ✅ `-Mode Revert` |
| **WindowsSpyBlocker** | 347+ firewall rules for telemetry domains | ✅ Remove rules |
| **privacy.sexy Revamped** | Web-based script builder, inspect before run | ✅ Revert commands included |
| **ReWindows** | GUI tool for privacy + debloat, per-tweak revert | ✅ Full revert |
| **fortify** | Modular: telemetry, AI removal, network, security | ✅ Per-module revert |

All tools are free and open-source. **Always create a restore point before running any hardening tool.**


## Layer 7: Verification & Ongoing Maintenance

### After every major Windows update

Windows updates can silently re-enable services, restore scheduled tasks, and reset policy keys. Re-run your checks:

```powershell
# Check critical services
sc qc DiagTrack | findstr "START_TYPE"
sc qc wlidsvc | findstr "START_TYPE"
# Expected: START_TYPE : 4 DISABLED

# Check hosts block
findstr "PRIVACY BLOCK" C:\Windows\System32\drivers\etc\hosts

# Check deGDID status
.\degdid.ps1 -Status
```

### Monthly automated check

Create a scheduled task to run verification monthly:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -Command `"& 'C:\Tools\degdid.ps1' -Status | Out-File `$env:USERPROFILE\degdid_check.log -Append`""
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "Privacy-Monthly-Check" -Action $action -Trigger $trigger -Principal $principal
```


## Summary: Defense in Depth

| Layer | Method | What It Blocks |
|---|---|---|
| 1 | Local account + no sync | Identity binding |
| 2 | AllowTelemetry=0 + DiagTrack disabled | Diagnostic upload pipeline |
| 3 | deGDID + identity cleanup | Device identifier minting |
| 4 | Hosts + firewall rules | Network exfiltration |
| 5 | Browser + AI toggles | Edge/Copilot telemetry |
| 6 | Open-source tools | Automation + audit |
| 7 | Monthly verification | Regression detection |

**Key principle:** No single layer is sufficient. Microsoft's telemetry architecture is designed so that disabling one channel (e.g., the Settings toggle) leaves others active. Layered blocking at the policy, service, identity, and network levels is required to achieve meaningful privacy on Windows.
