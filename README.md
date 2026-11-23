# PowerShell Sandbox Telemetry Pipeline

![CI](../../actions/workflows/ci.yml/badge.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Automated dynamic-analysis pipeline that executes PowerShell scripts inside an
isolated VirtualBox Windows VM, records their behaviour with **Sysmon** and turns
each run into one machine-learning-ready JSONL sample that combines static
script features with aggregated runtime telemetry.

It was used to build a labelled dataset of malicious and benign PowerShell
behaviour for fileless-malware detection. The resulting samples can be trained
on directly with
[`fileless-powershell-malware-detector`](../fileless-powershell-malware-detector).
In the accompanying master's thesis this project is referred to as the
**Malware-Erfassungspipeline** (malware collection pipeline), the detector as the
**DP-Tool**.

**Stack:** Python | VirtualBox (VBoxManage) | WinRM | Sysmon

## What it does

For every `.ps1` file in the input directory:

1. **Select & track**: compute the SHA-256 sample ID and skip samples that are
   already processed (`progress.json`, resumable).
2. **Reset the sandbox**: restore a clean snapshot, boot the VM headless and
   wait until WinRM is reachable.
3. **Execute & observe**: start the script over WinRM and observe it for a
   **fixed window** that is identical for every sample regardless of outcome
   (default 30 s, `--observation-window`). Interactive prompts (`Read-Host`,
   `-Confirm`, `pause`) are auto-answered "yes" so the script runs to
   completion instead of blocking (`--no-auto-confirm` to disable).
4. **Collect telemetry**: export the Sysmon operational log for that time
   window, parse it and strip artefacts caused by the harness itself
   (`taskkill.exe`, `C:\Tools\`, `__PSScriptPolicyTest_*`, registry noise).
   An activity check rejects runs without real PowerShell activity to avoid
   label noise.
5. **Build the sample**: static features from the script (character/token
   sequences, AST metrics, entropy, Base64 ratio, suspicious-pattern flags)
   + aggregated behaviour (process tree, file, registry, network, DNS,
   credential access, injection, persistence, timing) + the raw event sequence
   -> one JSONL line.
6. **Restore** the snapshot before the next sample (or every N samples).

Token and AST IDs are produced by a fixed, versioned vocabulary
(`vocabulary.py`): known PowerShell tokens keep a constant ID, everything else
is mapped into a fixed hash space with CRC32. The same token therefore gets the
same ID in every run and on every machine, so datasets built in several passes
stay consistent. The exact encoding is written next to the dataset as
`vocab.json` for the training project to reuse.

## Requirements

| Component | Requirement |
|---|---|
| Host OS | Windows 10/11 or Windows Server 2019+ |
| Oracle VirtualBox | 6.1+, `VBoxManage.exe` in the default path |
| Python | 3.11 or 3.12 |
| Guest VM | prepared snapshot, see below |

VM name, snapshot name and network settings are defined in `config.py`
(`MalwareExecutionConfig`) and can be overridden on the command line.

## Preparing the VM (one time)

The host drives the VM via `VBoxManage` and WinRM. Prepare the guest once, then
take a snapshot the pipeline restores before every sample.

### Host prerequisite: free the hardware virtualization

VirtualBox needs VT-x/AMD-V. On Windows 10/11 and Server, **Hyper-V, the
Virtual Machine Platform and Core Isolation / Memory Integrity (VBS/HVCI) hold
VT-x** and make the VM fail to start with `VERR_UNRESOLVED_ERROR`. Disable them
once (requires a reboot, must be done by you):

```cmd
:: run as administrator, then REBOOT
bcdedit /set hypervisorlaunchtype off
dism /Online /Disable-Feature:Microsoft-Hyper-V-All /NoRestart
dism /Online /Disable-Feature:VirtualMachinePlatform /NoRestart
```

Also turn off **Settings -> Privacy & security -> Windows Security -> Device
security -> Core isolation -> Memory integrity**, then reboot. Verify with
`Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`
(`VirtualizationBasedSecurityStatus` should be 0).

### Guest setup (inside the VM)

1. Install **Windows Server 2019/2022** (or Windows 10/11) and the **VirtualBox
   Guest Additions**.
2. Enable **auto-logon** for an administrator account (so the VM reaches a
   usable desktop after each snapshot restore without interaction).
3. Add a **host-only network adapter** and give the guest a fixed IP (default
   `192.168.56.102`). A host-only network keeps live samples off the internet.
4. Enable **WinRM** over that adapter:
   ```powershell
   Enable-PSRemoting -Force
   Set-Item WSMan:\localhost\Service\Auth\Basic $true
   Set-Item WSMan:\localhost\Service\AllowUnencrypted $true   # host-only network only
   Set-Item WSMan:\localhost\MaxEnvelopeSizekb 8192
   New-NetFirewallRule -DisplayName "WinRM 5985" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow
   ```
5. Install **Sysmon** with the bundled config:
   ```powershell
   sysmon64.exe -accepteula -i C:\path\to\vm_scripts\sysmon_config.xml
   ```
6. **Disable Microsoft Defender** real-time protection (Tamper Protection off
   first), so it does not quarantine samples or flood the telemetry.
7. Create `C:\Tools\` and `C:\Temp\`. `export_sysmon.ps1` is deployed to
   `C:\Tools\` automatically; bake it into the snapshot to use
   `--snapshot-has-tools`.

### Take the snapshot

From the host, with the VM in the prepared state:

```cmd
VBoxManage snapshot "<vm-name>" take "clean-baseline"
```

Use that snapshot name with `--snapshot-name`. From here the whole run is
automated: the pipeline restores this snapshot, boots the VM, waits for WinRM,
executes each script in the fixed window, exports Sysmon, builds the sample and
restores the snapshot again - no interaction required.

> **Tip:** to speed up large runs, also copy the input scripts into the snapshot
> (`--snapshot-has-malware`) and bake in `export_sysmon.ps1`
> (`--snapshot-has-tools`); the pipeline then skips the per-sample file copy.

## Installation

```cmd
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

Check without a VM:

```cmd
.venv\Scripts\python -c "import config, collectors, utils, malware_executor; print('OK')"
.venv\Scripts\python malware_executor.py --help
```

## Usage

Pass the VM password through the environment, never in a file:

```cmd
set MALWARE_VM_PASSWORD=...
```

Direct call:

```cmd
.venv\Scripts\python malware_executor.py ^
    --timeout 30 ^
    --vm-name "sandbox-vm" ^
    --snapshot-name "clean-baseline" ^
    --snapshot-has-tools ^
    --input-dir "C:\path\to\ps1-files" ^
    --output-dir "output\samples" ^
    --verbose
```

Or edit the paths and names in `run_malware.bat` and start it from an
administrator prompt. It powers off and resets the VM and restarts the
pipeline automatically after infrastructure failures.

### Options

| Flag | Meaning |
|---|---|
| `--observation-window N` (`--window-sec`) | fixed observation window in seconds, identical for every sample regardless of success/timeout/error (default 30) |
| `--timeout N` | hard kill for the script per sample (default: follows the observation window) |
| `--no-auto-confirm` | do **not** auto-answer interactive prompts; by default `Read-Host`/`-Confirm`/`pause` are answered "yes" so the script runs to completion instead of blocking |
| `--input-dir` / `--output-dir` | input `.ps1` folder / output folder |
| `--restore-interval N` | restore the snapshot every N scripts (1 = before each sample, default) |
| `--vm-name` / `--snapshot-name` | VirtualBox target |
| `--vm-password` | VM password (alternatively `MALWARE_VM_PASSWORD`) |
| `--snapshot-has-malware` | scripts are already inside the snapshot, skip copying |
| `--snapshot-has-tools` | `export_sysmon.ps1` is already inside the snapshot |
| `--retry-failed` | reprocess samples marked as failed |
| `--start-from SHA256` | resume from this sample |
| `--samples N` | process only the first N samples |
| `--test-run` | process 2 samples, then ask |
| `--skip-snapshot` | no snapshot restore (faster, not isolated) |
| `--verbose` | detailed logging |

## Static-only extraction without a VM (scaling)

The full sandbox produces static **and** behavioural features but runs one
sample at a time inside a VM. When only the static view is needed (character and
token sequences, AST metrics, entropy, suspicious-pattern flags and a weighted
`suspicion_score`), `extract_features.py` builds it in parallel, on any OS and
without a VM, scaling to tens of thousands of scripts. It reuses the same
`utils.build_static_features`, so the static features are identical to the
sandbox output.

```bash
python extract_features.py scripts/ --label benign --workers 8 -o benign.jsonl
python extract_features.py malware/ --label malicious --workers 8 -o malicious.jsonl
python extract_features.py one.ps1 --no-ast -o out.jsonl   # fastest, no PowerShell needed
```

Without Windows/PowerShell the tokenizer falls back to a regex tokenizer and
`--no-ast` skips the AST metrics. `vocab.json` is written next to the output.

## Output

`<output-dir>/malware_samples.jsonl` (one line per sample), `progress.json`
and logs.

```json
{
  "sample_id": "<sha256>",
  "label": "malicious",
  "static": {
    "entropy": 4.82, "char_ids": [72, 101, 108], "token_ids": [234, 12, 88],
    "has_encoding": true, "has_download": true, "has_invoke_expression": false,
    "has_obfuscation": false, "has_amsi_bypass": false, "has_dotnet_exec": true,
    "has_credential_pattern": false, "has_defense_evasion": false,
    "has_lolbin": true, "has_hidden_execution": true, "has_persistence": false
  },
  "behavioral": {
    "event_count": 1847, "registry_writes": 412, "network_connections": 2,
    "dns_queries": 1, "child_processes": 5, "file_creates": 12,
    "distinct_dest_ips": 2, "external_connections": 1, "raw_ip_connections": 1,
    "high_entropy_dns_count": 0, "lsass_access_count": 0,
    "has_credential_access": false, "injection_events": 0,
    "loads_dotnet_runtime": true, "loads_amsi": false,
    "file_deletes": 1, "deletes_script": true
  },
  "sysmon_events": [{"event_type": "ProcessCreate", "timestamp_ms": 0}],
  "metadata": {"sha256": "<sha256>", "original_filename": "sample.ps1"}
}
```

The example above shows only a subset. **The complete list of every static and
behavioural feature that is recorded - with the Sysmon event each one derives
from - is in [`docs/FEATURES.md`](docs/FEATURES.md).**

Alongside the dataset the pipeline writes `vocab.json` (the token/AST encoding)
and `progress.json`.

Despite its name, `malware_executor.py` is used for benign scripts as well;
the label is assigned by the input set.

## Files

| File | Purpose |
|---|---|
| `malware_executor.py` | orchestration: VM control (VBoxManage + WinRM), execution, sample building, persistence |
| `extract_features.py` | VM-less, parallel static feature extraction for large script sets |
| `collectors.py` | Sysmon/process event collection and parsing |
| `utils.py` | tokenizer, AST metrics, entropy/Base64, suspicious-pattern detector, behaviour aggregation |
| `vocabulary.py` | fixed, versioned token/AST vocabulary with deterministic CRC32 hashing for unknown tokens |
| `config.py` | VM/WinRM settings, timing, reset cycle, encoding limits, event vocabularies |
| `vm_scripts/export_sysmon.ps1` | runs inside the VM and exports the Sysmon log for a time window |
| `vm_scripts/sysmon_config.xml` | Sysmon configuration for the guest |
| `run_malware.bat` | launcher with VM reset and auto-restart |
| `docs/FEATURES.md` | full reference of every static and behavioural feature recorded |

## Safety

- Malicious code runs **only inside the VM**, never on the host.
- The snapshot is restored before every sample (or batch).
- Use a host-only network for WinRM. If the guest gets internet access via
  NAT, live samples can reach real infrastructure; isolate or monitor the
  network accordingly and follow your organisation's malware-handling rules.
- No malware samples are included in this repository.
