# Feature Reference

Every processed script becomes one JSONL line with four blocks:
`static`, `process`, `behavioral` and `sysmon_events` (plus `metadata`).
This document lists **all** features that are recorded, what they mean and -
for behavioural features - which Sysmon event they are derived from.

- **Static** features come from the script text alone (no execution) and are
  produced by `utils.build_static_features`. They are identical whether the
  sample is built by the sandbox (`malware_executor.py`) or by the VM-less
  extractor (`extract_features.py`).
- **Behavioural** features are aggregated from the Sysmon telemetry recorded
  during the fixed observation window, by `utils.BehaviorAggregator.aggregate`.
- **Process** features describe the executed process itself, derived from the
  Sysmon `ProcessCreate` event of the script.

All events are scoped to the **process subtree of the executed script** (see
*Process-tree scoping* below), so VM background noise is excluded.

---

## 1. Static features (`static`)

### 1.1 Sequence encodings (for sequence models)

| Field | Type | Description |
|---|---|---|
| `scriptblock_raw` | str | The raw script text. |
| `scriptblock_normalized` | str | Normalised text (lower-cased, whitespace-collapsed) for stable matching. |
| `char_ids` | int[] | Character-level encoding of the script. |
| `char_length` | int | Number of characters. |
| `tokens` | str[] | PowerShell tokens from the AST tokenizer (regex fallback off-Windows). |
| `token_ids` | int[] | Deterministic token IDs from `vocabulary.py` (fixed base vocab + CRC32 hashing for unknown tokens; stable across runs/machines). |
| `token_length` | int | Number of tokens. |

### 1.2 AST metrics

| Field | Type | Description |
|---|---|---|
| `ast_json` | obj | Serialised abstract syntax tree. |
| `ast_node_types` | str[] | AST node type names in traversal order. |
| `ast_node_type_ids` | int[] | Deterministic IDs for the node types (frozen AST vocabulary). |
| `ast_depth` | int | Maximum nesting depth of the AST. |
| `ast_node_count` | int | Total number of AST nodes. |
| `cmdlets_used` | str[] | Cmdlets referenced in the script. |

### 1.3 Scalar statistics

| Field | Type | Description |
|---|---|---|
| `entropy` | float | Shannon entropy of the script (obfuscation/packing indicator). |
| `base64_ratio` | float | Share of the script that looks like Base64 (0-1). |

### 1.4 Suspicious-pattern flags

Boolean flags produced by `SuspiciousPatternDetector.detect` after comment
stripping and light de-obfuscation. Each also contributes, with a weight, to
`suspicion_score`.

| Field | Weight | MITRE ATT&CK | Detects |
|---|---|---|---|
| `has_amsi_bypass` | 3 | T1562.001 | AMSI bypass / tampering patterns. |
| `has_credential_pattern` | 3 | T1003 | Credential access (LSASS, Mimikatz-style, SAM). |
| `has_dotnet_exec` | 2 | T1059.001 | In-memory .NET execution / reflective loading. |
| `has_defense_evasion` | 2 | T1562 | Disabling logging/AV, ETW patching, etc. |
| `has_persistence` | 2 | T1547 / T1053 | Run keys, scheduled tasks, startup persistence. |
| `has_lolbin` | 2 | T1218 | Living-off-the-land binaries (certutil, regsvr32, mshta, ...). |
| `has_obfuscation` | 2 | T1027 | String concatenation, char-code, format-operator obfuscation. |
| `has_encoding` | 1 | T1027 / T1140 | `-EncodedCommand`, Base64, gzip/deflate. |
| `has_download` | 1 | T1105 | Remote download (`DownloadString`, `Invoke-WebRequest`, BITS). |
| `has_invoke_expression` | 1 | T1059.001 | `Invoke-Expression` / `IEX`. |
| `has_reflection` | 1 | T1620 | `System.Reflection`, `GetMethod`, dynamic invoke. |
| `has_wmi` | 1 | T1047 | WMI usage (`Get-WmiObject`, `Invoke-CimMethod`). |
| `has_hidden_execution` | 1 | T1564.003 | Hidden window / non-interactive execution switches. |
| `suspicion_score` | - | - | Weighted sum of the flags above, normalised to [0, 1]. |

---

## 2. Process features (`process`)

Derived from the `ProcessCreate` event of the executed script.

| Field | Type | Description |
|---|---|---|
| `pid` | int | Process ID of the script process. |
| `parent_pid` | int | Parent process ID. |
| `parent_name` | str | Parent image name (e.g. `wsmprovhost.exe` under WinRM). |
| `grandparent_name` | str | Grandparent image name. |
| `command_line` | str | Full command line of the process. |
| `working_directory` | str | Current directory at launch. |
| `user` | str | User context the process ran as. |
| `integrity_level` | str | `Medium` / `High` / `System`. |
| `is_elevated` | bool | True if integrity level is `High` or `System`. |
| `process_chain` | str[] | `[grandparent, parent, process]` image names. |
| `process_chain_ids` | int[] | Encoded IDs of the chain names. |

---

## 3. Behavioural features (`behavioral`)

Aggregated from the scoped Sysmon telemetry of the observation window.

### 3.1 Volume & timing

| Field | Type | Sysmon source | Description |
|---|---|---|---|
| `event_count` | int | all | Total scoped events. |
| `duration_ms` | int | - | Length of the event window in ms. |
| `event_density` | float | all | Events per second. |
| `event_timestamps_ms` | int[] | all | Relative event timestamps (capped). |
| `event_deltas_ms` | int[] | all | Gaps between consecutive events (capped). |
| `first_event_delay_ms` | int | all | Delay until the first event. |
| `max_event_gap_ms` | int | all | Largest gap between events. |
| `event_type_counts` | obj | all | Count per event type. |

### 3.2 Process & child processes

| Field | Type | Sysmon source | Description |
|---|---|---|---|
| `child_processes` | int | 1 ProcessCreate | Processes spawned by the script subtree (root excluded). |
| `child_process_names` | str[] | 1 | Distinct child image names (capped). |
| `distinct_child_images` | int | 1 | Number of distinct child images. |
| `spawns_non_ps_process` / `has_non_powershell_child` | bool | 1 | A non-PowerShell child was spawned. |
| `max_child_cmdline_entropy` | float | 1 | Highest entropy among child command lines (obfuscation). |
| `child_has_encoded_command` | bool | 1 | A child used `-EncodedCommand` with a Base64 blob. |
| `has_lolbin_child` | bool | 1 | A child is a known LOLBin (certutil, regsvr32, mshta, ...). |
| `elevated_execution` | bool | 1 | A child ran at High/System integrity. |

### 3.3 File activity

| Field | Type | Sysmon source | Description |
|---|---|---|---|
| `file_creates` | int | 11 FileCreate | Files created. |
| `file_paths_created` | str[] | 11 | Created file paths (capped). |
| `writes_to_temp` | bool | 11 | A file was created under a temp path. |
| `creates_executable` | bool | 11 | A created file has an executable extension (`.exe`, `.dll`, `.ps1`, ...). |
| `file_deletes` | int | 23/26 FileDelete | Files deleted. |
| `deletes_script` | bool | 23/26 | A script file was deleted (self-deletion / cleanup). |

### 3.4 Registry activity

| Field | Type | Sysmon source | Description |
|---|---|---|---|
| `registry_writes` | int | 12/13 RegistrySetValue/CreateKey | Registry writes. |
| `registry_net_writes` | int | 12/13 | Writes to network-related keys. |
| `registry_cert_writes` | int | 12/13 | Writes to certificate stores. |
| `registry_user_writes` | int | 12/13 | Writes under HKU/HKCU. |
| `registry_system_writes` | int | 12/13 | Writes under system hives. |
| `registry_persistence_writes` | int | 12/13 | Writes to persistence keys (Run, RunOnce, ...). |
| `persistence_registry_touched` | bool | 12/13 | At least one persistence-key write. |
| `unique_registry_paths` | int | 12/13 | Distinct registry paths touched. |

### 3.5 Network & DNS

| Field | Type | Sysmon source | Description |
|---|---|---|---|
| `network_connections` | int | 3 NetworkConnect | Outbound connections. |
| `distinct_dest_ips` | int | 3 | Distinct destination IPs. |
| `distinct_dest_ports` | int | 3 | Distinct destination ports. |
| `external_connections` | int | 3 | Connections to public/routable IPs (C2 indicator). |
| `raw_ip_connections` | int | 3 | Connections to a raw IP with no hostname. |
| `uses_suspicious_port` | bool | 3 | A known-suspicious port was contacted. |
| `network_dest_entropy` | float | 3 | Max entropy of destination host/IP (DGA indicator). |
| `time_to_first_network_ms` | int | 3 | Time to first network event (`-1` if none). |
| `beaconing_regularity` | float | 3 | Regularity of connection intervals (1.0 = perfectly periodic beaconing). |
| `dns_queries` | int | 22 DnsQuery | DNS lookups. |
| `dns_query_entropy` | float | 22 | Max entropy of queried names (DGA indicator). |
| `high_entropy_dns_count` | int | 22 | Number of high-entropy DNS queries (≥ 3.5 bits). |

### 3.6 Credential access & injection

| Field | Type | Sysmon source | Description |
|---|---|---|---|
| `process_access_count` | int | 10 ProcessAccess | Cross-process handle opens. |
| `lsass_access_count` | int | 10 | Accesses targeting `lsass.exe` (credential dumping). |
| `sensitive_process_access` | int | 10 | Accesses to lsass/winlogon/csrss. |
| `has_credential_access` | bool | 10 | At least one LSASS access. |
| `create_remote_thread_count` | int | 8 CreateRemoteThread | Remote threads created. |
| `has_process_injection` | bool | 8 | At least one remote thread. |
| `injection_events` | int | 8 | Injection events (code injection indicator). |

### 3.7 In-memory .NET / AMSI

| Field | Type | Sysmon source | Description |
|---|---|---|---|
| `dlls_loaded` | int | 7 ImageLoad | Modules loaded. |
| `loads_dotnet_runtime` | bool | 7 | CLR / `System.Management.Automation` loaded (in-memory .NET). |
| `loads_amsi` | bool | 7 | `amsi.dll` loaded (AMSI interaction). |

### 3.8 WMI persistence

| Field | Type | Sysmon source | Description |
|---|---|---|---|
| `wmi_persistence_count` | int | 19/20/21 WmiEvent | WMI filter/consumer/binding events. |
| `has_wmi_persistence` | bool | 19/20/21 | At least one WMI persistence artefact. |

### 3.9 Scoping & reliability

| Field | Type | Description |
|---|---|---|
| `scoped_to_subtree` | bool | True if events were restricted to the script's process subtree. |
| `process_tree_size` | int | Number of processes in the scoped subtree. |
| `process_tree_depth` | int | Depth of the scoped subtree. |
| `behavioral_reliable` | bool | True if Sysmon was confirmed active during the run. |
| `success` | bool | Script finished with a normal exit. |
| `exit_code` | int | 0 on success, -1 otherwise. |
| `is_elevated` | bool | The script process ran elevated. |
| `parent_process_name` | str | Parent image name of the script process. |

### 3.10 Sequence encodings (for sequence models)

| Field | Type | Description |
|---|---|---|
| `event_sequence` | obj[] | Noise-aware selected event sequence. |
| `event_type_ids` | int[] | Padded event-type ID sequence (fixed length). |
| `activity_matrix` | float[][] | Binned activity matrix (time × event-type channels). |

Mirrored static scalars are also copied into `behavioral` for convenience
(`entropy`, `base64_ratio`, `has_encoding`, `has_download`,
`has_invoke_expression`, `has_reflection`, `has_wmi`, `has_obfuscation`); the
richer static flags stay in `static` only, to avoid duplicating the same signal.

---

## 4. Raw events (`sysmon_events`)

A capped, priority-ordered list of the parsed Sysmon events behind the
aggregates (network, DNS, process, registry and injection events are kept
first). Events that do not fit the cap are written to
`<output-dir>/rest_events/sysmon_<id>_rest.json`.

### Sysmon event types captured

| EventID | Type | Used for |
|---|---|---|
| 1 | ProcessCreate | process tree, child processes, elevation, LOLBins |
| 3 | NetworkConnect | connections, C2/beaconing, external/raw-IP |
| 5 | ProcessTerminate | process lifetime |
| 7 | ImageLoad | in-memory .NET / AMSI |
| 8 | CreateRemoteThread | process injection |
| 10 | ProcessAccess | credential access (LSASS) |
| 11 | FileCreate | file creation, executables, temp writes |
| 12-14 | RegistryEvent | registry writes, persistence keys |
| 15 | FileCreateStreamHash | alternate data streams |
| 19-21 | WmiEvent | WMI persistence |
| 22 | DnsQuery | DNS, DGA detection |
| 23/26 | FileDelete | self-deletion / cleanup |

---

## Process-tree scoping

The VM is a full Windows Server (domain controller, background services), so
Sysmon records far more than the script itself. Before aggregation, events are
restricted to the **process subtree of the executed script**:

1. The script is launched over WinRM as
   `winrshost.exe -> ... -> powershell.exe -EncodedCommand <base64>`.
2. The aggregator decodes the Base64 `-EncodedCommand` to find the exact
   PowerShell process that runs the script (fallback: the
   `winrshost`/`wsmprovhost` host subtree).
3. Only that process and its descendants are kept; the harness root itself is
   **not** counted as a spawned child.

This is why a benign script yields `child_processes = 0` and a small, stable
`registry_writes` baseline instead of hundreds of noise events. `scoped_to_subtree`
reports whether scoping succeeded for a given sample.
