"""Utility-Klassen für AST-Parsing, Tokenization, Varianten-Generierung und Encoding.
"""
import base64
import ipaddress
import json
import logging
import math
import os
import random
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

import config
import vocabulary

logger = logging.getLogger(__name__)


class PowerShellASTParser:
    """Parsed PowerShell-Code zu AST-JSON mittels PowerShell Parser."""

    def __init__(self) -> None:
        """Initialisiert den AST-Parser mit Cache."""
        self.node_type_vocab: Dict[str, int] = vocabulary.AST_NODE_TYPE_VOCAB
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_max = config.PERFORMANCE.ast_cache_size
        self._cache_hits = 0
        self._cache_misses = 0

    def parse(self, code: str) -> Dict[str, Any]:
        """Parsed PowerShell-Code zu AST.

        Verwendet Cache um redundante PowerShell-Prozess-Starts zu vermeiden.

        Args:
            code: PowerShell-Code als String.

        Returns:
            Dictionary mit ast_json, node_types, node_type_ids, depth, node_count.
        """
        # Cache-Lookup (spart ~0.5-1s PowerShell-Startup pro Hit)
        if code in self._cache:
            self._cache_hits += 1
            cached = self._cache[code]
            # Node-Type-IDs müssen ggf. aktualisiert werden (neue Vocab-Einträge)
            return cached.copy()

        self._cache_misses += 1

        try:
            ast_data = self._parse_with_powershell(code)
            node_types = self._extract_node_types_dfs(ast_data)
            node_type_ids = [self._get_node_type_id(nt) for nt in node_types]
            depth = self._calculate_depth(ast_data)
            node_count = len(node_types)

            result = {
                "ast_json": ast_data,
                "ast_node_types": node_types,
                "ast_node_type_ids": node_type_ids,
                "ast_depth": depth,
                "ast_node_count": node_count,
            }

            # In Cache speichern
            if len(self._cache) < self._cache_max:
                self._cache[code] = result.copy()

            if (self._cache_hits + self._cache_misses) % 200 == 0:
                logger.info(
                    f"AST-Cache: {self._cache_hits} hits, "
                    f"{self._cache_misses} misses, "
                    f"{len(self._cache)} cached"
                )

            return result
        except Exception as e:
            logger.warning(f"AST-Parsing fehlgeschlagen: {e}")
            return self._empty_ast_result()

    def _parse_with_powershell(self, code: str) -> Dict[str, Any]:
        """Führt PowerShell-Parser aus via FindAll. Temp-Datei für lange Scripts."""
        import base64
        import tempfile

        ast_logic = (
            "$ast=[System.Management.Automation.Language.Parser]::ParseInput($code,[ref]$null,[ref]$null);"
            "if(-not $ast){Write-Output '[]';exit};"
            "$all=@($ast.FindAll({param($n) $n -ne $null},$true));"
            "$idx=@{};"
            "for($i=0;$i -lt $all.Count;$i++){"
            "$hc=[System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($all[$i]);"
            "$idx[$hc]=$i};"
            "$out=@(foreach($n in $all){"
            "$ph=-1;"
            "if($n.Parent){"
            "$phc=[System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($n.Parent);"
            "if($idx.ContainsKey($phc)){$ph=$idx[$phc]}};"
            "[PSCustomObject]@{t=$n.GetType().Name;p=$ph}});"
            "try{$out|ConvertTo-Json -Compress}catch{Write-Output '[]'}"
        )

        tmp_file = None
        try:
            if len(code) <= 20000:
                code_b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")
                ps_script = f"$code=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{code_b64}'));{ast_logic}"
                cmd = ["powershell", "-NoProfile", "-Command", ps_script]
            else:
                tmp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', encoding='utf-8', delete=False)
                tmp_file.write(code)
                tmp_file.close()
                ps_script = f"$code=[IO.File]::ReadAllText('{tmp_file.name}',[Text.Encoding]::UTF8);{ast_logic}"
                cmd = ["powershell", "-NoProfile", "-Command", ps_script]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=config.PERFORMANCE.ast_timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                raw = json.loads(result.stdout.strip())
                if isinstance(raw, list) and raw:
                    return self._build_tree_from_node_list(raw)
                elif isinstance(raw, dict):
                    return self._build_tree_from_node_list([raw])
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.debug(f"PowerShell AST parsing error: {e}")
        finally:
            if tmp_file and os.path.exists(tmp_file.name):
                os.unlink(tmp_file.name)

        return {"type": "ScriptBlockAst", "children": []}

    def _build_tree_from_node_list(self, node_list: list) -> Dict[str, Any]:
        """Baut ast_json Baum aus flacher FindAll-Liste mit Parent-Indizes."""
        if not node_list:
            return {"type": "ScriptBlockAst", "children": []}

        nodes = [{"type": n.get("t", "Unknown"), "children": []} for n in node_list]

        roots: list = []
        for i, item in enumerate(node_list):
            p_idx = item.get("p", -1)
            if p_idx == -1 or not isinstance(p_idx, int) or p_idx >= len(nodes) or p_idx == i:
                roots.append(nodes[i])
            else:
                nodes[p_idx]["children"].append(nodes[i])

        return roots[0] if roots else {"type": "ScriptBlockAst", "children": []}

    def _extract_node_types_dfs(self, ast_node: Dict[str, Any]) -> List[str]:
        """Extrahiert Node-Typen in DFS-Reihenfolge."""
        if not ast_node:
            return []

        result = [ast_node.get("type", "Unknown")]
        for child in ast_node.get("children", []):
            result.extend(self._extract_node_types_dfs(child))
        return result

    def _get_node_type_id(self, node_type: str) -> int:
        """Gibt die feste ID für einen Node-Typ zurück (<UNK> wenn unbekannt)."""
        return vocabulary.ast_node_type_id(node_type)

    def _calculate_depth(self, ast_node: Dict[str, Any], current_depth: int = 0) -> int:
        """Berechnet maximale Tiefe des AST."""
        if not ast_node:
            return current_depth

        max_depth = current_depth + 1
        for child in ast_node.get("children", []):
            child_depth = self._calculate_depth(child, current_depth + 1)
            max_depth = max(max_depth, child_depth)
        return max_depth

    def _empty_ast_result(self) -> Dict[str, Any]:
        """Gibt leeres AST-Ergebnis zurück."""
        return {
            "ast_json": {"type": "Empty", "children": []},
            "ast_node_types": ["Empty"],
            "ast_node_type_ids": [self._get_node_type_id("Empty")],
            "ast_depth": 1,
            "ast_node_count": 1,
        }

    def get_vocabulary(self) -> Dict[str, int]:
        """Gibt aktuelles Node-Type-Vocabulary zurück."""
        return self.node_type_vocab.copy()


class PowerShellTokenizer:
    """Tokenisiert PowerShell-Code für ML-Modelle."""

    def __init__(self) -> None:
        """Initialisiert Tokenizer mit festen Vocabularies."""
        self.token_vocab_size = config.TOKEN_VOCAB_SIZE
        self.char_vocab: Dict[str, int] = {"<PAD>": 0, "<UNK>": 1}
        self._next_char_id = 2
        self._init_char_vocab()
        self._cache: Dict[str, List[str]] = {}
        self._cache_max = 1000

    def _init_char_vocab(self) -> None:
        """Initialisiert Char-Vocabulary mit druckbaren ASCII-Zeichen."""
        for i in range(32, 127):
            char = chr(i)
            self.char_vocab[char] = self._next_char_id
            self._next_char_id += 1

    def tokenize(self, code: str) -> Dict[str, Any]:
        """Tokenisiert PowerShell-Code.

        Args:
            code: PowerShell-Code als String.

        Returns:
            Dictionary mit tokens, token_ids, char_ids und Längen.
        """
        # Null-Bytes entfernen (UTF-16-kodierte oder binary-gemischte Scripts crashen subprocess.run)
        code = code.replace('\x00', '')

        if code in self._cache:
            tokens = self._cache[code]
        else:
            tokens = self._tokenize_with_powershell(code)
            if not tokens:
                tokens = self._tokenize_with_regex(code)
            if len(self._cache) < self._cache_max:
                self._cache[code] = tokens

        token_ids = [self._get_token_id(t) for t in tokens]
        char_ids = [self._get_char_id(c) for c in code]

        # Truncate to max lengths
        tokens = tokens[:config.MAX_TOKEN_LENGTH]
        token_ids = token_ids[:config.MAX_TOKEN_LENGTH]
        char_ids = char_ids[:config.MAX_CHAR_LENGTH]

        # Padding nur wenn konfiguriert
        store_without_padding = getattr(config, 'STORE_WITHOUT_PADDING', False)

        if store_without_padding:
            # Keine Padding - nur echte Daten speichern
            return {
                "tokens": tokens,
                "token_ids": token_ids,
                "token_length": len(tokens),
                "char_ids": char_ids,
                "char_length": len(char_ids),
            }
        else:
            # Mit Padding auf feste Länge
            return {
                "tokens": tokens,
                "token_ids": self.pad_sequence(token_ids, config.MAX_TOKEN_LENGTH),
                "token_length": len(tokens),
                "char_ids": self.pad_sequence(char_ids, config.MAX_CHAR_LENGTH),
                "char_length": len(char_ids),
            }

    def _tokenize_with_powershell(self, code: str) -> List[str]:
        """Tokenisiert mittels PowerShell Parser."""
        # CreateProcessW limit is 32767 chars; with heavy ' escaping worst-case ~2x expansion
        if len(code) > 15000:
            return []

        ps_script = '''
$code = @'
{code}
'@

$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$errors)

$tokens | ForEach-Object {{ $_.Text }} | Where-Object {{ $_ }}
'''.format(code=code.replace("'", "''"))

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=1.5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return [t for t in result.stdout.strip().split('\n') if t]
        except subprocess.TimeoutExpired:
            pass
        return []

    def _tokenize_with_regex(self, code: str) -> List[str]:
        """Fallback-Tokenisierung mit Regex."""
        pattern = r'''
            (\$[\w:]+)|                      # Variables
            ([A-Za-z][\w-]*)|                # Identifiers/Cmdlets
            (\d+\.?\d*)|                     # Numbers
            (\"[^\"]*\"|\'[^\']*\')|         # Strings
            ([|;,\(\)\[\]\{\}@])|            # Operators
            ([-+*/%=<>!]+)|                  # Math/comparison operators
            (\S)                             # Other non-whitespace
        '''
        matches = re.findall(pattern, code, re.VERBOSE)
        return [m for group in matches for m in group if m]

    def _get_token_id(self, token: str) -> int:
        """Gibt eine deterministische, laufunabhängige ID für ein Token zurück."""
        return vocabulary.token_id(token, self.token_vocab_size)

    def _get_char_id(self, char: str) -> int:
        """Gibt ID für Zeichen zurück."""
        return self.char_vocab.get(char, self.char_vocab["<UNK>"])

    def pad_sequence(self, ids: List[int], max_len: int) -> List[int]:
        """Padded oder kürzt Sequenz auf max_len."""
        if len(ids) >= max_len:
            return ids[:max_len]
        return ids + [0] * (max_len - len(ids))

    def get_vocabulary(self) -> Dict[str, Dict[str, int]]:
        """Gibt das feste Token-Basisvocabulary und das Char-Vocabulary zurück."""
        return {
            "tokens": vocabulary.TOKEN_BASE_VOCAB.copy(),
            "chars": self.char_vocab.copy(),
        }


class BehaviorAggregator:
    """Aggregiert Sysmon-Events zu Verhaltens-Features."""

    def __init__(self) -> None:
        """Initialisiert Aggregator."""
        self.event_type_vocab = config.EVENT_TYPES.copy()

    # Registry path patterns für Kategorisierung
    _REG_NET_PATTERNS = (
        "\\Tcpip\\", "\\NetworkList\\", "\\DNS\\", "\\Winsock",
        "\\NlsData", "\\Internet Settings\\ZoneMap",
    )
    _REG_CERT_PATTERNS = (
        "\\Certificates\\", "\\Disallowed\\", "\\EnterpriseCertificates\\",
        "\\SystemCertificates\\", "\\Policies\\Microsoft\\SystemCertificates",
    )
    _REG_PERSISTENCE_PATTERNS = (
        "\\Run\\", "\\RunOnce\\", "\\RunOnceEx\\",
        "\\Startup\\", "\\StartMenu\\",
        "\\CurrentVersion\\App Paths\\",
        "\\Winlogon\\", "\\Active Setup\\",
    )
    _TEMP_PATTERNS = (
        "\\Temp\\", "\\temp\\", "AppData\\Local\\Temp",
        "\\Temporary Internet Files\\",
    )
    _EXEC_EXTENSIONS = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr")

    # Living-off-the-Land-Binaries, die als Kindprozess auf Missbrauch hindeuten.
    _LOLBIN_IMAGES = (
        "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
        "regsvcs.exe", "wmic.exe", "cmstp.exe", "msiexec.exe",
    )
    # Ports, die häufig für C2/Reverse-Shells genutzt werden (nicht die
    # Standard-Web-Ports, um False Positives zu vermeiden).
    _SUSPICIOUS_PORTS = frozenset({4444, 1337, 31337, 6667, 6697, 8443, 9001, 1234, 5555, 12345})

    # ImageLoad/RegistryCreateKey sind PowerShell-Engine-Startrauschen (~90/~150 Events vor
    # dem eigentlichen Skriptstart) - bei naivem Prefix-Cut füllen sie fast alle Slots in
    # event_sequence/event_type_ids und verdrängen die eigentlichen Verhaltens-Events.
    _SEQUENCE_NOISE_TYPES = {"ImageLoad", "RegistryCreateKey"}

    def _scope_to_subtree(
        self, events: List[Dict[str, Any]], root_hint: str
    ) -> Tuple[List[Dict[str, Any]], bool, int, int]:
        """Beschränkt Events auf den Prozessbaum des ausgeführten Skripts.

        Die VM läuft als Active-Directory-DC mit Diensten, Fake-Azure usw. und
        erzeugt ständig Hintergrund-Events (Registry, Prozesse, Netzwerk). Ohne
        Einschränkung dominiert dieses Rauschen jede Probe. Hier wird die per
        WinRM gestartete PowerShell (ProcessCreate mit dem Skriptnamen in der
        Kommandozeile) als Wurzel bestimmt und nur sie plus alle Nachkommen
        (über ParentProcessGuid) behalten; alle Events ohne process_guid im
        Teilbaum werden verworfen.

        Returns (gefilterte Events, ob gescoped, Baumgröße, Baumtiefe).
        Findet sich keine Wurzel, werden die Events unverändert zurückgegeben.
        """
        rh = (root_hint or "").lower()

        # WinRM führt jedes Kommando als winrshost.exe -> cmd.exe -> powershell.exe
        # aus (Skriptname ist base64-kodiert, daher nicht im Klartext). Stabiler
        # Anker ist deshalb der WinRM-Host selbst: dessen Prozesse plus alle
        # Nachkommen sind genau das, was die Ausführung ausgelöst hat; OS-Dienste
        # (svchost, services, silcollector ...) liegen außerhalb.
        winrm_hosts = ("winrshost.exe", "wsmprovhost.exe")
        children: Dict[str, list] = defaultdict(list)
        precise_roots: list = []   # genau die Skript-PowerShell (dekodierter Befehl)
        host_roots: list = []      # Fallback: alles unter dem WinRM-Host
        for e in events:
            if e.get("type") != "ProcessCreate":
                continue
            f = e.get("features", {})
            guid = f.get("process_guid") or ""
            parent = f.get("parent_process_guid") or ""
            if guid:
                children[parent].append(guid)
            if not guid:
                continue
            img = (f.get("image") or "").lower()
            pimg = (f.get("parent_image") or "").lower()
            cmd = f.get("command_line") or ""
            if any(img.endswith(h) for h in winrm_hosts) or any(pimg.endswith(h) for h in winrm_hosts):
                host_roots.append(guid)
            # Präzise: Skriptname im Klartext ODER im dekodierten -EncodedCommand.
            if rh and (rh in cmd.lower() or rh in _decode_encoded_command(cmd)):
                precise_roots.append(guid)

        roots = precise_roots or host_roots
        if not roots:
            return events, False, 0, 0, set()

        # Nachkommen per BFS einsammeln und dabei die Tiefe messen.
        keep: set = set()
        depth = 0
        frontier = list(roots)
        while frontier:
            nxt = []
            for guid in frontier:
                if guid in keep:
                    continue
                keep.add(guid)
                nxt.extend(children.get(guid, []))
            if nxt:
                depth += 1
            frontier = nxt

        scoped = [e for e in events if (e.get("features", {}).get("process_guid") or "") in keep]
        return scoped, True, len(keep), depth, set(roots)

    def aggregate(
        self,
        events: List[Dict[str, Any]],
        start_ms: int,
        end_ms: int,
        root_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Aggregiert Events zu Verhaltens-Features.

        Args:
            events: Liste von Sysmon-Events.
            start_ms: Start-Timestamp in Millisekunden.
            end_ms: End-Timestamp in Millisekunden.

        Returns:
            Dictionary mit aggregierten Verhaltens-Features.
        """
        # Zuerst auf den Prozessbaum des Skripts einschränken (entfernt
        # VM-Hintergrundrauschen von Diensten/AD/Azure).
        events, scoped_to_subtree, process_tree_size, process_tree_depth, root_guids = \
            self._scope_to_subtree(events, root_hint)

        # __PSScriptPolicyTest_*.ps1/.psm1 werden von der PS-Engine bei JEDEM Skriptstart
        # erzeugt (Execution-Policy-Check). Ohne Filter wäre creates_executable immer True.
        events = [
            e for e in events
            if not (
                e.get("type") == "FileCreate"
                and "__PSScriptPolicyTest_" in e.get("features", {}).get("target_filename", "")
            )
        ]

        duration_ms = max(end_ms - start_ms, 1)

        counts = self._count_events(events)
        event_sequence = self._build_event_sequence(events, start_ms)
        selected_sequence = self._select_sequence_events(event_sequence, config.MAX_EVENT_LENGTH)
        event_type_ids = [e["type_id"] for e in selected_sequence]
        activity_matrix = self._build_activity_matrix(events, start_ms, duration_ms)

        # --- Temporal features ---
        rel_timestamps = sorted(
            e["timestamp_ms"] for e in event_sequence if e.get("timestamp_ms") is not None
        )
        if rel_timestamps:
            event_deltas_ms = [
                rel_timestamps[i + 1] - rel_timestamps[i]
                for i in range(len(rel_timestamps) - 1)
            ]
            first_event_delay_ms = rel_timestamps[0]
            max_event_gap_ms = max(event_deltas_ms) if event_deltas_ms else 0
        else:
            event_deltas_ms = []
            first_event_delay_ms = 0
            max_event_gap_ms = 0
        event_density = round(len(events) / max(duration_ms / 1000.0, 0.001), 4)

        # --- Registry categorisation ---
        reg_net = reg_cert = reg_user = reg_sys = reg_persist = 0
        reg_paths_seen: set = set()
        for ev in events:
            t = ev.get("type", "")
            if t not in ("RegistrySetValue", "RegistryCreateKey", "RegistryDeleteKey"):
                continue
            path = ev.get("features", {}).get("target_object", "")
            if not path:
                continue
            reg_paths_seen.add(path)
            if any(p in path for p in self._REG_PERSISTENCE_PATTERNS):
                reg_persist += 1
            if any(p in path for p in self._REG_CERT_PATTERNS):
                reg_cert += 1
            elif any(p in path for p in self._REG_NET_PATTERNS):
                reg_net += 1
            elif path.startswith("HKU\\") or path.startswith("HKCU\\"):
                reg_user += 1
            else:
                reg_sys += 1

        # --- Lists ---
        file_paths_created: List[str] = []
        for ev in events:
            if ev.get("type") == "FileCreate":
                fp = ev.get("features", {}).get("target_filename", "")
                if fp:
                    file_paths_created.append(fp)

        # --- DNS/Netzwerk-Entropie (DGA-Erkennung) ---
        dns_query_entropies: List[float] = []
        for ev in events:
            if ev.get("type") == "DnsQuery":
                query_name = ev.get("features", {}).get("query_name", "")
                if query_name:
                    dns_query_entropies.append(EntropyCalculator.calculate(query_name))

        network_dest_entropies: List[float] = []
        for ev in events:
            if ev.get("type") == "NetworkConnect":
                features = ev.get("features", {})
                dest = features.get("dest_hostname") or features.get("dest_ip", "")
                if dest:
                    network_dest_entropies.append(EntropyCalculator.calculate(dest))

        dns_query_entropy = max(dns_query_entropies) if dns_query_entropies else 0.0
        network_dest_entropy = max(network_dest_entropies) if network_dest_entropies else 0.0

        child_process_names: List[str] = []
        spawns_non_ps = False
        for ev in events:
            if ev.get("type") == "ProcessCreate":
                f = ev.get("features", {})
                if (f.get("process_guid") or "") in root_guids:
                    continue  # Wurzel (Skript-PowerShell) ist kein gespawntes Kind
                img = f.get("image", "")
                name = img.split("\\")[-1] if img else ""
                if name:
                    child_process_names.append(name)
                if name and name.lower() not in ("powershell.exe", "pwsh.exe", ""):
                    spawns_non_ps = True

        # --- Netzwerk-Diversitaet (C2-/DGA-Indikatoren) ---
        dest_ips: set = set()
        dest_ports: set = set()
        external_connections = 0
        raw_ip_connections = 0
        for ev in events:
            if ev.get("type") != "NetworkConnect":
                continue
            f = ev.get("features", {})
            ip = f.get("dest_ip", "")
            if ip:
                dest_ips.add(ip)
                if self._is_external_ip(ip):
                    external_connections += 1
            port = f.get("dest_port")
            if port:
                dest_ports.add(port)
            if ip and not f.get("dest_hostname"):
                raw_ip_connections += 1
        high_entropy_dns_count = sum(1 for e in dns_query_entropies if e >= 3.5)

        # --- Credential Access / Injektion (ProcessAccess, CreateRemoteThread) ---
        lsass_access = 0
        sensitive_process_access = 0
        injection_events = 0
        for ev in events:
            t = ev.get("type")
            target = ev.get("features", {}).get("target_image", "").lower()
            if t == "ProcessAccess":
                if target.endswith("lsass.exe"):
                    lsass_access += 1
                if target.endswith(("lsass.exe", "winlogon.exe", "csrss.exe")):
                    sensitive_process_access += 1
            elif t == "CreateRemoteThread":
                injection_events += 1

        # --- In-Memory-.NET / AMSI (ImageLoad) ---
        loads_dotnet = False
        loads_amsi = False
        for ev in events:
            if ev.get("type") != "ImageLoad":
                continue
            loaded = ev.get("features", {}).get("image_loaded", "").lower()
            if loaded.endswith(("clr.dll", "clrjit.dll", "mscoree.dll")) or "system.management.automation" in loaded:
                loads_dotnet = True
            if loaded.endswith("amsi.dll"):
                loads_amsi = True

        # --- Datei-Loeschung (Cleanup / Selbstloeschung) ---
        file_deletes = 0
        deletes_script = False
        for ev in events:
            if ev.get("type") != "FileDelete":
                continue
            file_deletes += 1
            fn = ev.get("features", {}).get("target_filename", "").lower()
            if fn.endswith((".ps1", ".psm1", ".bat", ".cmd", ".vbs")):
                deletes_script = True

        # --- Kindprozesse: Kommandozeilen, Elevation, LOLBins (reale Felder) ---
        max_child_cmdline_entropy = 0.0
        child_has_encoded_command = False
        has_lolbin_child = False
        elevated_execution = False
        distinct_child_images: set = set()
        for ev in events:
            if ev.get("type") != "ProcessCreate":
                continue
            f = ev.get("features", {})
            if (f.get("process_guid") or "") in root_guids:
                continue  # Wurzel selbst nicht als Kind werten
            img = f.get("image", "")
            name = img.split("\\")[-1].lower() if img else ""
            if name:
                distinct_child_images.add(name)
            if name in self._LOLBIN_IMAGES:
                has_lolbin_child = True
            cmdline = f.get("command_line", "")
            if cmdline:
                max_child_cmdline_entropy = max(
                    max_child_cmdline_entropy, EntropyCalculator.calculate(cmdline)
                )
                if re.search(r'-e(nc|ncodedcommand)?\b\s+[A-Za-z0-9+/=]{16,}', cmdline, re.IGNORECASE):
                    child_has_encoded_command = True
            if f.get("integrity_level", "").lower() in ("high", "system"):
                elevated_execution = True

        # --- Netzwerk-Timing/Beaconing (reale Timestamps/Ports) ---
        net_ts = sorted(
            e.get("timestamp_ms", start_ms) - start_ms
            for e in events if e.get("type") == "NetworkConnect"
        )
        time_to_first_network_ms = net_ts[0] if net_ts else -1
        beaconing_regularity = 0.0
        if len(net_ts) >= 3:
            deltas = [net_ts[i + 1] - net_ts[i] for i in range(len(net_ts) - 1)]
            mean_delta = sum(deltas) / len(deltas)
            if mean_delta > 0:
                variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                cv = (variance ** 0.5) / mean_delta
                beaconing_regularity = round(max(0.0, 1.0 - cv), 4)  # 1.0 = perfekt gleichmäßig
        uses_suspicious_port = any(
            e.get("features", {}).get("dest_port") in self._SUSPICIOUS_PORTS
            for e in events if e.get("type") == "NetworkConnect"
        )

        # --- Derived flags ---
        writes_to_temp = any(
            any(p in fp for p in self._TEMP_PATTERNS)
            for fp in file_paths_created
        )
        creates_executable = any(
            fp.lower().endswith(self._EXEC_EXTENSIONS)
            for fp in file_paths_created
        )
        persistence_registry_touched = reg_persist > 0

        return {
            # Existing scalar counts
            "duration_ms": duration_ms,
            "file_creates": counts.get("FileCreate", 0),
            "registry_writes": counts.get("RegistrySetValue", 0) + counts.get("RegistryCreateKey", 0),
            "network_connections": counts.get("NetworkConnect", 0),
            "dns_queries": counts.get("DnsQuery", 0),
            "dns_query_entropy": dns_query_entropy,
            "network_dest_entropy": network_dest_entropy,
            "high_entropy_dns_count": high_entropy_dns_count,
            "distinct_dest_ips": len(dest_ips),
            "distinct_dest_ports": len(dest_ports),
            "external_connections": external_connections,
            "raw_ip_connections": raw_ip_connections,
            "dlls_loaded": counts.get("ImageLoad", 0),
            "child_processes": sum(
                1 for ev in events
                if ev.get("type") == "ProcessCreate"
                and (ev.get("features", {}).get("process_guid") or "") not in root_guids
            ),
            "event_count": len(events),
            # Temporal
            "event_timestamps_ms": rel_timestamps[:config.MAX_EVENT_LENGTH],
            "event_deltas_ms": event_deltas_ms[:config.MAX_EVENT_LENGTH],
            "event_density": event_density,
            "first_event_delay_ms": first_event_delay_ms,
            "max_event_gap_ms": max_event_gap_ms,
            # Registry breakdown
            "registry_net_writes": reg_net,
            "registry_cert_writes": reg_cert,
            "registry_user_writes": reg_user,
            "registry_system_writes": reg_sys,
            "registry_persistence_writes": reg_persist,
            "unique_registry_paths": len(reg_paths_seen),
            # Lists
            "file_paths_created": file_paths_created[:20],
            "child_process_names": list(dict.fromkeys(child_process_names))[:10],
            # Flags
            "spawns_non_ps_process": spawns_non_ps,
            "has_non_powershell_child": spawns_non_ps,
            "writes_to_temp": writes_to_temp,
            "creates_executable": creates_executable,
            "persistence_registry_touched": persistence_registry_touched,
            # Process Injection (Sysmon EventID 8/10) + WMI-Persistenz (EventID 19-21)
            "create_remote_thread_count": counts.get("CreateRemoteThread", 0),
            "process_access_count": counts.get("ProcessAccess", 0),
            "has_process_injection": counts.get("CreateRemoteThread", 0) > 0,
            "injection_events": injection_events,
            "lsass_access_count": lsass_access,
            "sensitive_process_access": sensitive_process_access,
            "has_credential_access": lsass_access > 0,
            "loads_dotnet_runtime": loads_dotnet,
            "loads_amsi": loads_amsi,
            "file_deletes": file_deletes,
            "deletes_script": deletes_script,
            "scoped_to_subtree": scoped_to_subtree,
            "process_tree_size": process_tree_size,
            "process_tree_depth": process_tree_depth,
            "distinct_child_images": len(distinct_child_images),
            "max_child_cmdline_entropy": round(max_child_cmdline_entropy, 4),
            "child_has_encoded_command": child_has_encoded_command,
            "has_lolbin_child": has_lolbin_child,
            "elevated_execution": elevated_execution,
            "time_to_first_network_ms": time_to_first_network_ms,
            "beaconing_regularity": beaconing_regularity,
            "uses_suspicious_port": uses_suspicious_port,
            "wmi_persistence_count": (
                counts.get("WmiEventFilter", 0)
                + counts.get("WmiEventConsumer", 0)
                + counts.get("WmiEventConsumerToFilter", 0)
            ),
            "has_wmi_persistence": (
                counts.get("WmiEventFilter", 0)
                + counts.get("WmiEventConsumer", 0)
                + counts.get("WmiEventConsumerToFilter", 0)
            ) > 0,
            # Event type breakdown
            "event_type_counts": counts,
            # Sequence (noise-aware selection, dann padding)
            "event_sequence": selected_sequence,
            "event_type_ids": self._pad_sequence(event_type_ids, config.MAX_EVENT_LENGTH),
            "activity_matrix": activity_matrix,
        }

    @staticmethod
    def _is_external_ip(ip: str) -> bool:
        """Prüft, ob eine IP öffentlich routbar ist (C2-Indikator).

        Nutzt ipaddress.is_global und deckt damit IPv4 und IPv6 korrekt ab
        (privat, loopback, link-local, reserviert zählen als nicht extern).
        """
        if not ip:
            return False
        try:
            return ipaddress.ip_address(ip.split("%", 1)[0]).is_global
        except ValueError:
            return False

    def _count_events(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Zählt Events nach Typ."""
        counter: Counter[str] = Counter()
        for event in events:
            event_type = event.get("type", "Unknown")
            counter[event_type] += 1
        return dict(counter)

    def _build_event_sequence(
        self,
        events: List[Dict[str, Any]],
        start_ms: int
    ) -> List[Dict[str, Any]]:
        """Baut Event-Sequenz für Sequence-Models."""
        sequence = []
        for event in sorted(events, key=lambda e: e.get("timestamp_ms", 0)):
            event_type = event.get("type", "Unknown")
            type_id = self.event_type_vocab.get(event_type, self.event_type_vocab["<UNK>"])
            relative_ts = event.get("timestamp_ms", start_ms) - start_ms

            sequence.append({
                "type": event_type,
                "type_id": type_id,
                "timestamp_ms": relative_ts,
                "features": event.get("features", {}),
            })
        return sequence

    def _select_sequence_events(
        self,
        event_sequence: List[Dict[str, Any]],
        limit: int,
    ) -> List[Dict[str, Any]]:
        """Wählt bis zu `limit` Events für event_sequence/event_type_ids aus.

        Bevorzugt Events außerhalb von _SEQUENCE_NOISE_TYPES (ImageLoad,
        RegistryCreateKey), damit ein reiner Prefix-Cut nicht ausschließlich
        das PowerShell-Engine-Startrauschen erfasst. Restplätze werden
        chronologisch mit den Rauschen-Events aufgefüllt.
        """
        if len(event_sequence) <= limit:
            return event_sequence

        interesting = [e for e in event_sequence if e.get("type") not in self._SEQUENCE_NOISE_TYPES]
        noise = [e for e in event_sequence if e.get("type") in self._SEQUENCE_NOISE_TYPES]

        if len(interesting) >= limit:
            selected = interesting[:limit]
        else:
            selected = interesting + noise[:limit - len(interesting)]

        selected.sort(key=lambda e: e.get("timestamp_ms", 0))
        return selected

    def _build_activity_matrix(
        self,
        events: List[Dict[str, Any]],
        start_ms: int,
        duration_ms: int
    ) -> List[List[float]]:
        """Baut Activity Matrix [6 features × 50 time_bins].

        Features:
            0: file_create
            1: file_modify
            2: registry
            3: network
            4: dns
            5: process_spawn
        """
        num_features = config.ACTIVITY_MATRIX_FEATURES
        num_bins = config.ACTIVITY_MATRIX_BINS
        matrix = [[0.0] * num_bins for _ in range(num_features)]

        type_to_feature = {
            "FileCreate": 0,
            "FileDelete": 1,
            "RegistrySetValue": 2,
            "RegistryCreateKey": 2,
            "RegistryDeleteKey": 2,
            "NetworkConnect": 3,
            "DnsQuery": 4,
            "ProcessCreate": 5,
        }

        for event in events:
            event_type = event.get("type")
            feature_idx = type_to_feature.get(event_type)
            if feature_idx is None:
                continue

            event_ts = event.get("timestamp_ms", start_ms)
            relative_ts = event_ts - start_ms
            bin_idx = min(int((relative_ts / duration_ms) * num_bins), num_bins - 1)
            bin_idx = max(0, bin_idx)

            matrix[feature_idx][bin_idx] += 1.0

        self._normalize_matrix(matrix)
        return matrix

    def _normalize_matrix(self, matrix: List[List[float]]) -> None:
        """Normalisiert Matrix-Werte auf [0.0, 1.0]."""
        for row in matrix:
            max_val = max(row) if row else 1.0
            if max_val > 0:
                for i in range(len(row)):
                    row[i] = row[i] / max_val

    def _pad_sequence(self, ids: List[int], max_len: int) -> List[int]:
        """Padded Sequenz auf max_len."""
        if len(ids) >= max_len:
            return ids[:max_len]
        return ids + [0] * (max_len - len(ids))

    def build_matrix(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Baut Activity Matrix aus Events (öffentliche Methode für Malware-Executor).

        Args:
            events: Liste von Events mit 'type' und 'timestamp_ms'.

        Returns:
            numpy Array [6 features × 50 time_bins].
        """
        if not events:
            return np.zeros((config.ACTIVITY_MATRIX_FEATURES, config.ACTIVITY_MATRIX_BINS))

        # Timestamps extrahieren
        timestamps = [e.get("timestamp_ms", 0) for e in events]
        start_ms = min(timestamps) if timestamps else 0
        end_ms = max(timestamps) if timestamps else start_ms + 1000
        duration_ms = max(end_ms - start_ms, 1)

        matrix = self._build_activity_matrix(events, start_ms, duration_ms)
        return np.array(matrix)


class EntropyCalculator:
    """Berechnet Shannon-Entropie von Text."""

    @staticmethod
    def calculate(text: str) -> float:
        """Berechnet Shannon-Entropie.

        Args:
            text: Input-Text.

        Returns:
            Entropie-Wert als Float.
        """
        if not text:
            return 0.0

        freq = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)

        return round(entropy, 4)


class SuspiciousPatternDetector:
    """Erkennt verdächtige Muster in PowerShell-Code."""

    ENCODING_PATTERNS = [
        r'FromBase64String',
        r'\[Convert\]::',
        r'-EncodedCommand',
        r'-enc\b',
        r'::Decompress',
        r'GZipStream',
    ]

    DOWNLOAD_PATTERNS = [
        r'Invoke-WebRequest',
        r'Invoke-RestMethod',
        r'WebClient',
        r'DownloadString',
        r'DownloadFile',
        r'Net\.WebClient',
        r'BitsTransfer',
        r'curl\b',
        r'wget\b',
        r'iwr\b',
        r'irm\b',
    ]

    INVOKE_EXPRESSION_PATTERNS = [
        r'Invoke-Expression',
        r'\biex\b',
        r'\.Invoke\(',
        r'Invoke-Command',
        r'icm\b',
    ]

    REFLECTION_PATTERNS = [
        r'\[Reflection\.',
        r'GetMethod\(',
        r'Assembly::Load',
        r'DynamicInvoke',
        r'\[System\.Reflection\.',
    ]

    WMI_PATTERNS = [
        r'Get-WmiObject',
        r'gwmi\b',
        r'Get-CimInstance',
        r'gcim\b',
        r'Invoke-WmiMethod',
        r'Set-WmiInstance',
        r'Register-WmiEvent',
        r'__EventFilter',
        r'CommandLineEventConsumer',
    ]

    # AMSI-Umgehung (Defense Evasion, T1562.001)
    AMSI_BYPASS_PATTERNS = [
        r'amsiInitFailed',
        r'AmsiUtils',
        r'AmsiScanBuffer',
        r'System\.Management\.Automation\.AmsiUtils',
        r'\[Ref\]\.Assembly\.GetType',
    ]

    # In-Memory-/.NET-Ausfuehrung und Shellcode-Injektion (T1055, T1620)
    DOTNET_EXEC_PATTERNS = [
        r'Add-Type',
        r'DllImport',
        r'VirtualAlloc',
        r'VirtualProtect',
        r'WriteProcessMemory',
        r'CreateRemoteThread',
        r'CreateThread',
        r'NtCreateThreadEx',
        r'memset\b',
        r'GetDelegateForFunctionPointer',
        r'Marshal::',
        r'OpenProcess',
    ]

    # Zugriff auf Anmeldeinformationen (T1003, T1555)
    CREDENTIAL_PATTERNS = [
        r'Mimikatz',
        r'sekurlsa',
        r'logonpasswords',
        r'Invoke-Mimikatz',
        r'lsass',
        r'MiniDump',
        r'comsvcs\.dll',
        r'Get-Credential',
        r'ConvertFrom-SecureString',
        r'vaultcli',
    ]

    # Deaktivieren von Schutzmechanismen und Spurenverwischung (T1562, T1070)
    DEFENSE_EVASION_PATTERNS = [
        r'Set-MpPreference',
        r'Add-MpPreference',
        r'DisableRealtimeMonitoring',
        r'-ExclusionPath',
        r'-ExclusionExtension',
        r'Clear-EventLog',
        r'wevtutil\s+(cl|clear-log)',
        r'Remove-Item.{0,40}MpPreference',
        r'Set-ExecutionPolicy\s+Bypass',
    ]

    # Living-off-the-Land-Binaries (T1218)
    LOLBIN_PATTERNS = [
        r'\bcertutil\b',
        r'\bbitsadmin\b',
        r'\bregsvr32\b',
        r'\bmshta\b',
        r'\brundll32\b',
        r'\bmsbuild\b',
        r'\binstallutil\b',
        r'\bregasm\b',
        r'\bregsvcs\b',
        r'\bwmic\b',
    ]

    # Versteckte/unbeaufsichtigte Ausfuehrung (T1059.001)
    HIDDEN_EXEC_PATTERNS = [
        r'-WindowStyle\s+Hidden',
        r'-w\s+hidden',
        r'-NonInteractive',
        r'-noni\b',
        r'-NoProfile',
        r'-nop\b',
        r'-ExecutionPolicy\s+Bypass',
        r'-ep\s+bypass',
        r'-EncodedCommand',
        r'-enc\b',
    ]

    # Persistenz-Mechanismen (T1053, T1543, T1547)
    PERSISTENCE_PATTERNS = [
        r'schtasks',
        r'Register-ScheduledTask',
        r'New-ScheduledTask',
        r'New-Service',
        r'sc\s+create',
        r'CurrentVersion\\Run',
        r'Startup',
        r'Set-ItemProperty.{0,60}Run',
    ]

    OBFUSCATION_PATTERNS = [
        r'-join\s*\(\s*[\'"]{0,1}[\'"]{0,1}\s*\)',  # -join('')/-join("") - Char-Array-Reassembly
        r'-f\s*\(?\s*\[char\]',                       # Format-Operator mit [char]
        r'\[char\[\]\]',                              # Char-Array-Cast
        r'(\[char\]\s*\d+\s*\+\s*){2,}',              # [char]NN + [char]NN + ...
        r'-join\s*\(.{0,100}?\[char\]',               # -join(... | ForEach-Object {[char]$_})
        r"['\"][A-Za-z-]{2,}['\"].?\+.?['\"][A-Za-z-]{2,}['\"]",  # 'Wri'+'te-Ho'+'st' String-Concat
        r'`[A-Za-z]',                                  # Backtick-Obfuscation: W`rite-H`ost
    ]

    # Zählbasierte Schwellwerte: einzelne [char]/-replace Treffer sind in benignem Code häufig
    # (ANSI-Farbcodes, Pfad-Bereinigung). Erst mehrere deuten auf echte Obfuskation hin.
    _CHAR_CAST_TOTAL_THRESHOLD = 5
    _CHAR_CAST_WITH_JOIN_THRESHOLD = 2
    _REPLACE_CHAIN_THRESHOLD = 3

    # Gewichte für den suspicion_score: schwere Techniken (AMSI-Bypass,
    # Credential Access, Injektion) zählen mehr als generische Indikatoren.
    _SCORE_WEIGHTS = {
        "has_amsi_bypass": 3,
        "has_credential_pattern": 3,
        "has_dotnet_exec": 2,
        "has_defense_evasion": 2,
        "has_persistence": 2,
        "has_lolbin": 2,
        "has_obfuscation": 2,
        "has_encoding": 1,
        "has_download": 1,
        "has_invoke_expression": 1,
        "has_reflection": 1,
        "has_wmi": 1,
        "has_hidden_execution": 1,
    }

    def detect(self, code: str) -> Dict[str, Any]:
        """Erkennt verdächtige Muster.

        Das Matching läuft auf einer kommentarbereinigten und deobfuskierten
        Sicht des Codes: Kommentare werden entfernt (senkt False Positives durch
        dokumentierte Beispiele), Backticks und einfache String-Verkettung werden
        aufgelöst (senkt False Negatives bei Obfuskation). Die Obfuskations-
        Erkennung selbst arbeitet weiter auf dem Rohcode, da Backticks und
        Verkettung genau das gesuchte Signal sind.

        Args:
            code: PowerShell-Code.

        Returns:
            Dictionary mit Boolean-Flags je Muster und einem gewichteten
            ``suspicion_score`` in [0, 1].
        """
        scan = _deobfuscate(_strip_comments(code))

        char_cast_count = len(re.findall(r'\[char\]', code, re.IGNORECASE))
        replace_count = len(re.findall(r'-replace\b', code, re.IGNORECASE))

        has_obfuscation = bool(
            self._match_any(code, self.OBFUSCATION_PATTERNS)
            or char_cast_count >= self._CHAR_CAST_TOTAL_THRESHOLD
            or (
                char_cast_count >= self._CHAR_CAST_WITH_JOIN_THRESHOLD
                and re.search(r'-join', code, re.IGNORECASE) is not None
            )
            or replace_count >= self._REPLACE_CHAIN_THRESHOLD
        )

        flags = {
            "has_encoding": self._match_any(scan, self.ENCODING_PATTERNS),
            "has_download": self._match_any(scan, self.DOWNLOAD_PATTERNS),
            "has_invoke_expression": self._match_any(scan, self.INVOKE_EXPRESSION_PATTERNS),
            "has_reflection": self._match_any(scan, self.REFLECTION_PATTERNS),
            "has_wmi": self._match_any(scan, self.WMI_PATTERNS),
            "has_obfuscation": has_obfuscation,
            "has_amsi_bypass": self._match_any(scan, self.AMSI_BYPASS_PATTERNS),
            "has_dotnet_exec": self._match_any(scan, self.DOTNET_EXEC_PATTERNS),
            "has_credential_pattern": self._match_any(scan, self.CREDENTIAL_PATTERNS),
            "has_defense_evasion": self._match_any(scan, self.DEFENSE_EVASION_PATTERNS),
            "has_lolbin": self._match_any(scan, self.LOLBIN_PATTERNS),
            "has_hidden_execution": self._match_any(scan, self.HIDDEN_EXEC_PATTERNS),
            "has_persistence": self._match_any(scan, self.PERSISTENCE_PATTERNS),
        }

        weighted = sum(w for key, w in self._SCORE_WEIGHTS.items() if flags[key])
        total = sum(self._SCORE_WEIGHTS.values())
        flags["suspicion_score"] = round(weighted / total, 4) if total else 0.0
        return flags

    def _match_any(self, code: str, patterns: List[str]) -> bool:
        """Prüft ob eines der Patterns matched."""
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                return True
        return False


_CODE_NOISE_PATTERN = re.compile(
    r'<#[\s\S]*?#>'           # Block-Kommentar
    r'|"(?:[^"`]|`.|"")*"'    # Double-quoted String (inkl. Escapes)
    r"|'(?:[^']|'')*'"        # Single-quoted String (inkl. '' Escape)
    r'|#[^\n]*'               # Zeilen-Kommentar
)


def _strip_comments_and_strings(code: str) -> str:
    """Entfernt Kommentare und String-Literale aus PowerShell-Code.

    Verhindert, dass Kommentartexte oder String-Inhalte fälschlicherweise
    als Cmdlet-Namen erkannt werden.
    """
    return _CODE_NOISE_PATTERN.sub(' ', code)


_COMMENT_PATTERN = re.compile(r'<#[\s\S]*?#>|#[^\n]*')

_ENCODED_CMD_RE = re.compile(r'-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})', re.IGNORECASE)


def _decode_encoded_command(cmdline: str) -> str:
    """Dekodiert ein PowerShell -EncodedCommand (base64/UTF-16LE) zu Text (lowercase).

    Leerer String, wenn kein -EncodedCommand enthalten ist oder das Dekodieren
    fehlschlägt. Dient dazu, die per WinRM gestartete Skript-PowerShell zu
    erkennen (der Skriptname steckt base64-kodiert in der Kommandozeile).
    """
    if not cmdline:
        return ""
    m = _ENCODED_CMD_RE.search(cmdline)
    if not m:
        return ""
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le", errors="ignore").lower()
    except Exception:
        return ""
_CONCAT_PATTERN = re.compile(r"""(['"])([^'"\n]*)\1\s*\+\s*(['"])([^'"\n]*)\3""")


def _strip_comments(code: str) -> str:
    """Entfernt nur Kommentare (Block und Zeile), erhält aber String-Literale.

    String-Inhalte bleiben erhalten, weil dort echte Indikatoren stehen (URLs,
    ``certutil``-Argumente, Modulnamen). Kommentare dagegen erzeugen nur False
    Positives und werden entfernt.
    """
    return _COMMENT_PATTERN.sub(' ', code)


def _deobfuscate(code: str) -> str:
    """Löst gängige, syntaxerhaltende Obfuskation auf, damit Muster greifen.

    * Backticks (``i`e`x`` -> ``iex``) werden entfernt.
    * Einfache String-Verkettung (``'Dow'+'nload'`` -> ``'Download'``) wird
      iterativ zusammengefügt.

    Das verbessert die Erkennung (weniger False Negatives), ohne die eigentliche
    Semantik zu verändern.
    """
    text = code.replace('`', '')
    for _ in range(6):
        folded = _CONCAT_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(4)}{m.group(1)}", text)
        if folded == text:
            break
        text = folded
    return text


def extract_cmdlets(code: str) -> List[str]:
    """Extrahiert verwendete Cmdlets aus Code.

    Args:
        code: PowerShell-Code.

    Returns:
        Liste der gefundenen Cmdlets.
    """
    cleaned = _strip_comments_and_strings(code)

    cmdlet_pattern = r'\b([A-Z][a-z]+(?:-[A-Z][a-z]+)+)\b'
    matches = re.findall(cmdlet_pattern, cleaned)

    alias_pattern = r'\b(gsv|gps|gci|gc|iwr|irm|gwmi|gcim|icm|iex)\b'
    alias_matches = re.findall(alias_pattern, cleaned, re.IGNORECASE)

    return list(set(matches + [m.lower() for m in alias_matches]))


def normalize_script(code: str) -> str:
    """Normalisiert PowerShell-Script.

    Args:
        code: Original-Code.

    Returns:
        Normalisierter Code (lowercase, whitespace-normalized).
    """
    normalized = code.lower()
    normalized = re.sub(r'\s+', ' ', normalized)
    normalized = normalized.strip()
    return normalized


_BASE64_RUN = re.compile(r'[A-Za-z0-9+/=]{20,}')


def calculate_base64_ratio(text: str) -> float:
    """Anteil zusammenhängender Base64-artiger Zeichenketten am Gesamttext."""
    if not text:
        return 0.0
    matches = _BASE64_RUN.findall(text)
    if not matches:
        return 0.0
    return round(sum(len(m) for m in matches) / max(len(text), 1), 4)


def build_static_features(
    code: str,
    tokenizer: "PowerShellTokenizer",
    ast_parser: "PowerShellASTParser",
    detector: "SuspiciousPatternDetector",
) -> Dict[str, Any]:
    """Baut die statischen Features eines Skripts.

    Einzige Quelle für die statische Feature-Erzeugung: sowohl die VM-Pipeline
    (malware_executor.py) als auch der VM-lose Extractor (extract_features.py)
    rufen diese Funktion auf, damit beide exakt dieselben Features liefern.
    """
    token_data = tokenizer.tokenize(code)
    ast_data = ast_parser.parse(code)

    static = {
        "scriptblock_raw": code,
        "scriptblock_normalized": normalize_script(code),
        "char_ids": token_data["char_ids"],
        "char_length": token_data["char_length"],
        "tokens": token_data["tokens"],
        "token_ids": token_data["token_ids"],
        "token_length": token_data["token_length"],
        "ast_json": ast_data["ast_json"],
        "ast_node_types": ast_data["ast_node_types"],
        "ast_node_type_ids": ast_data["ast_node_type_ids"],
        "ast_depth": ast_data["ast_depth"],
        "ast_node_count": ast_data["ast_node_count"],
        "cmdlets_used": extract_cmdlets(code),
        "entropy": EntropyCalculator.calculate(code),
        "base64_ratio": calculate_base64_ratio(code),
    }
    # detect() liefert alle has_*-Flags und den suspicion_score.
    static.update(detector.detect(code))
    return static
