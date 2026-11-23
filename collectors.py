"""Collector-Klassen für Sysmon-Events, PowerShell-Logs und Prozess-Informationen.
"""
import json
import logging
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import orjson

import config

try:
    import win32evtlog
    WIN32EVTLOG_AVAILABLE = True
except ImportError:
    WIN32EVTLOG_AVAILABLE = False

try:
    import win32api
    import win32con
    import win32security
    WIN32SECURITY_AVAILABLE = True
except ImportError:
    WIN32SECURITY_AVAILABLE = False

logger = logging.getLogger(__name__)


class SysmonCollector:
    """Sammelt Sysmon Events für PowerShell-Prozesse."""

    RELEVANT_EVENT_IDS = [1, 3, 5, 7, 8, 10, 11, 12, 13, 14, 19, 20, 21, 22, 23, 26]
    # 1=ProcessCreate, 3=NetworkConnect, 5=ProcessTerminate,
    # 7=ImageLoad, 8=CreateRemoteThread, 10=ProcessAccess, 11=FileCreate,
    # 12-14=Registry, 19-21=WmiEvent, 22=DnsQuery, 23/26=FileDelete

    EVENT_ID_TO_TYPE = {
        1: "ProcessCreate",
        3: "NetworkConnect",
        5: "ProcessTerminate",
        7: "ImageLoad",
        8: "CreateRemoteThread",
        10: "ProcessAccess",
        11: "FileCreate",
        12: "RegistryCreateKey",
        13: "RegistrySetValue",
        14: "RegistryDeleteKey",
        19: "WmiEventFilter",
        20: "WmiEventConsumer",
        21: "WmiEventConsumerToFilter",
        22: "DnsQuery",
        23: "FileDelete",
        26: "FileDelete",
    }

    def __init__(self) -> None:
        """Initialisiert den Sysmon Collector."""
        self.log_name = "Microsoft-Windows-Sysmon/Operational"
        self._sysmon_available = None
        self._check_sysmon_availability()

    def _check_sysmon_availability(self) -> bool:
        """Prüft ob Sysmon installiert und aktiv ist."""
        if self._sysmon_available is not None:
            return self._sysmon_available

        try:
            # Use sc.exe (always available, no PATH dependency)
            result = subprocess.run(
                ["sc", "query", "Sysmon64"],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5,
            )
            if "RUNNING" in result.stdout:
                self._sysmon_available = True
            else:
                # Fallback: try Sysmon (32-bit name)
                result2 = subprocess.run(
                    ["sc", "query", "Sysmon"],
                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5,
                )
                self._sysmon_available = "RUNNING" in result2.stdout
            if not self._sysmon_available:
                logger.warning("Sysmon nicht gefunden oder gestoppt")
        except Exception as e:
            logger.warning(f"Sysmon-Check fehlgeschlagen: {e}")
            self._sysmon_available = False

        return self._sysmon_available

    def is_available(self) -> bool:
        """Gibt zurück ob Sysmon verfügbar ist."""
        return self._sysmon_available if self._sysmon_available is not None else self._check_sysmon_availability()

    def get_own_process_create(
        self,
        pid: int,
        lookback_seconds: int = 300,
    ) -> Optional[Dict[str, Any]]:
        """Sucht das ProcessCreate-Event (EventID 1) für exakt diese PID.

        Wird als Fallback genutzt wenn psutil.Process(pid) fehlschlägt -
        typisch wenn der Prozess bereits beendet ist. Sysmon hat das Event
        bereits beim Prozess-Start geloggt, also rückwärts suchen.

        Args:
            pid : Die gesuchte Process-ID (neu erstellter Prozess, nicht Parent).
            lookback_seconds: Wie weit zurücksuchen (dfault 90s deckt posh-git Profil-Ladezeit ab).

        Returns:
            Geparstes ProcessCreate-Event oder None.
        """
        from datetime import timezone as _tz
        now = datetime.now(_tz.utc)
        start = now - timedelta(seconds=lookback_seconds)
        try:
            raw_events = self._query_event_log(start, now)
            for raw in raw_events:
                if raw.get("EventId") != 1:
                    continue
                parsed = self.parse_event(raw)
                if parsed and parsed.get("process_id") == pid:
                    return parsed
        except Exception as e:
            logger.debug(f"get_own_process_create Fehler PID {pid}: {e}")
        return None

    def get_events(
        self,
        start_time: datetime,
        end_time: datetime,
        process_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Holt Sysmon Events aus Windows Event Log.

        Args:
            start_time: Start-Zeitpunkt für Event-Abfrage.
            end_time: End-Zeitpunkt für Event-Abfrage.
            process_id: Optional - filtert auf spezifische PID.

        Returns:
            Liste von geparsten Sysmon-Events.
        """
        events = []
        try:
            raw_events = self._query_event_log(start_time, end_time)
            for raw_event in raw_events:
                parsed = self.parse_event(raw_event)
                if parsed:
                    if process_id is None:
                        events.append(parsed)
                    elif parsed.get("event_id") == 1:
                        if parsed.get("features", {}).get("parent_process_id", 0) == process_id:
                            events.append(parsed)
                    else:
                        if parsed.get("process_id") == process_id:
                            events.append(parsed)
        except Exception as e:
            logger.warning(f"Fehler beim Sammeln von Sysmon-Events: {e}")

        return events

    def _query_event_log(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Holt Sysmon Events direkt via win32evtlog (kein PowerShell-Subprocess).
        Auf Windows Server dauert PS-Startup 14+ Sekunden -> immer Timeout.
        """
        if WIN32EVTLOG_AVAILABLE:
            return self._query_via_win32evtlog(start_time, end_time)
        return self._query_via_subprocess_fallback(start_time, end_time)

    def _query_via_win32evtlog(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Direkte win32evtlog-Abfrage ohne PowerShell-Subprocess."""
        CHANNEL = "Microsoft-Windows-Sysmon/Operational"
        RELEVANT_IDS = set(self.RELEVANT_EVENT_IDS)
        NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        results = []

        try:
            id_cond = " or ".join(f"EventID={eid}" for eid in RELEVANT_IDS)
            start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            end_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            query = f"*[System[({id_cond}) and TimeCreated[@SystemTime>='{start_str}' and @SystemTime<='{end_str}']]]"

            try:
                handle = win32evtlog.EvtQuery(
                    CHANNEL,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                    query,
                )
            except Exception:
                handle = win32evtlog.EvtQuery(
                    CHANNEL,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                    f"*[System[{id_cond}]]",
                )

            while True:
                batch = win32evtlog.EvtNext(handle, 50)
                if not batch:
                    break
                for ev in batch:
                    try:
                        xml_str = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                        root = ET.fromstring(xml_str)

                        time_el = root.find(".//e:TimeCreated", NS)
                        t_str = time_el.get("SystemTime", "") if time_el is not None else ""
                        if t_str:
                            try:
                                event_dt = datetime.fromisoformat(t_str.replace("Z", "+00:00"))
                                # Ensure same tz-awareness as start_time for comparison
                                if start_time.tzinfo is None:
                                    event_dt = event_dt.replace(tzinfo=None)
                                if event_dt > end_time:
                                    continue
                                if event_dt < start_time:
                                    return results
                            except Exception:
                                pass

                        event_id_el = root.find(".//e:EventID", NS)
                        event_id = int(event_id_el.text) if event_id_el is not None else 0
                        if event_id not in RELEVANT_IDS:
                            continue

                        data_els = root.findall(".//e:Data", NS)
                        event_data = {}
                        for d in data_els:
                            name = d.get("Name")
                            if name:
                                event_data[name] = d.text or ""

                        results.append({
                            "EventId": event_id,
                            "TimeCreated": t_str,
                            "EventData": event_data,
                        })
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"win32evtlog Sysmon-Query Fehler: {e}")

        return results

    def _query_via_subprocess_fallback(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fallback: PowerShell-Subprocess (langsam, nur wenn win32evtlog fehlt)."""
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%S")
        event_ids_str = ",".join(str(eid) for eid in self.RELEVANT_EVENT_IDS)

        ps_script = f'''
$filterHash = @{{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = {event_ids_str}
    StartTime = [DateTime]::Parse("{start_str}")
    EndTime = [DateTime]::Parse("{end_str}")
}}
try {{
    $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue
    $results = @()
    foreach ($event in $events) {{
        $xml = [xml]$event.ToXml()
        $eventData = @{{}}
        foreach ($data in $xml.Event.EventData.Data) {{
            $eventData[$data.Name] = $data.'#text'
        }}
        $results += @{{ EventId = $event.Id; TimeCreated = $event.TimeCreated.ToString("o"); EventData = $eventData }}
    }}
    $results | ConvertTo-Json -Depth 5 -Compress
}} catch {{ Write-Output "[]" }}
'''
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                timeout=config.PERFORMANCE.sysmon_subprocess_timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                if output and output != "[]":
                    data = json.loads(output)
                    return [data] if isinstance(data, dict) else data
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.debug(f"Subprocess Sysmon Fallback Fehler: {e}")
        return []

    def parse_event(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parsed einzelnes Sysmon Event zu Dictionary.

        Args:
            raw_event: Rohes Event-Dictionary.

        Returns:
            Gepartes Event oder None.
        """
        try:
            event_id = raw_event.get("EventId")
            event_type = self.EVENT_ID_TO_TYPE.get(event_id, f"Unknown_{event_id}")
            event_data = raw_event.get("EventData", {})

            time_created = raw_event.get("TimeCreated", "")
            timestamp_ms = 0
            if time_created:
                try:
                    dt = datetime.fromisoformat(time_created.replace("Z", "+00:00"))
                    timestamp_ms = int(dt.timestamp() * 1000)
                except ValueError:
                    pass

            parsed = {
                "event_id": event_id,
                "type": event_type,
                "timestamp_ms": timestamp_ms,
                "process_id": self._safe_int(event_data.get("ProcessId")),
                "features": {
                    "image": event_data.get("Image", ""),
                    "user": event_data.get("User", ""),
                    "process_guid": event_data.get("ProcessGuid", ""),
                },
            }

            if event_type == "ProcessCreate":
                parsed["features"].update({
                    "command_line": event_data.get("CommandLine", ""),
                    "parent_image": event_data.get("ParentImage", ""),
                    "parent_process_guid": event_data.get("ParentProcessGuid", ""),
                    "parent_process_id": int(event_data.get("ParentProcessId") or 0),
                    "current_directory": event_data.get("CurrentDirectory", ""),
                    "integrity_level": event_data.get("IntegrityLevel", "Medium"),
                    "parent_user": event_data.get("ParentUser", ""),
                    "parent_command_line": event_data.get("ParentCommandLine", ""),
                })
            elif event_type == "NetworkConnect":
                parsed["features"].update({
                    "dest_ip": event_data.get("DestinationIp", ""),
                    "dest_port": self._safe_int(event_data.get("DestinationPort")),
                    "dest_hostname": event_data.get("DestinationHostname", ""),
                })
            elif event_type in ("FileCreate", "FileDelete"):
                parsed["features"].update({
                    "target_filename": event_data.get("TargetFilename", ""),
                })
            elif event_type in ("ProcessAccess", "CreateRemoteThread"):
                parsed["features"].update({
                    "target_image": event_data.get("TargetImage", ""),
                    "granted_access": event_data.get("GrantedAccess", ""),
                    "call_trace": event_data.get("CallTrace", ""),
                })
            elif event_type in ("RegistrySetValue", "RegistryCreateKey", "RegistryDeleteKey"):
                parsed["features"].update({
                    "target_object": event_data.get("TargetObject", ""),
                    "details": event_data.get("Details", ""),
                })
            elif event_type == "DnsQuery":
                parsed["features"].update({
                    "query_name": event_data.get("QueryName", ""),
                    "query_results": event_data.get("QueryResults", ""),
                })
            elif event_type == "ImageLoad":
                parsed["features"].update({
                    "image_loaded": event_data.get("ImageLoaded", ""),
                })

            return parsed

        except Exception as e:
            logger.debug(f"Event-Parsing Fehler: {e}")
            return None

    def _safe_int(self, value: Any) -> int:
        """Sicheres Parsen zu Integer."""
        try:
            return int(value) if value else 0
        except (ValueError, TypeError):
            return 0


class PowerShellLogCollector:
    """Sammelt PowerShell ScriptBlock Logs (Event ID 4104)."""

    def __init__(self) -> None:
        """Initialisiert den PowerShell Log Collector."""
        self.log_name = "Microsoft-Windows-PowerShell/Operational"
        self.event_id = 4104

    def get_scriptblocks(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Holt ScriptBlock Logs.

        Args:
            start_time: Start-Zeitpunkt.
            end_time: End-Zeitpunkt.

        Returns:
            Liste von ScriptBlock-Events.
        """
        scriptblocks = []

        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%S")

        ps_script = f'''
$startTime = [DateTime]::Parse("{start_str}")
$endTime = [DateTime]::Parse("{end_str}")

$filterHash = @{{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    ID = 4104
    StartTime = $startTime
    EndTime = $endTime
}}

try {{
    $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue -MaxEvents 100
    $results = @()
    foreach ($event in $events) {{
        $results += @{{
            TimeCreated = $event.TimeCreated.ToString("o")
            ScriptBlockText = $event.Properties[2].Value
            ScriptBlockId = $event.Properties[3].Value
        }}
    }}
    $results | ConvertTo-Json -Depth 3 -Compress
}} catch {{
    Write-Output "[]"
}}
'''

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=config.PERFORMANCE.sysmon_subprocess_timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                if output != "[]":
                    data = json.loads(output)
                    if isinstance(data, dict):
                        scriptblocks = [data]
                    else:
                        scriptblocks = data
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.debug(f"ScriptBlock Query Fehler: {e}")

        return scriptblocks


class ProcessInfoCollector:
    """Sammelt Prozess-Informationen."""

    def __init__(self) -> None:
        """Initialisiert den Prozess-Info Collector."""
        self.process_name_vocab = config.COMMON_PROCESSES.copy()
        self._next_id = max(self.process_name_vocab.values()) + 1

    def get_process_info(self, pid: int) -> Dict[str, Any]:
        """Holt aktuelle Prozess-Info via psutil.

        Args:
            pid: Process ID.

        Returns:
            Dictionary mit Prozess-Informationen.
        """
        default_info = {
            "pid": pid,
            "parent_pid": 0,
            "parent_name": "",
            "grandparent_name": "",
            "command_line": "",
            "working_directory": "",
            "user": "",
            "integrity_level": "Medium",
            "is_elevated": False,
            "process_chain": [],
            "process_chain_ids": [],
        }

        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Prozess-Info Fehler für PID {pid}: {e}")
            return default_info

        # Each psutil call individually guarded - AccessDenied on cmdline/cwd
        # must not discard parent_pid which is the most valuable field.
        parent_pid = 0
        try:
            parent_pid = proc.ppid()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        cmdline = ""
        try:
            cl = proc.cmdline()
            cmdline = " ".join(cl) if cl else ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        working_directory = ""
        try:
            working_directory = proc.cwd()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        user = ""
        try:
            user = proc.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        info = {
            "pid": pid,
            "parent_pid": parent_pid,
            "parent_name": "",
            "grandparent_name": "",
            "command_line": cmdline,
            "working_directory": working_directory,
            "user": user,
            "integrity_level": self._get_integrity_level(proc),
            "is_elevated": self._check_elevated(proc),
            "process_chain": [],
            "process_chain_ids": [],
        }

        if parent_pid:
            try:
                parent = psutil.Process(parent_pid)
                info["parent_name"] = parent.name()
                try:
                    grandparent = psutil.Process(parent.ppid())
                    info["grandparent_name"] = grandparent.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        info["process_chain"] = self.get_process_chain(pid)
        info["process_chain_ids"] = [
            self._get_process_name_id(name)
            for name in info["process_chain"]
        ]

        return info

    def get_process_chain(self, pid: int) -> List[str]:
        """Baut Process Chain: [grandparent, parent, current].

        Args:
            pid: Ausgangs-PID.

        Returns:
            Liste von Prozess-Namen in der Kette.
        """
        chain = []
        current_pid = pid

        for _ in range(3):
            try:
                proc = psutil.Process(current_pid)
                chain.insert(0, proc.name())
                current_pid = proc.ppid()
                if current_pid == 0:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

        while len(chain) < 3:
            chain.insert(0, "")

        return chain[-3:]

    # SECURITY_MANDATORY_*_RID Werte aus winnt.h
    _INTEGRITY_RID_LEVELS = (
        (0x4000, "System"),
        (0x3000, "High"),
        (0x2000, "Medium"),
        (0x1000, "Low"),
    )

    def _open_process_token(self, pid: int):
        """Oeffnet Process-Token via Win32 API für echte Token-Abfragen."""
        handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        try:
            return win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
        finally:
            win32api.CloseHandle(handle)

    def _get_integrity_level(self, proc: psutil.Process) -> str:
        """Ermittelt Integrity Level des Prozesses via echtes Process-Token."""
        if WIN32SECURITY_AVAILABLE:
            try:
                token = self._open_process_token(proc.pid)
                sid, _attrs = win32security.GetTokenInformation(
                    token, win32security.TokenIntegrityLevel
                )
                rid = sid.GetSubAuthority(sid.GetSubAuthorityCount() - 1)
                for threshold, label in self._INTEGRITY_RID_LEVELS:
                    if rid >= threshold:
                        return label
                return "Untrusted"
            except Exception:
                pass
        # Fallback (z.B. Access Denied auf bereits beendete Prozesse)
        try:
            username = proc.username().lower()
            if "system" in username:
                return "System"
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass
        return "Medium"

    def _check_elevated(self, proc: psutil.Process) -> bool:
        """Prüft ob Prozess elevated läuft via echtes Process-Token (TokenElevation)."""
        if WIN32SECURITY_AVAILABLE:
            try:
                token = self._open_process_token(proc.pid)
                elevation = win32security.GetTokenInformation(
                    token, win32security.TokenElevation
                )
                return bool(elevation)
            except Exception:
                pass
        # Fallback (z.B. Access Denied auf bereits beendete Prozesse)
        try:
            username = proc.username().lower()
            return "system" in username
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            return False

    def _get_process_name_id(self, name: str) -> int:
        """Gibt ID für Prozess-Name zurück."""
        name_lower = name.lower()
        if name_lower not in self.process_name_vocab:
            self.process_name_vocab[name_lower] = self._next_id
            self._next_id += 1
        return self.process_name_vocab[name_lower]

    def get_vocabulary(self) -> Dict[str, int]:
        """Gibt Prozess-Name-Vocabulary zurück."""
        return self.process_name_vocab.copy()


class SampleRecorder:
    """Zeichnet Samples auf und exportiert als JSONL."""

    def __init__(self, output_file: Path, vocab_file: Path) -> None:
        """Initialisiert den Sample Recorder.

        Args:
            output_file: Pfad zur Output-JSONL-Datei.
            vocab_file: Pfad zur Vocabulary-JSON-Datei.
        """
        self.output_file = output_file
        self.vocab_file = vocab_file
        self.vocab: Dict[str, Dict[str, int]] = {
            "tokens": {},
            "chars": {},
            "ast_nodes": {},
            "event_types": {},
            "processes": {},
        }
        self.sample_count = 0
        self.category_counts: Dict[str, int] = {}

        output_file.parent.mkdir(parents=True, exist_ok=True)

    def record(self, sample: Dict[str, Any]) -> None:
        """Schreibt Sample als JSON-Line.

        Args:
            sample: Vollständiges Sample-Dictionary.
        """
        try:
            json_bytes = orjson.dumps(sample, option=orjson.OPT_APPEND_NEWLINE)

            with open(self.output_file, "ab") as f:
                f.write(json_bytes)

            self.sample_count += 1

            category = sample.get("metadata", {}).get("category", "unknown")
            self.category_counts[category] = self.category_counts.get(category, 0) + 1

            if self.sample_count % 100 == 0:
                logger.info(f"Samples aufgezeichnet: {self.sample_count}")

        except Exception as e:
            logger.error(f"Fehler beim Aufzeichnen des Samples: {e}")

    def update_vocabulary(
        self,
        token_vocab: Dict[str, int],
        char_vocab: Dict[str, int],
        ast_vocab: Dict[str, int],
        event_vocab: Dict[str, int],
        process_vocab: Dict[str, int]
    ) -> None:
        """Aktualisiert die Vocabularies.

        Args:
            token_vocab: Token-Vocabulary.
            char_vocab: Character-Vocabulary.
            ast_vocab: AST-Node-Type-Vocabulary.
            event_vocab: Event-Type-Vocabulary.
            process_vocab: Process-Name-Vocabulary.
        """
        self._merge_vocab(self.vocab["tokens"], token_vocab)
        self._merge_vocab(self.vocab["chars"], char_vocab)
        self._merge_vocab(self.vocab["ast_nodes"], ast_vocab)
        self._merge_vocab(self.vocab["event_types"], event_vocab)
        self._merge_vocab(self.vocab["processes"], process_vocab)

    def _merge_vocab(
        self,
        target: Dict[str, int],
        source: Dict[str, int]
    ) -> None:
        """Übernimmt die festen IDs aus dem Quell-Vocabulary.

        Die IDs werden aus vocabulary.py vorgegeben und hier unverändert
        übernommen, damit die gespeicherte Vocabular-Datei exakt der im Datensatz
        verwendeten Kodierung entspricht.
        """
        for key, value in source.items():
            target[key] = value

    def finalize(self) -> Dict[str, Any]:
        """Speichert Vocabulary und gibt Statistiken zurück.

        Returns:
            Dictionary mit Statistiken.
        """
        try:
            with open(self.vocab_file, "wb") as f:
                f.write(orjson.dumps(self.vocab, option=orjson.OPT_INDENT_2))
            logger.info(f"Vocabulary gespeichert: {self.vocab_file}")
        except Exception as e:
            logger.error(f"Fehler beim Speichern des Vocabularies: {e}")

        stats = {
            "total_samples": self.sample_count,
            "samples_per_category": self.category_counts,
            "vocabulary_sizes": {
                "tokens": len(self.vocab["tokens"]),
                "chars": len(self.vocab["chars"]),
                "ast_nodes": len(self.vocab["ast_nodes"]),
                "event_types": len(self.vocab["event_types"]),
                "processes": len(self.vocab["processes"]),
            },
            "output_file": str(self.output_file),
            "vocab_file": str(self.vocab_file),
        }

        return stats

    def get_stats(self) -> Dict[str, Any]:
        """Gibt aktuelle Statistiken zurück."""
        return {
            "total_samples": self.sample_count,
            "samples_per_category": self.category_counts.copy(),
        }
