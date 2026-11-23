"""Zentrale Konfiguration der Erfassungspipeline.
Enthalt die Laufzeitparameter für die kontrollierte Ausfuehrung einer
PowerShell-Skriptdatei in der VirtualBox-VM (MalwareExecutionConfig) sowie
die Event-/Prozess-Vokabulare.
"""
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict


# === PERFORMANCE ===
@dataclass
class PerformanceConfig:
    """Performance-Parameter fuer AST-Parsing und Sysmon-Abfragen."""
    enable_ast_parsing: bool = True
    ast_cache_size: int = 1000
    ast_timeout: int = 15

    sysmon_query_timeout: int = 5
    sysmon_batch_size: int = 50

    enable_parallel_parsing: bool = True
    parser_thread_count: int = 4

    skip_slow_variants: bool = False
    min_samples_per_minute: int = 5

    post_exec_sysmon_wait: float = 0.15
    max_variants_per_command: int = 3
    sysmon_subprocess_timeout: int = 10


PERFORMANCE = PerformanceConfig()

# === KODIERUNG / SAMPLE-BILDUNG ===
MAX_CHAR_LENGTH = 16000
MAX_TOKEN_LENGTH = 256
MAX_EVENT_LENGTH = 100
ACTIVITY_MATRIX_BINS = 50
ACTIVITY_MATRIX_FEATURES = 6

# Groesse des Token-ID-Raums. Feste Token belegen die niedrigen IDs, unbekannte
# Token werden deterministisch in den restlichen Bereich gehasht (siehe
# vocabulary.py). Muss mit token_vocab_size im Trainingsprojekt uebereinstimmen.
TOKEN_VOCAB_SIZE = 10000

# True = nur echte Daten speichern, Padding erst beim Training
STORE_WITHOUT_PADDING = True


# === EVENT-TYP-VOKABULAR ===
EVENT_TYPES: Dict[str, int] = {
    "<PAD>": 0,
    "<UNK>": 1,
    "ProcessCreate": 2,
    "ProcessTerminate": 3,
    "NetworkConnect": 4,
    "FileCreate": 5,
    "FileDelete": 6,
    "RegistrySetValue": 7,
    "RegistryCreateKey": 8,
    "RegistryDeleteKey": 9,
    "DnsQuery": 10,
    "ImageLoad": 11,
}

# === PROZESSNAMEN-VOKABULAR ===
COMMON_PROCESSES: Dict[str, int] = {
    "<PAD>": 0,
    "<UNK>": 1,
    "powershell.exe": 2,
    "pwsh.exe": 3,
    "cmd.exe": 4,
    "explorer.exe": 5,
    "python.exe": 6,
    "conhost.exe": 7,
    "svchost.exe": 8,
    "code.exe": 9,
    "git.exe": 10,
    "node.exe": 11,
}

# === LOGGING ===
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


# =============================================================================
# MALWARE-AUSFUEHRUNG (Host steuert VM via VBoxManage + WinRM)
# =============================================================================

@dataclass
class MalwareExecutionConfig:
    """Konfiguration fuer die kontrollierte Malware-Ausfuehrung in der VM.

    Laeuft auf dem Host und steuert die VM via VBoxManage.

    Voraussetzungen:
    - VM mit Autologon und aktivem WinRM
    - Guest Additions installiert
    - vorbereiteter Snapshot (Sysmon aktiv, Defender deaktiviert)
    """

    # VirtualBox
    vm_name: str = field(default="sandbox-vm")
    snapshot_name: str = field(default="clean-baseline")
    vm_username: str = field(default="Administrator")
    # Leer lassen: Passwort via CLI --vm-password oder Umgebungsvariable
    # MALWARE_VM_PASSWORD uebergeben.
    vm_password: str = field(default="")
    vboxmanage_path: str = field(default=r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")

    # WinRM (Host-Only-Adapter)
    winrm_host: str = field(default="192.168.56.102")
    winrm_port: int = field(default=5985)

    # Pfade in der VM (absolut)
    vm_temp_dir: str = field(default=r"C:\Temp")
    vm_tools_dir: str = field(default=r"C:\Tools")
    vm_sysmon_export_script: str = field(default=r"C:\Tools\export_sysmon.ps1")
    local_export_script: Path = field(default_factory=lambda: Path(__file__).parent / "vm_scripts" / "export_sysmon.ps1")

    # Timing
    vm_boot_timeout: int = field(default=120)
    execution_timeout: int = field(default=60)
    post_execution_wait: int = field(default=60)
    # FESTES Beobachtungsfenster (Sekunden). Jedes Sample wird - unabhaengig
    # davon, ob das Skript erfolgreich endet, vorzeitig abbricht oder ins
    # Timeout laeuft - fuer GENAU diese Dauer ab Skriptstart beobachtet. So ist
    # das Sysmon-Fenster fuer alle Samples (benign wie malicious) identisch und
    # die Fensterlaenge korreliert nicht mehr mit dem Ausgang (kein Label-Bias).
    # Ueber --observation-window / --window-sec ueberschreibbar.
    observation_window_sec: int = field(default=30)
    # Interaktive Prompts (Read-Host, -Confirm/ShouldProcess, pause) werden
    # automatisch mit "yes"/Enter beantwortet, damit das Skript vollstaendig
    # durchlaeuft statt bis zum Hard-Timeout zu blockieren. Ueber
    # --no-auto-confirm abschaltbar.
    auto_confirm_prompts: bool = field(default=True)
    snapshot_has_malware: bool = field(default=False)
    snapshot_has_tools: bool = field(default=False)
    sysmon_buffer_before: int = field(default=2)
    sysmon_buffer_after: int = field(default=10)

    # Activity Check (gegen Label Noise)
    min_powershell_events: int = field(default=1)

    # Reset-Zyklus: Snapshot-Restore alle N Skripte (1 = vor jedem Sample;
    # > 1 = Batch-Modus, schneller, aber Proben teilen sich einen Zustand).
    # Ueber --restore-interval ueberschreibbar.
    restore_interval: int = field(default=1)

    # Host-Pfade: Eingabe-Skripte (.ps1) und Ausgabe-Datensatz.
    # Ueber die CLI-Flags --input-dir / --output-dir ueberschreibbar.
    malware_input_dir: Path = field(default_factory=lambda: Path(__file__).parent / "input" / "malware")
    metadata_file: Path = field(default_factory=lambda: Path(__file__).parent / "input" / "metadata.json")
    output_dir: Path = field(default_factory=lambda: Path(__file__).parent / "output" / "malware" / "samples")
    output_file: Path = field(default_factory=lambda: Path(__file__).parent / "output" / "malware" / "samples" / "malware_samples.jsonl")
    temp_dir: Path = field(default_factory=lambda: Path(__file__).parent / "output" / "malware" / "logs" / "temp")
    stats_file: Path = field(default_factory=lambda: Path(__file__).parent / "output" / "malware" / "logs" / "execution_stats.json")

