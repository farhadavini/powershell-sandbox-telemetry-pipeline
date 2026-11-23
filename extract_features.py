#!/usr/bin/env python3
"""Statische Feature-Extraktion ohne VM - für große Datensätze.

Die VM-Pipeline (malware_executor.py) liefert statische *und* dynamische
Features, ist dafür aber auf eine isolierte Windows-VM angewiesen und verarbeitet
eine Probe nach der anderen. Für viele Anwendungsfälle genügen die *statischen*
Features (Zeichen-/Token-Sequenzen, AST-Metriken, Entropie, Verdachtsmuster).
Dieses Werkzeug erzeugt genau diese - parallel, auf jedem Betriebssystem und
ohne VM - und skaliert damit auf zehntausende Skripte.

Es nutzt dieselbe Funktion wie die VM-Pipeline (utils.build_static_features),
sodass die statischen Features identisch sind.

Beispiele:
    python extract_features.py scripts/ --label benign -o benign.jsonl
    python extract_features.py malware/ --label malicious --workers 8 -o mal.jsonl
    python extract_features.py one.ps1 --no-ast -o out.jsonl

Ohne Windows/PowerShell fällt der Tokenizer automatisch auf eine Regex-
Tokenisierung zurück; die AST-Metriken sind dann leer (``--no-ast`` erzwingt das
und ist deutlich schneller).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import config
import vocabulary
from utils import PowerShellTokenizer, PowerShellASTParser, SuspiciousPatternDetector, build_static_features

MAX_BYTES = 5_000_000  # Skripte über ~5 MB sind praktisch nie echte PowerShell.

_WORKER: Dict[str, Any] = {}


class _NullASTParser:
    """Platzhalter für den AST-Parser, wenn --no-ast gesetzt ist."""

    def parse(self, code: str) -> Dict[str, Any]:
        return {
            "ast_json": {"type": "Disabled", "children": []},
            "ast_node_types": [],
            "ast_node_type_ids": [],
            "ast_depth": 0,
            "ast_node_count": 0,
        }


def _init_worker(no_ast: bool) -> None:
    """Richtet pro Prozess einen eigenen Satz Analysewerkzeuge ein."""
    _WORKER["tokenizer"] = PowerShellTokenizer()
    _WORKER["ast"] = _NullASTParser() if no_ast else PowerShellASTParser()
    _WORKER["detector"] = SuspiciousPatternDetector()


def _read_script(path: Path) -> Optional[str]:
    """Liest ein Skript robust ein (begrenzte Größe, Null-Bytes entfernt)."""
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
        return text.replace("\x00", "")
    except OSError:
        return None


def _process_file(args: tuple) -> Optional[Dict[str, Any]]:
    """Erzeugt ein Sample für eine Datei (läuft im Worker-Prozess)."""
    path_str, label = args
    path = Path(path_str)
    code = _read_script(path)
    if code is None or not code.strip():
        return None

    static = build_static_features(
        code, _WORKER["tokenizer"], _WORKER["ast"], _WORKER["detector"]
    )
    sample_id = hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()
    sample = {
        "sample_id": sample_id,
        "static": static,
        "metadata": {"sha256": sample_id, "original_filename": path.name},
    }
    if label != "none":
        sample["label"] = label
    return sample


def _collect_files(inputs, pattern: str, recursive: bool) -> list:
    files = []
    for raw in inputs:
        p = Path(raw)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(p.rglob(pattern) if recursive else p.glob(pattern))
    return sorted({f.resolve() for f in files})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Statische PowerShell-Features ohne VM extrahieren.")
    parser.add_argument("inputs", nargs="+", help="Skriptdateien oder Ordner")
    parser.add_argument("-o", "--output", required=True, help="Ziel-JSONL-Datei")
    parser.add_argument("--label", choices=["malicious", "benign", "none"], default="none",
                        help="Label für alle Samples (Standard: none)")
    parser.add_argument("--pattern", default="*.ps1", help="Dateimuster in Ordnern (Standard: *.ps1)")
    parser.add_argument("--recursive", action="store_true", help="Ordner rekursiv durchsuchen")
    parser.add_argument("--workers", type=int, default=0,
                        help="Parallele Prozesse (0 = CPU-Anzahl)")
    parser.add_argument("--no-ast", action="store_true",
                        help="AST-Metriken überspringen (schneller, kein PowerShell nötig)")
    parser.add_argument("--limit", type=int, default=0, help="Nur die ersten N Dateien")
    args = parser.parse_args(argv)

    files = _collect_files(args.inputs, args.pattern, args.recursive)
    if args.limit:
        files = files[: args.limit]
    if not files:
        print("Keine passenden Dateien gefunden.", file=sys.stderr)
        return 1

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Kodierung neben dem Datensatz ablegen (wie in der VM-Pipeline).
    vocabulary.export_vocabularies(output.with_name("vocab.json"), config.TOKEN_VOCAB_SIZE)

    workers = args.workers or None
    tasks = [(str(f), args.label) for f in files]
    written = 0
    skipped = 0
    start = time.time()

    print(f"Verarbeite {len(files)} Dateien (workers={workers or 'auto'}, no_ast={args.no_ast})...")

    import multiprocessing as mp
    with open(output, "w", encoding="utf-8") as out:
        if workers == 1:
            _init_worker(args.no_ast)
            results = (_process_file(t) for t in tasks)
            for sample in results:
                written, skipped = _emit(out, sample, written, skipped)
        else:
            with mp.Pool(processes=workers, initializer=_init_worker, initargs=(args.no_ast,)) as pool:
                for sample in pool.imap_unordered(_process_file, tasks, chunksize=16):
                    written, skipped = _emit(out, sample, written, skipped)
                    if (written + skipped) % 500 == 0:
                        print(f"  {written + skipped}/{len(files)} ...")

    elapsed = time.time() - start
    rate = written / elapsed if elapsed else 0
    print(f"Fertig: {written} Samples geschrieben, {skipped} übersprungen "
          f"({elapsed:.1f}s, {rate:.0f}/s) -> {output}")
    return 0


def _emit(out, sample: Optional[Dict[str, Any]], written: int, skipped: int):
    if sample is None:
        return written, skipped + 1
    out.write(json.dumps(sample, ensure_ascii=False) + "\n")
    return written + 1, skipped


if __name__ == "__main__":
    raise SystemExit(main())
