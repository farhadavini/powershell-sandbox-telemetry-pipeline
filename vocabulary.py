"""Feste, versionierte Vokabulare fuer die Token- und AST-Kodierung.

Hintergrund: Frueher bauten Tokenizer und AST-Parser ihr Vokabular zur Laufzeit
in Auftretens-Reihenfolge auf. Dieselbe Eingabe bekam dadurch je nach Lauf und
Verarbeitungsreihenfolge unterschiedliche IDs, und zwei in getrennten Laeufen
erzeugte Datensaetze waren nicht mehr vergleichbar.

Die Kodierung hier ist stattdessen vollstaendig deterministisch:

* Bekannte PowerShell-Token (Schluesselwoerter, Operatoren, gaengige Cmdlets)
  erhalten feste IDs aus ``TOKEN_BASE_VOCAB``.
* Alle uebrigen Token (Variablennamen, Zeichenketten, Zufallsbezeichner) werden
  per CRC32 in einen festen Bereich an Hash-Buckets abgebildet (Hashing-Trick).
  CRC32 ist - anders als Pythons ``hash()`` fuer Strings - nicht pro Prozess
  gesalzen und liefert daher auf jeder Maschine dieselbe ID.

Dadurch ist ``token_id`` fuer ein Token immer gleich, ohne wachsenden Zustand
und ohne dass eine Vokabulardatei mitgefuehrt werden muss. ``VOCAB_VERSION`` wird
mit jedem Datensatz exportiert, damit das Trainingsprojekt dieselbe Kodierung
nachvollziehen kann.
"""
from __future__ import annotations

import json
import zlib
from pathlib import Path
from typing import Dict, List

VOCAB_VERSION = 1

PAD_ID = 0
UNK_ID = 1


# ---------------------------------------------------------------------------
# AST-Knotentypen (System.Management.Automation.Language.*Ast)
# ---------------------------------------------------------------------------
# Die Menge der AST-Knotentypen ist durch die PowerShell-Sprache fest vorgegeben.
# Unbekannte Typen (neue Sprachversionen) fallen deterministisch auf <UNK>.
AST_NODE_TYPES: List[str] = [
    "ScriptBlockAst", "ParamBlockAst", "NamedBlockAst", "StatementBlockAst",
    "PipelineAst", "PipelineChainAst", "CommandAst", "CommandExpressionAst",
    "CommandParameterAst", "AssignmentStatementAst",
    "IfStatementAst", "ForStatementAst", "ForEachStatementAst",
    "WhileStatementAst", "DoWhileStatementAst", "DoUntilStatementAst",
    "SwitchStatementAst", "TryStatementAst", "CatchClauseAst", "TrapStatementAst",
    "DataStatementAst", "FunctionDefinitionAst", "ReturnStatementAst",
    "BreakStatementAst", "ContinueStatementAst", "ThrowStatementAst",
    "ExitStatementAst", "BlockStatementAst",
    "VariableExpressionAst", "ConstantExpressionAst",
    "StringConstantExpressionAst", "ExpandableStringExpressionAst",
    "ScriptBlockExpressionAst", "ArrayExpressionAst", "ArrayLiteralAst",
    "HashtableAst", "BinaryExpressionAst", "UnaryExpressionAst",
    "ConvertExpressionAst", "TypeExpressionAst", "TypeConstraintAst",
    "AttributeAst", "NamedAttributeArgumentAst", "AttributedExpressionAst",
    "MemberExpressionAst", "InvokeMemberExpressionAst",
    "BaseCtorInvokeMemberExpressionAst", "IndexExpressionAst",
    "ParenExpressionAst", "SubExpressionAst", "UsingExpressionAst",
    "ParameterAst", "FileRedirectionAst", "MergingRedirectionAst",
    "TernaryExpressionAst", "PropertyMemberAst", "FunctionMemberAst",
    "TypeDefinitionAst", "UsingStatementAst", "ConfigurationDefinitionAst",
    "DynamicKeywordStatementAst", "ErrorStatementAst", "ErrorExpressionAst",
    "Empty",
]

AST_NODE_TYPE_VOCAB: Dict[str, int] = {"<PAD>": PAD_ID, "<UNK>": UNK_ID}
for _i, _name in enumerate(AST_NODE_TYPES, start=2):
    AST_NODE_TYPE_VOCAB[_name] = _i


def ast_node_type_id(node_type: str) -> int:
    """Gibt die feste ID eines AST-Knotentyps zurueck (<UNK> wenn unbekannt)."""
    return AST_NODE_TYPE_VOCAB.get(node_type, UNK_ID)


# ---------------------------------------------------------------------------
# Token-Basisvokabular (lowercase, wie vom Tokenizer erzeugt)
# ---------------------------------------------------------------------------
_KEYWORDS = [
    "if", "else", "elseif", "switch", "foreach", "for", "while", "do", "until",
    "break", "continue", "function", "filter", "return", "throw", "try", "catch",
    "finally", "trap", "param", "begin", "process", "end", "data", "dynamicparam",
    "class", "enum", "using", "namespace", "module", "in", "exit", "workflow",
    "parallel", "sequence", "inlinescript", "configuration", "hidden", "static",
]

_OPERATORS = [
    "-eq", "-ne", "-gt", "-ge", "-lt", "-le", "-like", "-notlike", "-match",
    "-notmatch", "-contains", "-notcontains", "-in", "-notin", "-replace",
    "-split", "-join", "-and", "-or", "-not", "-xor", "-band", "-bor", "-bnot",
    "-bxor", "-shl", "-shr", "-is", "-isnot", "-as", "-f", "-ceq", "-cne",
    "-clike", "-cmatch", "-creplace", "-ieq", "-ine",
    "=", "+=", "-=", "*=", "/=", "%=", "++", "--",
    "+", "-", "*", "/", "%", "|", "&", "&&", "||", ";", ",", ".", "::", "?",
    "(", ")", "{", "}", "[", "]", "@", "@(", "@{", "$(", "${",
    "<", ">", ">>", "2>", "2>&1", "|>", "`",
    "$", "$_", "$null", "$true", "$false", "$args", "$input", "$psitem",
    "$error", "$host", "$pwd", "$home", "$pshome", "$matches", "$lastexitcode",
]

# Gaengige und fuer die Analyse besonders relevante Cmdlets/Aliasse.
_CMDLETS = [
    "invoke-expression", "iex", "invoke-command", "icm", "invoke-webrequest",
    "iwr", "invoke-restmethod", "irm", "invoke-item", "ii", "invoke-wmimethod",
    "new-object", "add-type", "start-process", "saps", "start-sleep", "sleep",
    "start-job", "register-scheduledtask", "new-scheduledtask", "schtasks",
    "set-item", "set-itemproperty", "sp", "new-item", "ni", "new-itemproperty",
    "get-item", "gi", "get-itemproperty", "gp", "get-childitem", "gci", "dir", "ls",
    "get-content", "gc", "cat", "set-content", "sc", "add-content", "ac",
    "out-file", "out-null", "out-string", "write-host", "write-output", "echo",
    "write-error", "write-verbose", "where-object", "where", "foreach-object",
    "select-object", "select", "sort-object", "measure-object", "group-object",
    "convertto-securestring", "convertfrom-securestring", "convertto-json",
    "convertfrom-json", "convertto-base64", "export-clixml", "import-clixml",
    "get-credential", "get-wmiobject", "gwmi", "get-ciminstance", "gcim",
    "set-wmiinstance", "register-wmievent", "get-process", "gps", "ps",
    "stop-process", "spps", "kill", "get-service", "gsv", "set-service",
    "new-service", "start-service", "stop-service", "set-mppreference",
    "add-mppreference", "get-mppreference", "clear-eventlog", "remove-eventlog",
    "wevtutil", "net", "netsh", "reg", "certutil", "bitsadmin", "rundll32",
    "regsvr32", "mshta", "wscript", "cscript", "msbuild", "installutil",
    "powershell", "pwsh", "cmd", "downloadstring", "downloadfile", "downloaddata",
    "webclient", "net.webclient", "frombase64string", "tobase64string",
    "getstring", "getbytes", "compress", "decompress", "gzipstream",
    "deflatestream", "memorystream", "reflection", "assembly", "load", "loadfile",
    "getmethod", "getmethods", "gettype", "invoke", "dynamicinvoke",
    "copy-item", "move-item", "remove-item", "ri", "rm", "del", "rename-item",
    "test-path", "resolve-path", "join-path", "split-path", "get-command",
    "get-member", "gm", "measure-command", "set-executionpolicy", "import-module",
    "export-modulemember", "set-alias", "new-alias", "enter-pssession",
    "new-pssession", "invoke-mimikatz", "amsiutils", "amsiinitfailed",
    "virtualalloc", "writeprocessmemory", "createthread", "createremotethread",
    "getprocaddress", "loadlibrary", "dllimport", "marshal", "getdelegatefor",
]

TOKEN_BASE_VOCAB: Dict[str, int] = {"<PAD>": PAD_ID, "<UNK>": UNK_ID}
for _tok in _KEYWORDS + _OPERATORS + _CMDLETS:
    _key = _tok.lower()
    if _key not in TOKEN_BASE_VOCAB:
        TOKEN_BASE_VOCAB[_key] = len(TOKEN_BASE_VOCAB)

TOKEN_BASE_SIZE = len(TOKEN_BASE_VOCAB)


def token_id(token: str, vocab_size: int) -> int:
    """Gibt eine deterministische, laufunabhaengige ID fuer ein Token zurueck.

    Bekannte Token erhalten ihre feste ID aus ``TOKEN_BASE_VOCAB``. Unbekannte
    werden per CRC32 in den Bereich ``[TOKEN_BASE_SIZE, vocab_size)`` gehasht.
    """
    key = token.lower()
    fixed = TOKEN_BASE_VOCAB.get(key)
    if fixed is not None:
        return fixed

    n_buckets = vocab_size - TOKEN_BASE_SIZE
    if n_buckets <= 0:
        return UNK_ID
    return TOKEN_BASE_SIZE + (zlib.crc32(key.encode("utf-8")) % n_buckets)


def export_vocabularies(path: Path, token_vocab_size: int) -> None:
    """Schreibt die Vokabular-Definition neben den Datensatz.

    Das Trainingsprojekt liest diese Datei, um dieselbe Kodierung (feste Token,
    Hash-Bereich, AST-Typen) zu reproduzieren.
    """
    payload = {
        "vocab_version": VOCAB_VERSION,
        "token_vocab_size": token_vocab_size,
        "token_base": TOKEN_BASE_VOCAB,
        "token_hash_range": [TOKEN_BASE_SIZE, token_vocab_size],
        "token_hash": "crc32(token.lower()) % (vocab_size - base_size) + base_size",
        "ast_node_types": AST_NODE_TYPE_VOCAB,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
