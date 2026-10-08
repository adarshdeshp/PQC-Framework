import warnings

warnings.filterwarnings("ignore")

import pytest
from cryptography.exceptions import InvalidTag

from pqcf import envelope
from pqcf.negotiation import (Client, DowngradeDetected, PolicyViolation, Server,
                              mitm_strip_quantum_safe)
from pqcf.policy import DataAsset, MoscaPolicyEngine
from pqcf.registry import AlgorithmCompromised, CryptoContext, default_registry


# ---------------- Mosca policy engine ----------------

def engine():
    return MoscaPolicyEngine(migration_years=3, quantum_horizon_years=12)


def test_short_lived_data_stays_classical():
    d = engine().decide(DataAsset("otp", "auth", 0.0001, "low"))
    assert not d.at_risk and d.level == "CLASSICAL"


def test_long_lived_critical_data_gets_max_protection():
    d = engine().decide(DataAsset("medical", "health", 50, "critical"))
    assert d.at_risk and d.level == "HYBRID-HIGH" and d.needs_migration


def test_mosca_inequality_boundary():
    e = engine()  # Y + Z threshold: X > 9 years is exposed
    assert not e.decide(DataAsset("a", "x", 9, "medium")).at_risk
    assert e.decide(DataAsset("b", "x", 9.5, "medium")).at_risk


def test_high_sensitivity_gets_hybrid_even_if_not_exposed():
    d = engine().decide(DataAsset("hr", "x", 1, "high"))
    assert not d.at_risk and d.level == "HYBRID"


def test_migration_plan_most_exposed_first_and_skips_safe():
    assets = [DataAsset("bank", "f", 10, "high"), DataAsset("gov", "i", 70, "critical"),
              DataAsset("otp", "a", 0.0001, "low"),
              DataAsset("done", "h", 50, "critical", current_kem="X25519+ML-KEM-1024")]
    plan = [d.asset.name for d in engine().migration_plan(assets)]
    assert plan == ["gov", "bank"]


# ---------------- envelope re-wrapping ----------------

def test_rewrap_keeps_payload_and_stays_readable():
    reg = default_registry()
    old, new = reg.kem("X25519"), reg.kem("X25519+ML-KEM-768")
    (opk, osk), (npk, nsk) = old.keygen(), new.keygen()
    rec = envelope.encrypt_record("r1", b"secret data" * 100, old, opk)
    moved = envelope.rewrap_record(rec, old, osk, new, npk)
    assert moved.payload_ct == rec.payload_ct
    assert moved.kem_name == new.name and moved.version == 2
    assert envelope.decrypt_record(moved, new, nsk) == b"secret data" * 100


def test_old_key_cannot_open_rewrapped_record():
    reg = default_registry()
    old, new = reg.kem("X25519"), reg.kem("X25519+ML-KEM-768")
    (opk, osk), (npk, _) = old.keygen(), new.keygen()
    moved = envelope.rewrap_record(envelope.encrypt_record("r", b"x", old, opk), old, osk, new, npk)
    with pytest.raises(Exception):
        envelope.decrypt_record(moved, old, osk)


def test_record_id_is_bound():
    reg = default_registry()
    k = reg.kem("X25519+ML-KEM-768")
    pk, sk = k.keygen()
    rec = envelope.encrypt_record("r1", b"x", k, pk)
    rec.record_id = "r2"                      # attacker swaps record identity
    with pytest.raises(InvalidTag):
        envelope.decrypt_record(rec, k, sk)


# ---------------- compromise + fallback ----------------

def test_family_compromise_blocks_hybrids_and_falls_back(tmp_path):
    reg = default_registry()
    cfg = tmp_path / "c.json"
    cfg.write_text('{"kem": "X25519+ML-KEM-768", "kem_fallbacks": ["X25519+FrodoKEM-976-AES"],'
                   ' "signature": "ML-DSA-65"}')
    ctx = CryptoContext.from_config(reg, str(cfg))
    reg.mark_compromised("ML-KEM")
    assert ctx.kem.name == "X25519+FrodoKEM-976-AES" and ctx.kem.quantum_safe
    with pytest.raises(AlgorithmCompromised):
        reg.kem("X25519+ML-KEM-1024")
    assert reg.kem_for_decryption("ML-KEM-768")   # old data still readable


def test_no_fallback_left_raises(tmp_path):
    reg = default_registry()
    cfg = tmp_path / "c.json"
    cfg.write_text('{"kem": "ML-KEM-768", "signature": "ML-DSA-65"}')
    ctx = CryptoContext.from_config(reg, str(cfg))
    reg.mark_compromised("ML-KEM")
    with pytest.raises(AlgorithmCompromised):
        _ = ctx.kem


# ---------------- downgrade-resistant negotiation ----------------

PREFS = ["X25519+ML-KEM-1024", "X25519+ML-KEM-768", "X25519"]


def handshake(attack, verify, require_qs=False):
    reg = default_registry()
    server = Server(reg, PREFS)
    client = Client(reg, PREFS, server.sig_pk, require_quantum_safe=require_qs, verify_transcript=verify)
    hello = client.hello()
    if attack:
        hello = mitm_strip_quantum_safe(hello, reg)
    reply = server.respond(hello)
    ct, secret, name = client.complete(reply)
    assert server.finish(ct) == secret
    return name


def test_honest_handshake_picks_strongest():
    assert handshake(attack=False, verify=True) == "X25519+ML-KEM-1024"


def test_naive_client_is_downgraded():
    assert handshake(attack=True, verify=False) == "X25519"


def test_protected_client_detects_downgrade():
    with pytest.raises(DowngradeDetected):
        handshake(attack=True, verify=True)


def test_quantum_safe_policy_rejects_classical():
    reg = default_registry()
    server = Server(reg, ["X25519"])
    client = Client(reg, ["X25519"], server.sig_pk, require_quantum_safe=True)
    with pytest.raises(PolicyViolation):
        client.complete(server.respond(client.hello()))
