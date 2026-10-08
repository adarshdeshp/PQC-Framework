"""
Phase 2 demo: run `python demo_phase2.py`

1. Mosca risk policy engine decides protection for each kind of data
2. Migration of stored data by key re-wrapping (payload untouched)
3. Algorithm compromise: ML-KEM declared broken -> automatic fallback
4. Downgrade attack on negotiation: naive client vs protected client
"""

import time
import warnings

warnings.filterwarnings("ignore")

from pqcf import envelope
from pqcf.negotiation import (Client, DowngradeDetected, Server,
                              mitm_strip_quantum_safe)
from pqcf.policy import SCENARIOS, DataAsset, MoscaPolicyEngine
from pqcf.registry import CryptoContext, default_registry

SAMPLE_ASSETS = [
    DataAsset("OTP code", "auth", 5 / (365 * 24 * 60), "low"),
    DataAsset("Login session token", "auth", 1 / 365, "medium"),
    DataAsset("Chat message", "messaging", 2, "medium"),
    DataAsset("E-commerce order history", "commerce", 5, "medium"),
    DataAsset("Bank transaction records", "finance", 10, "high"),
    DataAsset("Legal contract", "legal", 25, "high"),
    DataAsset("Medical record", "health", 50, "critical"),
    DataAsset("Government ID record", "identity", 70, "critical"),
]


def line(title):
    print("\n" + "=" * 78)
    print(f" {title}")
    print("=" * 78)


def life(years):
    if years < 1 / 365:
        return f"{years * 365 * 24 * 60:.0f} min"
    if years < 1:
        d = years * 365
        return f"{d:.0f} day" + ("" if round(d) == 1 else "s")
    return f"{years:.0f} yrs"


def part1_policy():
    engine = MoscaPolicyEngine.for_scenario("moderate", migration_years=3)
    line(f"1. MOSCA RISK POLICY  (X + Y > Z  with Y={engine.migration_years:.0f}y migration, "
         f"Z={engine.quantum_horizon_years:.0f}y to Q-day)")
    print(f"{'Data':<27}{'Shelf life':<11}{'Sensitivity':<12}{'Margin':>7}  {'Decision':<12}{'Reason'}")
    for d in engine.evaluate(SAMPLE_ASSETS):
        print(f"{d.asset.name:<27}{life(d.asset.shelf_life_years):<11}{d.asset.sensitivity:<12}"
              f"{d.risk_margin:>6.0f}y  {d.level:<12}{d.reason}")

    print("\nSame data under different Q-day assumptions (Z):")
    for name, z in SCENARIOS.items():
        e = MoscaPolicyEngine.for_scenario(name, migration_years=3)
        exposed = sum(d.at_risk for d in e.evaluate(SAMPLE_ASSETS))
        print(f"  {name:<11} Z={z:>2}y -> {exposed} of {len(SAMPLE_ASSETS)} data types exposed today")
    return engine


def part2_migration(registry, engine):
    line("2. MIGRATING STORED DATA BY KEY RE-WRAPPING")
    keys = envelope.KeyStore(registry)
    legacy = registry.kem("X25519")
    pk, sk = keys.keypair("X25519")

    store = {}
    for a in SAMPLE_ASSETS:
        payload = f"<<{a.name} contents>>".encode() * 2000          # ~40-60 KB each
        store[a.name] = envelope.encrypt_record(a.name, payload, legacy, pk)
    print(f"{len(store)} records stored today with legacy {legacy.name} (quantum-vulnerable)")

    plan = engine.migration_plan(SAMPLE_ASSETS)
    print(f"Policy engine says {len(plan)} records must migrate, in this order:")
    for i, d in enumerate(plan, 1):
        print(f"  {i}. {d.asset.name:<26} -> {d.kem:<20} (margin {d.risk_margin:.0f}y)")

    print()
    for d in plan:
        rec = store[d.asset.name]
        before = rec.payload_fingerprint()
        new_kem = registry.kem(d.kem)
        new_pk, new_sk = keys.keypair(d.kem)
        t = time.perf_counter()
        migrated = envelope.rewrap_record(rec, registry.kem_for_decryption(rec.kem_name),
                                          keys.secret_key(rec.kem_name), new_kem, new_pk)
        ms = (time.perf_counter() - t) * 1000
        ok = envelope.decrypt_record(migrated, new_kem, new_sk).startswith(f"<<{d.asset.name}".encode())
        same = migrated.payload_fingerprint() == before
        store[d.asset.name] = migrated
        print(f"  {d.asset.name:<26} re-wrapped in {ms:6.2f} ms | payload unchanged: {same} | readable: {ok}")
    print("\nOnly the 32-byte data key was re-protected; the encrypted data itself was never touched.")


def part3_compromise(registry):
    line("3. ALGORITHM COMPROMISE: 'ML-KEM has been broken'")
    ctx = CryptoContext.from_config(registry, "config.json")
    print(f"Active KEM before : {ctx.kem.name}")
    registry.mark_compromised("ML-KEM", "simulated cryptanalytic break")
    blocked = [n for n in registry.compromised() if n != "ML-KEM"]
    print(f"Blocked now       : {', '.join(sorted(blocked))}")
    kem = ctx.kem
    print(f"Active KEM after  : {kem.name}   ({ctx.events[-1]})")
    pk, sk = kem.keygen()
    ct, ss = kem.encaps(pk)
    print(f"New session works : {kem.decaps(sk, ct) == ss}  (no code change, no downtime)")


def part4_downgrade():
    line("4. DOWNGRADE ATTACK ON ALGORITHM NEGOTIATION")
    registry = default_registry()                    # fresh registry, nothing compromised
    prefs = ["X25519+ML-KEM-1024", "X25519+ML-KEM-768", "X25519"]

    # client still supports X25519 for backward compatibility with old servers
    for label, verify in [("Honest network, protected client", True),
                          ("Attacker in middle, NAIVE client", False),
                          ("Attacker in middle, PROTECTED client", True)]:
        server = Server(registry, prefs)
        client = Client(registry, prefs, server.sig_pk, require_quantum_safe=False,
                        verify_transcript=verify)
        hello = client.hello()
        if "Attacker" in label:
            hello = mitm_strip_quantum_safe(hello, registry)
        reply = server.respond(hello)
        try:
            ct, secret, kem_name = client.complete(reply)
            server.finish(ct)
            safe = registry.kem(kem_name).quantum_safe
            verdict = "quantum-safe" if safe else "DOWNGRADED to quantum-breakable crypto"
            print(f"{label:<38} -> agreed on {kem_name:<20} [{verdict}]")
        except DowngradeDetected as e:
            print(f"{label:<38} -> ATTACK DETECTED, handshake aborted ({e})")


def main():
    registry = default_registry()
    engine = part1_policy()
    part2_migration(registry, engine)
    part3_compromise(registry)
    part4_downgrade()
    line("PHASE 2 DEMO COMPLETE")


if __name__ == "__main__":
    main()
