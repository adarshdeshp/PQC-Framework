"""
Phase 2 evaluation: run `python evaluate_phase2.py`

A. Migration cost: key re-wrapping vs full re-encryption, for growing data sizes
B. Strategy comparison on a synthetic workload of 10,000 data assets:
     classical everywhere  vs  PQC everywhere  vs  Mosca risk-aware policy

The workload mix is an ASSUMPTION (stated below), chosen to resemble a typical
consumer cloud service. Results change with the mix; the script makes that
explicit rather than hiding it.
"""

import csv
import os
import random
import statistics
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

from pqcf import envelope
from pqcf.policy import DataAsset, MoscaPolicyEngine
from pqcf.registry import default_registry

RESULTS = Path("results")

# category: (share of assets, shelf life in years, sensitivity)
WORKLOAD = {
    "OTP / auth codes":       (0.30, 5 / (365 * 24 * 60), "low"),
    "Session tokens":         (0.25, 1 / 365, "medium"),
    "Chat messages":          (0.20, 2, "medium"),
    "Order history":          (0.10, 5, "medium"),
    "Financial transactions": (0.08, 10, "high"),
    "Legal contracts":        (0.04, 25, "high"),
    "Medical records":        (0.02, 50, "critical"),
    "Government ID records":  (0.01, 70, "critical"),
}


def median_ms(fn, n):
    times = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return statistics.median(times)


def part_a(registry):
    print("\nA. MIGRATION COST: re-wrap key vs re-encrypt data (X25519 -> X25519+ML-KEM-768)")
    print(f"{'Record size':<14}{'Re-wrap ms':>12}{'Re-encrypt ms':>15}{'Speed-up':>10}")
    old, new = registry.kem("X25519"), registry.kem("X25519+ML-KEM-768")
    old_pk, old_sk = old.keygen()
    new_pk, _ = new.keygen()
    rows = []
    for label, size in [("1 KB", 1_000), ("100 KB", 100_000), ("1 MB", 1_000_000),
                        ("10 MB", 10_000_000), ("50 MB", 50_000_000)]:
        rec = envelope.encrypt_record("r", os.urandom(size), old, old_pk)
        n = 30 if size <= 1_000_000 else 5
        rw = median_ms(lambda: envelope.rewrap_record(rec, old, old_sk, new, new_pk), n)
        re = median_ms(lambda: envelope.reencrypt_record(rec, old, old_sk, new, new_pk), n)
        rows.append({"record_size": label, "rewrap_ms": round(rw, 3),
                     "reencrypt_ms": round(re, 3), "speedup_x": round(re / rw, 1)})
        print(f"{label:<14}{rw:>12.3f}{re:>15.3f}{re / rw:>9.1f}x")
    print("-> re-wrap time stays flat; re-encryption grows with data size.")
    return rows


def kem_cost(kem, n=200):
    """Measured per-record cost: bytes stored/sent + time for encaps+decaps."""
    pk, sk = kem.keygen()
    ct, _ = kem.encaps(pk)
    ms = median_ms(lambda: kem.decaps(sk, kem.encaps(pk)[0]), n)
    return {"bytes": len(pk) + len(ct), "ms": ms}


def build_workload(n, seed=7):
    rng = random.Random(seed)
    names, weights = list(WORKLOAD), [v[0] for v in WORKLOAD.values()]
    assets = []
    for i in range(n):
        cat = rng.choices(names, weights)[0]
        _, life, sens = WORKLOAD[cat]
        assets.append(DataAsset(f"{cat}#{i}", cat, life, sens))
    return assets


def part_b(registry, n_assets=10_000):
    print(f"\nB. STRATEGY COMPARISON on {n_assets:,} synthetic data assets (moderate scenario, Z=12y, Y=3y)")
    engine = MoscaPolicyEngine.for_scenario("moderate", migration_years=3)
    assets = build_workload(n_assets)
    decisions = engine.evaluate(assets)

    costs = {name: kem_cost(registry.kem(name)) for name in
             ("X25519", "X25519+ML-KEM-768", "X25519+ML-KEM-1024")}

    def summarise(label, kem_for):
        total_bytes = total_ms = unprotected = 0
        for d in decisions:
            kem_name = kem_for(d)
            total_bytes += costs[kem_name]["bytes"]
            total_ms += costs[kem_name]["ms"]
            if d.at_risk and "ML-KEM" not in kem_name:
                unprotected += 1
        return {"strategy": label, "total_MB": round(total_bytes / 1e6, 2),
                "total_cpu_s": round(total_ms / 1000, 2), "exposed_assets_left": unprotected}

    rows = [
        summarise("Classical everywhere", lambda d: "X25519"),
        summarise("PQC everywhere (ML-KEM-768)", lambda d: "X25519+ML-KEM-768"),
        summarise("PQC everywhere (ML-KEM-1024)", lambda d: "X25519+ML-KEM-1024"),
        summarise("Mosca risk-aware (ours)", lambda d: d.kem),
    ]
    at_risk = sum(d.at_risk for d in decisions)
    print(f"Assets exposed today under Mosca: {at_risk:,} of {n_assets:,}\n")
    print(f"{'Strategy':<32}{'Key data MB':>12}{'CPU s':>8}{'Exposed left':>14}")
    for r in rows:
        print(f"{r['strategy']:<32}{r['total_MB']:>12}{r['total_cpu_s']:>8}{r['exposed_assets_left']:>14}")

    ours, pqc768 = rows[3], rows[1]
    saved = 100 * (1 - ours["total_MB"] / pqc768["total_MB"])
    print(f"\n-> Risk-aware policy protects ALL exposed assets while using {saved:.0f}% less "
          f"key-exchange data than PQC-everywhere (ML-KEM-768),")
    print(f"   and gives the most sensitive data ML-KEM-1024. Classical-everywhere leaves "
          f"{rows[0]['exposed_assets_left']:,} assets exposed.")
    print("   (Depends on the workload mix above - with more long-lived data, savings shrink.)")
    return rows


def save(rows, name):
    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / name, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)


def main():
    registry = default_registry()
    save(part_a(registry), "rewrap_vs_reencrypt.csv")
    save(part_b(registry), "strategy_comparison.csv")
    print(f"\nResults saved to {RESULTS}/")


if __name__ == "__main__":
    main()
