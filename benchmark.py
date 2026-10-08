"""
Phase 1 benchmark: run `python benchmark.py [iterations]`

Measures real timings (median ms) and real sizes (bytes) for every registered
algorithm, and writes results/kem_benchmark.csv and results/sig_benchmark.csv
for the Phase 3 dashboard.
"""

import csv
import statistics
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

from pqcf.registry import default_registry

RESULTS = Path("results")


def timed(fn, *args):
    t = time.perf_counter()
    out = fn(*args)
    return out, (time.perf_counter() - t) * 1000


def bench_kem(kem, n):
    kg, en, de = [], [], []
    for _ in range(n):
        (pk, sk), t1 = timed(kem.keygen)
        (ct, ss), t2 = timed(kem.encaps, pk)
        ss2, t3 = timed(kem.decaps, sk, ct)
        assert ss == ss2, f"{kem.name}: shared secrets differ"
        kg.append(t1); en.append(t2); de.append(t3)
    return {
        "algorithm": kem.name, "family": kem.family,
        "quantum_safe": kem.quantum_safe,
        "keygen_ms": statistics.median(kg), "encaps_ms": statistics.median(en),
        "decaps_ms": statistics.median(de),
        "public_key_B": len(pk), "ciphertext_B": len(ct),
        "on_wire_B": len(pk) + len(ct),
    }


def bench_sig(sig, n):
    msg = b"handshake-transcript" * 8
    kg, sg, vf = [], [], []
    for _ in range(n):
        (pk, sk), t1 = timed(sig.keygen)
        s, t2 = timed(sig.sign, sk, msg)
        ok, t3 = timed(sig.verify, pk, msg, s)
        assert ok, f"{sig.name}: verification failed"
        kg.append(t1); sg.append(t2); vf.append(t3)
    return {
        "algorithm": sig.name, "family": sig.family, "quantum_safe": sig.quantum_safe,
        "keygen_ms": statistics.median(kg), "sign_ms": statistics.median(sg),
        "verify_ms": statistics.median(vf),
        "public_key_B": len(pk), "signature_B": len(s),
    }


def save(rows, name):
    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / name, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    reg = default_registry()

    print(f"\nKEY ENCAPSULATION ({n} iterations, median)")
    print(f"{'Algorithm':<26}{'QSafe':<7}{'KeyGen ms':>10}{'Encaps ms':>11}{'Decaps ms':>11}"
          f"{'PubKey B':>10}{'Ctext B':>9}{'Wire B':>8}")
    kem_rows = []
    for kem in reg.list_kems():
        iters = max(5, n // 20) if kem.name.startswith("RSA") else n  # RSA keygen is slow
        r = bench_kem(kem, iters)
        kem_rows.append(r)
        print(f"{r['algorithm']:<26}{'yes' if r['quantum_safe'] else 'no':<7}{r['keygen_ms']:>10.3f}"
              f"{r['encaps_ms']:>11.3f}{r['decaps_ms']:>11.3f}{r['public_key_B']:>10}"
              f"{r['ciphertext_B']:>9}{r['on_wire_B']:>8}")

    print(f"\nDIGITAL SIGNATURES ({n} iterations, median)")
    print(f"{'Algorithm':<26}{'QSafe':<7}{'KeyGen ms':>10}{'Sign ms':>10}{'Verify ms':>11}"
          f"{'PubKey B':>10}{'Sig B':>8}")
    sig_rows = []
    for sig in reg.list_signatures():
        r = bench_sig(sig, n)
        sig_rows.append(r)
        print(f"{r['algorithm']:<26}{'yes' if r['quantum_safe'] else 'no':<7}{r['keygen_ms']:>10.3f}"
              f"{r['sign_ms']:>10.3f}{r['verify_ms']:>11.3f}{r['public_key_B']:>10}{r['signature_B']:>8}")

    save(kem_rows, "kem_benchmark.csv")
    save(sig_rows, "sig_benchmark.csv")

    x = next(r for r in kem_rows if r["algorithm"] == "X25519")
    h = next(r for r in kem_rows if "+" in r["algorithm"])
    print(f"\nKey finding: hybrid adds {h['on_wire_B'] - x['on_wire_B']} bytes on the wire "
          f"({h['on_wire_B'] / x['on_wire_B']:.0f}x X25519) -> PQC's main cost is bandwidth.")
    print(f"Results saved to {RESULTS}/kem_benchmark.csv and {RESULTS}/sig_benchmark.csv")


if __name__ == "__main__":
    main()
