# Crypto-Agile Hybrid Post-Quantum Cryptography Framework for Secure Cloud Communication

Final-year project, Dept. of ISE, DSCE. Current stage: **Phase 2 complete**.

## Project status

| # | Component | Phase | Status |
|---|-----------|-------|--------|
| 1 | Classical KEMs: X25519, RSA-3072 (baseline) | 1 | Done |
| 2 | Post-quantum KEMs: ML-KEM-512/768/1024 (FIPS 203) via liboqs | 1 | Done |
| 3 | Signatures: Ed25519, ML-DSA-44/65 (FIPS 204) | 1 | Done |
| 4 | Hybrid KEM: X25519 + ML-KEM combined through HKDF | 1 | Done |
| 5 | AES-256-GCM authenticated encryption | 1 | Done |
| 6 | Crypto-agility registry + config-driven algorithm selection | 1 | Done |
| 7 | Benchmark suite (timings + sizes, CSV export) | 1 | Done |
| 8 | Mosca risk policy engine (X + Y > Z) + migration ordering | 2 | Done |
| 9 | Envelope encryption + key re-wrapping for stored data | 2 | Done |
| 10 | Algorithm-compromise handling + automatic PQC fallback (FrodoKEM) | 2 | Done |
| 11 | Downgrade-resistant negotiation (signed transcript, ML-DSA-65) | 2 | Done |
| 12 | Evaluation: re-wrap vs re-encrypt, risk-aware vs PQC-everywhere | 2 | Done (synthetic workload) |
| 13 | Unit tests (31 tests) | 1-2 | Done |
| 14 | Client/server FastAPI services over the framework | 3 | Pending |
| 15 | Web dashboard + harvest-now-decrypt-later visualiser | 3 | Pending |
| 16 | Docker packaging, final evaluation on realistic workload, report | 3 | Pending |

## Structure

```
pqcf/
  kem.py          classical, post-quantum and hybrid KEMs (one common interface)
  signature.py    Ed25519 and ML-DSA signatures
  aead.py         AES-256-GCM
  registry.py     crypto-agility registry, compromise blocking, fallback chain
  envelope.py     envelope encryption + key re-wrapping            (Phase 2)
  policy.py       Mosca risk policy engine                         (Phase 2)
  negotiation.py  downgrade-resistant algorithm negotiation        (Phase 2)
config.json       active algorithm + fallback chain (no code change to switch)
demo_phase1.py    Phase 1 demo
demo_phase2.py    Phase 2 demo
benchmark.py      performance + size benchmarks -> results/*.csv
evaluate_phase2.py migration cost + strategy comparison -> results/*.csv
sample_output/    saved output of every script from our test run
tests/            pytest suite (31 tests)
```

## Setup

Linux / WSL / macOS:

```bash
sudo apt install build-essential cmake ninja-build git libssl-dev   # Ubuntu/WSL
pip install -r requirements.txt
```

The first `import oqs` automatically downloads and builds liboqs (takes a few minutes, once).

## Run

```bash
python demo_phase1.py       # Phase 1 demo
python demo_phase2.py       # Phase 2 demo
python benchmark.py 200     # algorithm benchmarks
python evaluate_phase2.py   # Phase 2 evaluation
python -m pytest -q         # tests
```

## Key findings so far

- ML-KEM-768 operations take ~0.02 ms, faster than X25519 (~0.08 ms) and RSA-3072 decryption (~1.7 ms).
- The real cost of post-quantum security is size: hybrid key exchange sends 2,352 bytes vs 64 for X25519; FrodoKEM (backup) needs ~31 KB.
- Re-wrapping a 50 MB record takes ~0.22 ms vs ~142 ms to re-encrypt it; re-wrap cost does not grow with data size.
- On a 10,000-asset synthetic workload, the Mosca risk-aware policy protects all 1,473 exposed assets while using ~80% less key-exchange data than "PQC everywhere" (ML-KEM-768). Classical-everywhere leaves all 1,473 exposed.
- A naive negotiation can be silently downgraded to X25519 by a man-in-the-middle; the signed-transcript negotiation detects and aborts it.

Workload mix and Q-day horizon (Z) are stated assumptions; see `evaluate_phase2.py` and `pqcf/policy.py`.
