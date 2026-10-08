"""
Phase 1 demo: run `python demo_phase1.py`

1. Lists every registered algorithm (classical, post-quantum, hybrid)
2. Hybrid key exchange between two parties + AES-256-GCM encrypted message
3. Signed handshake with ML-DSA-65 (prevents man-in-the-middle key swap)
4. Crypto-agility: same application function, algorithm chosen by a string
5. Tamper detection
"""

import warnings

warnings.filterwarnings("ignore")

from cryptography.exceptions import InvalidTag

from pqcf import aead
from pqcf.registry import CryptoContext, default_registry


def line(title=""):
    print("\n" + "=" * 70)
    if title:
        print(f" {title}")
        print("=" * 70)


def establish_session(kem, sig):
    """
    Application code. Notice it never names a concrete algorithm:
    it only uses the common interface -> this is crypto-agility.
    """
    # Server: long-term signing key + fresh KEM key pair
    server_sig_pk, server_sig_sk = sig.keygen()
    server_kem_pk, server_kem_sk = kem.keygen()
    signed_offer = sig.sign(server_sig_sk, server_kem_pk)

    # Client: verifies the server's KEM key really came from the server
    if not sig.verify(server_sig_pk, server_kem_pk, signed_offer):
        raise RuntimeError("Handshake signature invalid - possible MITM")
    ciphertext, client_secret = kem.encaps(server_kem_pk)

    # Server: recovers the same shared secret
    server_secret = kem.decaps(server_kem_sk, ciphertext)
    return client_secret, server_secret, server_kem_pk, ciphertext, signed_offer


def main():
    registry = default_registry()

    line("1. REGISTERED ALGORITHMS (crypto-agility registry)")
    print(f"{'Algorithm':<22}{'Type':<10}{'Family':<15}{'Quantum-safe'}")
    for k in registry.list_kems():
        print(f"{k.name:<22}{'KEM':<10}{k.family:<15}{'YES' if k.quantum_safe else 'NO (Shor)'}")
    for s in registry.list_signatures():
        print(f"{s.name:<22}{'SIG':<10}{s.family:<15}{'YES' if s.quantum_safe else 'NO (Shor)'}")

    line("2. HYBRID SECURE SESSION (config.json -> X25519 + ML-KEM-768)")
    ctx = CryptoContext.from_config(registry, "config.json")
    print(f"Active KEM       : {ctx.kem.name}")
    print(f"Active signature : {ctx.signature.name}")
    c_ss, s_ss, pk, ct, sig = establish_session(ctx.kem, ctx.signature)
    print(f"Public key size  : {len(pk)} bytes")
    print(f"Ciphertext size  : {len(ct)} bytes")
    print(f"Signature size   : {len(sig)} bytes")
    print(f"Client secret    : {c_ss.hex()[:32]}...")
    print(f"Server secret    : {s_ss.hex()[:32]}...")
    print(f"Secrets match    : {c_ss == s_ss}")

    session_key = s_ss
    message = b"Patient record #4471 - retention: 50 years"
    blob = aead.encrypt(c_ss, message, associated_data=b"session-1")
    recovered = aead.decrypt(s_ss, blob, associated_data=b"session-1")
    print(f"\nEncrypted (AES-256-GCM) : {blob.hex()[:48]}...")
    print(f"Decrypted by server     : {recovered.decode()}")

    line("3. CRYPTO-AGILITY: same function, algorithm swapped by name only")
    for kem_name, sig_name in [("X25519", "Ed25519"),
                               ("ML-KEM-768", "ML-DSA-65"),
                               ("X25519+ML-KEM-768", "ML-DSA-65")]:
        kem, s = registry.kem(kem_name), registry.signature(sig_name)
        c_ss, s_ss, *_ = establish_session(kem, s)
        status = "quantum-safe" if kem.quantum_safe and s.quantum_safe else "NOT quantum-safe"
        print(f"{kem_name:<20} + {sig_name:<10} -> secrets match: {c_ss == s_ss}  [{status}]")

    line("4. TAMPER DETECTION")
    assert aead.decrypt(session_key, blob, b"session-1") == message  # untampered still works
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    try:
        aead.decrypt(session_key, bytes(tampered), associated_data=b"session-1")
        print("Tampered message accepted  -> FAIL")
    except InvalidTag:
        print("Tampered ciphertext rejected by AES-GCM authentication -> OK")
    print("Forged handshake signature :",
          "rejected -> OK" if not registry.signature("ML-DSA-65").verify(
              registry.signature("ML-DSA-65").keygen()[0], pk, sig) else "accepted -> FAIL")

    line("PHASE 1 DEMO COMPLETE")


if __name__ == "__main__":
    main()
