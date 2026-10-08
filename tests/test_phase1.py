import warnings

warnings.filterwarnings("ignore")

import pytest
from cryptography.exceptions import InvalidTag

from pqcf import aead
from pqcf.kem import HybridKEM, OQSKEM, X25519KEM
from pqcf.registry import CryptoContext, default_registry

REG = default_registry()


@pytest.mark.parametrize("kem", REG.list_kems(), ids=lambda k: k.name)
def test_kem_roundtrip(kem):
    pk, sk = kem.keygen()
    ct, ss = kem.encaps(pk)
    assert kem.decaps(sk, ct) == ss
    assert len(ss) == 32


@pytest.mark.parametrize("sig", REG.list_signatures(), ids=lambda s: s.name)
def test_signature_valid_and_forged(sig):
    pk, sk = sig.keygen()
    s = sig.sign(sk, b"message")
    assert sig.verify(pk, b"message", s)
    assert not sig.verify(pk, b"tampered", s)


def test_fips203_sizes():
    pk, sk = REG.kem("ML-KEM-768").keygen()
    ct, _ = REG.kem("ML-KEM-768").encaps(pk)
    assert (len(pk), len(ct)) == (1184, 1088)  # FIPS 203 parameter set


def test_hybrid_depends_on_both_components():
    """Changing either component's ciphertext must change the hybrid secret."""
    from pqcf.kem import _pack, _unpack
    h = HybridKEM(X25519KEM(), OQSKEM("ML-KEM-768"))
    pk, sk = h.keygen()
    ct, ss = h.encaps(pk)
    ct_c, ct_p = _unpack(ct)
    bad_p = bytearray(ct_p); bad_p[0] ^= 1
    assert h.decaps(sk, _pack(ct_c, bytes(bad_p))) != ss  # ML-KEM implicit rejection
    other_ct_c, _ = X25519KEM().encaps(_unpack(pk)[0])
    assert h.decaps(sk, _pack(other_ct_c, ct_p)) != ss


def test_aead_tamper_detected():
    key = b"k" * 32
    blob = aead.encrypt(key, b"secret", b"ad")
    assert aead.decrypt(key, blob, b"ad") == b"secret"
    bad = bytearray(blob); bad[-1] ^= 1
    with pytest.raises(InvalidTag):
        aead.decrypt(key, bytes(bad), b"ad")


def test_config_driven_agility(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"kem": "ML-KEM-1024", "signature": "ML-DSA-44"}')
    ctx = CryptoContext.from_config(REG, str(cfg))
    assert ctx.kem.name == "ML-KEM-1024" and ctx.signature.name == "ML-DSA-44"


def test_unknown_algorithm_rejected():
    with pytest.raises(KeyError):
        REG.kem("DES-56")
