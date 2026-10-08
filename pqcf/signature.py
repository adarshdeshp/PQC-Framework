"""
Digital signatures behind one common interface.
Used to authenticate handshakes so a man-in-the-middle can't swap keys.

    keygen()                  -> (public_key, secret_key)
    sign(secret_key, msg)     -> signature
    verify(public_key, msg, signature) -> bool
"""

from abc import ABC, abstractmethod

import oqs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class Signature(ABC):
    name: str = "abstract"
    family: str = "abstract"
    quantum_safe: bool = False

    @abstractmethod
    def keygen(self) -> tuple: ...

    @abstractmethod
    def sign(self, secret_key: bytes, message: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


class Ed25519Signature(Signature):
    name, family, quantum_safe = "Ed25519", "classical", False

    def keygen(self):
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        skb = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
        return pk, skb

    def sign(self, secret_key, message):
        return ed25519.Ed25519PrivateKey.from_private_bytes(secret_key).sign(message)

    def verify(self, public_key, message, signature):
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except InvalidSignature:
            return False


class OQSSignature(Signature):
    """Any signature scheme provided by liboqs, e.g. ML-DSA-65 (FIPS 204)."""
    family, quantum_safe = "post-quantum", True

    def __init__(self, alg: str):
        if alg not in oqs.get_enabled_sig_mechanisms():
            raise ValueError(f"{alg} is not enabled in this liboqs build")
        self.name = alg

    def keygen(self):
        with oqs.Signature(self.name) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
        return pk, sk

    def sign(self, secret_key, message):
        with oqs.Signature(self.name, secret_key=secret_key) as s:
            return s.sign(message)

    def verify(self, public_key, message, signature):
        with oqs.Signature(self.name) as s:
            return s.verify(message, signature, public_key)
