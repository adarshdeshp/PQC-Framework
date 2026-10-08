"""
Envelope encryption + key re-wrapping (migration of stored data).

Each stored record is protected in two layers:

    payload  --AES-256-GCM-->  payload_ct        (key = DEK, random per record)
    DEK      --KEM + AES-GCM-> wrapped_dek       (key = KEK from the KEM)

AES-256 is already quantum-resistant, so the payload never needs to change.
The quantum-vulnerable part is the KEM that protects the DEK. Migrating a
record to a new algorithm therefore means re-wrapping only the 32-byte DEK:
cost depends on the number of records, not on the size of the data.

Note: re-wrapping protects data we still store. It cannot protect copies an
attacker already captured while they were wrapped with a classical algorithm.
"""

import hashlib
import os
from dataclasses import dataclass

from . import aead

DEK_LEN = 32


@dataclass
class EncryptedRecord:
    record_id: str
    kem_name: str
    kem_ciphertext: bytes
    wrapped_dek: bytes
    payload_ct: bytes
    version: int = 1

    def payload_fingerprint(self) -> str:
        """SHA-256 of the encrypted payload - lets us prove re-wrap didn't touch it."""
        return hashlib.sha256(self.payload_ct).hexdigest()


class KeyStore:
    """Holds one key pair per algorithm (stands in for a cloud KMS)."""

    def __init__(self, registry):
        self.registry = registry
        self._keys = {}

    def keypair(self, kem_name: str):
        if kem_name not in self._keys:
            self._keys[kem_name] = self.registry.kem(kem_name).keygen()
        return self._keys[kem_name]

    def secret_key(self, kem_name: str):
        """Old keys stay readable for unwrapping even after an algorithm is blocked."""
        return self._keys[kem_name][1]


def _wrap_ad(record_id: str, kem_name: str, version: int) -> bytes:
    return f"{record_id}|{kem_name}|v{version}".encode()


def encrypt_record(record_id: str, plaintext: bytes, kem, public_key: bytes) -> EncryptedRecord:
    dek = os.urandom(DEK_LEN)
    payload_ct = aead.encrypt(dek, plaintext, associated_data=record_id.encode())
    kem_ct, kek = kem.encaps(public_key)
    wrapped = aead.encrypt(kek, dek, associated_data=_wrap_ad(record_id, kem.name, 1))
    return EncryptedRecord(record_id, kem.name, kem_ct, wrapped, payload_ct, 1)


def _unwrap_dek(rec: EncryptedRecord, kem, secret_key: bytes) -> bytes:
    kek = kem.decaps(secret_key, rec.kem_ciphertext)
    return aead.decrypt(kek, rec.wrapped_dek, associated_data=_wrap_ad(rec.record_id, rec.kem_name, rec.version))


def decrypt_record(rec: EncryptedRecord, kem, secret_key: bytes) -> bytes:
    dek = _unwrap_dek(rec, kem, secret_key)
    return aead.decrypt(dek, rec.payload_ct, associated_data=rec.record_id.encode())


def rewrap_record(rec: EncryptedRecord, old_kem, old_secret_key: bytes,
                  new_kem, new_public_key: bytes) -> EncryptedRecord:
    """Move a record to a new KEM without decrypting or re-encrypting its payload."""
    dek = _unwrap_dek(rec, old_kem, old_secret_key)
    kem_ct, kek = new_kem.encaps(new_public_key)
    version = rec.version + 1
    wrapped = aead.encrypt(kek, dek, associated_data=_wrap_ad(rec.record_id, new_kem.name, version))
    return EncryptedRecord(rec.record_id, new_kem.name, kem_ct, wrapped, rec.payload_ct, version)


def reencrypt_record(rec: EncryptedRecord, old_kem, old_secret_key: bytes,
                     new_kem, new_public_key: bytes) -> EncryptedRecord:
    """Naive migration (for comparison only): decrypt everything, encrypt again."""
    plaintext = decrypt_record(rec, old_kem, old_secret_key)
    return encrypt_record(rec.record_id, plaintext, new_kem, new_public_key)
