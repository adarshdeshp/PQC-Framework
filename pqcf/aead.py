"""
AES-256-GCM authenticated encryption for the actual data.

AES-256 is considered quantum-resistant: Grover's algorithm only reduces its
effective strength to ~128 bits, which is still infeasible to brute force.
The quantum-vulnerable part of today's systems is the RSA/ECC used to exchange
or wrap the AES key - which is what the KEM layer replaces.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Returns nonce || ciphertext+tag."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """Raises cryptography.exceptions.InvalidTag if data was tampered with."""
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, associated_data)
