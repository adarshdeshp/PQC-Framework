"""
Downgrade-resistant algorithm negotiation.

The weakness of every crypto-agile system: if client and server negotiate an
algorithm, a man-in-the-middle can delete the strong options from the client's
offer, so both sides "agree" on a weak, quantum-breakable one.

Defence (same idea as TLS 1.3 transcript binding):
  1. Client sends its offer (supported KEMs, in preference order) + a nonce.
  2. Server picks the strongest common KEM and SIGNS a hash of the offer it
     received, its choice and its KEM public key, using ML-DSA-65.
  3. Client recomputes that hash from the offer it ACTUALLY sent. If an attacker
     modified the offer, the hashes differ and the signature check fails.
  4. Client also enforces a minimum policy (e.g. quantum-safe only).

Assumption: the client already trusts the server's long-term ML-DSA public key
(e.g. pinned or delivered through a certificate).
"""

import hashlib
import json
import os
from dataclasses import dataclass


class DowngradeDetected(Exception):
    pass


class PolicyViolation(Exception):
    pass


@dataclass
class ClientHello:
    offered_kems: list
    nonce: bytes

    def to_bytes(self) -> bytes:
        return json.dumps({"kems": self.offered_kems, "nonce": self.nonce.hex()}).encode()


@dataclass
class ServerHello:
    chosen_kem: str
    kem_public_key: bytes
    signature: bytes


def transcript_hash(client_hello_bytes: bytes, chosen_kem: str, kem_public_key: bytes) -> bytes:
    h = hashlib.sha256()
    for part in (b"PQCF-negotiation-v1", client_hello_bytes, chosen_kem.encode(), kem_public_key):
        h.update(len(part).to_bytes(4, "big") + part)
    return h.digest()


class Server:
    def __init__(self, registry, preference: list, sig_name: str = "ML-DSA-65"):
        self.registry = registry
        self.preference = preference                    # strongest first
        self.sig = registry.signature(sig_name)
        self.sig_pk, self._sig_sk = self.sig.keygen()  # long-term identity key
        self._kem_sk = None
        self.chosen = None

    def respond(self, hello: ClientHello) -> ServerHello:
        common = [k for k in self.preference
                  if k in hello.offered_kems and not self.registry.is_compromised(k)]
        if not common:
            raise PolicyViolation("No common approved algorithm")
        self.chosen = common[0]
        pk, self._kem_sk = self.registry.kem(self.chosen).keygen()
        sig = self.sig.sign(self._sig_sk, transcript_hash(hello.to_bytes(), self.chosen, pk))
        return ServerHello(self.chosen, pk, sig)

    def finish(self, kem_ciphertext: bytes) -> bytes:
        return self.registry.kem(self.chosen).decaps(self._kem_sk, kem_ciphertext)


class Client:
    def __init__(self, registry, supported: list, trusted_server_sig_pk: bytes,
                 sig_name: str = "ML-DSA-65", require_quantum_safe: bool = True,
                 verify_transcript: bool = True):
        self.registry = registry
        self.supported = supported
        self.server_pk = trusted_server_sig_pk
        self.sig = registry.signature(sig_name)
        self.require_qs = require_quantum_safe
        self.verify_transcript = verify_transcript   # False = naive, vulnerable client
        self.sent = None

    def hello(self) -> ClientHello:
        self.sent = ClientHello(list(self.supported), os.urandom(16))
        return self.sent

    def complete(self, sh: ServerHello) -> tuple:
        if self.verify_transcript:
            expected = transcript_hash(self.sent.to_bytes(), sh.chosen_kem, sh.kem_public_key)
            if not self.sig.verify(self.server_pk, expected, sh.signature):
                raise DowngradeDetected(
                    "Signed transcript does not match the offer we sent - handshake modified in transit")
        kem = self.registry.kem(sh.chosen_kem)
        if self.require_qs and not kem.quantum_safe:
            raise PolicyViolation(f"{kem.name} is not quantum-safe")
        ct, secret = kem.encaps(sh.kem_public_key)
        return ct, secret, kem.name


def mitm_strip_quantum_safe(hello: ClientHello, registry) -> ClientHello:
    """Attacker: removes every quantum-safe option from the client's offer."""
    weak = [k for k in hello.offered_kems if not registry.kem_for_decryption(k).quantum_safe]
    return ClientHello(weak, hello.nonce)
