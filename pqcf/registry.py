"""
Crypto-agility layer.

Algorithms are registered once by name. Applications ask for an algorithm by
name (from a config file / policy), never by importing a concrete class.
Switching algorithms = changing one config value, with zero code changes.

Phase 2 adds compromise handling: if an algorithm is declared broken, it is
blocked everywhere and the context automatically falls back to the next
approved algorithm in the configured chain.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

import oqs

from .kem import HybridKEM, OQSKEM, RSAOAEPKEM, X25519KEM
from .signature import Ed25519Signature, OQSSignature


class AlgorithmCompromised(Exception):
    pass


class AlgorithmRegistry:
    def __init__(self):
        self._kems, self._sigs = {}, {}
        self._compromised = {}          # name -> reason

    # ---- registration ----------------------------------------------------
    def register_kem(self, kem):
        self._kems[kem.name] = kem

    def register_signature(self, sig):
        self._sigs[sig.name] = sig

    # ---- compromise handling --------------------------------------------
    def mark_compromised(self, name: str, reason: str = "cryptanalytic break"):
        """
        Block an algorithm or a whole family, plus every hybrid containing it.
        mark_compromised("ML-KEM") blocks ML-KEM-512/768/1024 and their hybrids.
        """
        self._compromised[name] = reason
        for kem_name in list(self._kems) + list(self._sigs):
            parts = kem_name.split("+")
            if any(p == name or p.startswith(name + "-") for p in parts) and kem_name != name:
                self._compromised[kem_name] = (reason if len(parts) == 1
                                               else f"contains compromised {name}")

    def is_compromised(self, name: str) -> bool:
        return name in self._compromised

    def compromised(self) -> dict:
        return dict(self._compromised)

    # ---- lookup ------------------------------------------------------------
    def kem(self, name: str):
        if name not in self._kems:
            raise KeyError(f"KEM '{name}' not registered. Available: {list(self._kems)}")
        if self.is_compromised(name):
            raise AlgorithmCompromised(f"{name} is blocked: {self._compromised[name]}")
        return self._kems[name]

    def kem_for_decryption(self, name: str):
        """
        Blocked algorithms may not protect NEW data, but existing data wrapped
        with them must still be readable so it can be migrated (re-wrapped).
        """
        if name not in self._kems:
            raise KeyError(f"KEM '{name}' not registered")
        return self._kems[name]

    def signature(self, name: str):
        if name not in self._sigs:
            raise KeyError(f"Signature '{name}' not registered. Available: {list(self._sigs)}")
        if self.is_compromised(name):
            raise AlgorithmCompromised(f"{name} is blocked: {self._compromised[name]}")
        return self._sigs[name]

    def list_kems(self):
        return list(self._kems.values())

    def list_signatures(self):
        return list(self._sigs.values())


def default_registry() -> AlgorithmRegistry:
    """Registry with every algorithm the framework supports."""
    r = AlgorithmRegistry()
    x25519 = X25519KEM()
    r.register_kem(x25519)
    r.register_kem(RSAOAEPKEM(3072))
    for alg in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        r.register_kem(OQSKEM(alg))
    r.register_kem(HybridKEM(x25519, OQSKEM("ML-KEM-768")))
    r.register_kem(HybridKEM(x25519, OQSKEM("ML-KEM-1024")))

    # Backup post-quantum KEM based on different mathematics (plain LWE instead
    # of module-LWE). Used as fallback if ML-KEM is ever broken.
    if "FrodoKEM-976-AES" in oqs.get_enabled_kem_mechanisms():
        frodo = OQSKEM("FrodoKEM-976-AES")
        r.register_kem(frodo)
        r.register_kem(HybridKEM(x25519, frodo))

    r.register_signature(Ed25519Signature())
    for alg in ("ML-DSA-44", "ML-DSA-65"):
        r.register_signature(OQSSignature(alg))
    return r


@dataclass
class CryptoContext:
    """What the application actually uses: the active algorithms from config."""
    registry: AlgorithmRegistry
    kem_chain: list                       # preferred first, fallbacks after
    signature_name: str
    events: list = field(default_factory=list)

    @classmethod
    def from_config(cls, registry: AlgorithmRegistry, path: str):
        cfg = json.loads(Path(path).read_text())
        chain = [cfg["kem"]] + cfg.get("kem_fallbacks", [])
        return cls(registry=registry, kem_chain=chain, signature_name=cfg["signature"])

    @property
    def kem(self):
        """First algorithm in the chain that is registered and not compromised."""
        for name in self.kem_chain:
            if self.registry.is_compromised(name):
                continue
            try:
                kem = self.registry.kem(name)
            except KeyError:
                continue
            if name != self.kem_chain[0]:
                msg = f"fallback active: {self.kem_chain[0]} blocked -> using {name}"
                if not self.events or self.events[-1] != msg:
                    self.events.append(msg)
            return kem
        raise AlgorithmCompromised("No approved KEM left in the fallback chain")

    @property
    def signature(self):
        return self.registry.signature(self.signature_name)
