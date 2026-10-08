"""
Mosca risk policy engine (core contribution).

Mosca's theorem: data is ALREADY at risk today if

        X  +  Y  >  Z
        X = how many years the data must stay secret (shelf life)
        Y = how many years the organisation needs to migrate to PQC
        Z = how many years until a quantum computer can break RSA/ECC

Because of "harvest now, decrypt later", an attacker can record data today and
decrypt it once Z years have passed. Long-lived data (medical, legal,
financial) is exposed now; short-lived data (OTPs, sessions) is not.

The engine:
  1. scores every data asset with risk_margin = X + Y - Z
  2. picks a protection level (classical / hybrid / hybrid-high)
  3. orders migration of stored data so the most exposed assets go first

Z is unknown, so it is an explicit, configurable assumption. The engine can be
run under several scenarios (aggressive / moderate / optimistic).
"""

from dataclasses import dataclass, field

SENSITIVITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Protection levels -> KEM used for that level
PROTECTION_KEM = {
    "CLASSICAL": "X25519",
    "HYBRID": "X25519+ML-KEM-768",
    "HYBRID-HIGH": "X25519+ML-KEM-1024",
}

# Assumed years until a cryptographically relevant quantum computer (Z).
# These are scenario assumptions, not predictions.
SCENARIOS = {"aggressive": 8, "moderate": 12, "optimistic": 20}


@dataclass
class DataAsset:
    name: str
    category: str
    shelf_life_years: float          # X
    sensitivity: str = "medium"      # low | medium | high | critical
    current_kem: str = "X25519"      # how it is protected today


@dataclass
class PolicyDecision:
    asset: DataAsset
    risk_margin: float               # X + Y - Z (>0 means exposed today)
    at_risk: bool
    level: str
    kem: str
    needs_migration: bool
    reason: str


@dataclass
class MoscaPolicyEngine:
    migration_years: float = 3.0               # Y
    quantum_horizon_years: float = 12.0        # Z
    high_margin_years: float = 10.0            # margin above which HYBRID-HIGH is used
    level_kems: dict = field(default_factory=lambda: dict(PROTECTION_KEM))

    @classmethod
    def for_scenario(cls, scenario: str, migration_years: float = 3.0):
        return cls(migration_years=migration_years, quantum_horizon_years=SCENARIOS[scenario])

    def risk_margin(self, asset: DataAsset) -> float:
        return asset.shelf_life_years + self.migration_years - self.quantum_horizon_years

    def decide(self, asset: DataAsset) -> PolicyDecision:
        margin = self.risk_margin(asset)
        rank = SENSITIVITY_RANK[asset.sensitivity]
        at_risk = margin > 0

        if not at_risk and rank < SENSITIVITY_RANK["high"]:
            level = "CLASSICAL"
            reason = f"expires {-margin:.0f}y before Q-day; classical is sufficient"
        elif at_risk and (margin >= self.high_margin_years or rank == SENSITIVITY_RANK["critical"]):
            level = "HYBRID-HIGH"
            reason = f"exposed by {margin:.0f}y and/or critical; maximum protection"
        else:
            level = "HYBRID"
            reason = (f"exposed by {margin:.0f}y" if at_risk
                      else "high sensitivity; hybrid as precaution")

        kem = self.level_kems[level]
        current_quantum_safe = "ML-KEM" in asset.current_kem or "Frodo" in asset.current_kem
        needs_migration = level != "CLASSICAL" and not current_quantum_safe
        return PolicyDecision(asset, margin, at_risk, level, kem, needs_migration, reason)

    def evaluate(self, assets) -> list:
        return [self.decide(a) for a in assets]

    def migration_plan(self, assets) -> list:
        """At-risk assets still on classical crypto, most exposed first."""
        todo = [d for d in self.evaluate(assets) if d.needs_migration]
        return sorted(todo, key=lambda d: (d.at_risk, d.risk_margin,
                                           SENSITIVITY_RANK[d.asset.sensitivity]), reverse=True)
