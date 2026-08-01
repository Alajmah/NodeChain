"""Confidence Calibrator — deterministic confidence scoring from structured evidence features.

Computes calibrated confidence from source count, support strength, source agreement,
and source quality. This is a chain artifact, not a model opinion.

Placed between Evidence Synthesizer and Claim Validator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CalibrationResult:
    """Result of calibrating a single claim's confidence."""
    claim_id: str
    raw_confidence: float
    feature_based_confidence: float
    calibration_adjustment: float
    final_confidence: float
    reason_codes: list[str] = field(default_factory=list)
    caps_applied: list[str] = field(default_factory=list)


class ConfidenceCalibrator:
    """Deterministic confidence calibration from structured evidence features.

    Rules:
    - Source count caps: 0→0.20, 1→0.65, 2→0.75, 3+→0.85
    - Support strength: direct=0, indirect=-0.10, weak=-0.25
    - Source agreement: consistent=0, mixed=-0.10, contradicted→cap 0.35
    - Source quality: best<0.50→-0.10, best>0.80→+0.05
    - Invalid refs: any→cap 0.20
    """

    # Source count confidence caps
    SOURCE_COUNT_CAPS = {
        0: 0.20,
        1: 0.65,
        2: 0.75,
    }
    # 3+ sources → cap at 0.85

    # Support strength adjustments
    SUPPORT_STRENGTH_ADJ = {
        "direct": 0.0,
        "indirect": -0.10,
        "weak": -0.25,
    }

    # Source agreement adjustments
    SOURCE_AGREEMENT_ADJ = {
        "consistent": 0.0,
        "mixed": -0.10,
        "contradicted": None,  # Special: cap at 0.35
    }
    CONTRADICTED_CAP = 0.35

    # Source quality thresholds
    QUALITY_LOW_THRESHOLD = 0.50
    QUALITY_HIGH_THRESHOLD = 0.80
    QUALITY_LOW_PENALTY = -0.10
    QUALITY_HIGH_BONUS = 0.05

    # Invalid ref cap
    INVALID_REF_CAP = 0.20

    # Absolute bounds
    MIN_CONFIDENCE = 0.05
    MAX_CONFIDENCE = 0.95

    def calibrate_claim(
        self,
        claim: dict[str, Any],
        source_quality_map: dict[str, float] | None = None,
    ) -> CalibrationResult:
        """Calibrate a single claim's confidence from its evidence features.

        Args:
            claim: Claim dict with supporting_sources, support_strength,
                   source_agreement, confidence, etc.
            source_quality_map: Optional map of source_ref → quality_score
        """
        claim_id = claim.get("claim_id", "?")
        raw = claim.get("confidence", 0.5)
        if not isinstance(raw, (int, float)):
            raw = 0.5

        reason_codes: list[str] = []
        caps_applied: list[str] = []

        # Count valid (non-INVALID) supporting sources
        supporting = claim.get("supporting_sources", [])
        valid_sources = [
            s for s in supporting
            if isinstance(s, str) and "[INVALID]" not in s
        ]
        invalid_sources = [
            s for s in supporting
            if isinstance(s, str) and "[INVALID]" in s
        ]
        source_count = len(valid_sources)

        # 1. Source count cap
        if source_count == 0:
            cap = self.SOURCE_COUNT_CAPS[0]
            caps_applied.append(f"source_count_0_cap={cap}")
            reason_codes.append("no_valid_sources")
        elif source_count == 1:
            cap = self.SOURCE_COUNT_CAPS[1]
            caps_applied.append(f"source_count_1_cap={cap}")
        elif source_count == 2:
            cap = self.SOURCE_COUNT_CAPS[2]
        else:
            cap = 0.85

        feature_conf = min(raw, cap)

        # 2. Invalid ref cap (overrides everything)
        if invalid_sources:
            feature_conf = min(feature_conf, self.INVALID_REF_CAP)
            caps_applied.append(f"invalid_ref_cap={self.INVALID_REF_CAP}")
            reason_codes.append("has_invalid_source_refs")

        # 3. Support strength adjustment
        strength = (claim.get("support_strength") or "direct").lower()
        adj = self.SUPPORT_STRENGTH_ADJ.get(strength, 0.0)
        if adj != 0:
            reason_codes.append(f"support_strength_{strength}={adj}")
            feature_conf += adj

        # 4. Source agreement
        agreement = (claim.get("source_agreement") or "consistent").lower()
        agree_adj = self.SOURCE_AGREEMENT_ADJ.get(agreement, 0.0)
        if agree_adj is None:
            # Contradicted → hard cap
            feature_conf = min(feature_conf, self.CONTRADICTED_CAP)
            caps_applied.append(f"contradicted_cap={self.CONTRADICTED_CAP}")
            reason_codes.append("sources_contradicted")
        elif agree_adj != 0:
            reason_codes.append(f"source_agreement_{agreement}={agree_adj}")
            feature_conf += agree_adj

        # 5. Source quality adjustment
        if source_quality_map and valid_sources:
            best_quality = max(
                (source_quality_map.get(s, 0.5) for s in valid_sources),
                default=0.5,
            )
            if best_quality < self.QUALITY_LOW_THRESHOLD:
                feature_conf += self.QUALITY_LOW_PENALTY
                reason_codes.append(f"low_source_quality={best_quality:.2f}")
            elif best_quality > self.QUALITY_HIGH_THRESHOLD:
                feature_conf += self.QUALITY_HIGH_BONUS
                reason_codes.append(f"high_source_quality={best_quality:.2f}")

        # 6. High-confidence independence gate
        # Confidence >= 0.85 requires independent source clusters
        if feature_conf >= 0.85 and source_count >= 3:
            # Check independence via source metadata (if available)
            venues = set()
            for s_ref in valid_sources:
                # Extract venue from source ref or use ref as proxy
                venues.add(s_ref)  # Unique refs = unique sources
            if len(venues) < 2:
                # Sources may be duplicates or from same record
                feature_conf = min(feature_conf, 0.75)
                caps_applied.append("independence_cap=0.75")
                reason_codes.append(f"low_independence: {len(venues)} unique refs for {source_count} sources")

        # Clamp to bounds
        calibration_adj = feature_conf - raw
        final_conf = max(self.MIN_CONFIDENCE, min(self.MAX_CONFIDENCE, feature_conf))

        return CalibrationResult(
            claim_id=claim_id,
            raw_confidence=round(raw, 4),
            feature_based_confidence=round(feature_conf, 4),
            calibration_adjustment=round(calibration_adj, 4),
            final_confidence=round(final_conf, 4),
            reason_codes=reason_codes,
            caps_applied=caps_applied,
        )

    def calibrate_claims(
        self,
        claims: list[dict[str, Any]],
        source_quality_map: dict[str, float] | None = None,
    ) -> list[dict[str, Any]]:
        """Calibrate all claims and return enriched claim dicts.

        Adds calibrated_confidence, raw_confidence, and calibration_metadata
        to each claim.
        """
        results = []
        for claim in claims:
            cal = self.calibrate_claim(claim, source_quality_map)
            enriched = {**claim}
            enriched["raw_confidence"] = cal.raw_confidence
            enriched["calibrated_confidence"] = cal.final_confidence
            enriched["confidence"] = cal.final_confidence  # Updated for downstream
            enriched["calibration_metadata"] = {
                "feature_based_confidence": cal.feature_based_confidence,
                "calibration_adjustment": cal.calibration_adjustment,
                "reason_codes": cal.reason_codes,
                "caps_applied": cal.caps_applied,
            }
            results.append(enriched)

            logger.info(
                "Calibrated %s: raw=%.2f → calibrated=%.2f (%s)",
                cal.claim_id, cal.raw_confidence, cal.final_confidence,
                ", ".join(cal.reason_codes) if cal.reason_codes else "no_adjustment",
            )

        return results
