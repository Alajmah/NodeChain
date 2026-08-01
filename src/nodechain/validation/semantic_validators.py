"""Semantic validators — beyond-schema validation for chain outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SemanticValidationResult:
    """Result of a semantic validation check."""
    valid: bool
    validator: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ReferentialIntegrityValidator:
    """Verify that source references in claims resolve to actual sources.

    This catches the Phase D bug: claims referenced source_ids that
    didn't match any source in the evidence base.
    """

    def validate(
        self, claims: list[dict[str, Any]], sources: list[dict[str, Any]]
    ) -> SemanticValidationResult:
        source_ids = set()
        for s in sources:
            # Check multiple possible ID fields
            for key in ("source_id", "id", "source_ref"):
                if s.get(key):
                    source_ids.add(s[key])

        errors = []
        warnings = []

        if not claims:
            return SemanticValidationResult(
                valid=True,
                validator="referential_integrity",
                warnings=["No claims to validate"],
            )

        for claim in claims:
            claim_id = claim.get("claim_id", "?")
            refs = claim.get("supporting_sources", [])
            if not refs:
                warnings.append(
                    f"Claim {claim_id} has no supporting_sources"
                )
                continue

            for ref in refs:
                if ref and ref not in source_ids:
                    errors.append(
                        f"Claim {claim_id} references non-existent source: '{ref}'"
                    )

        return SemanticValidationResult(
            valid=len(errors) == 0,
            validator="referential_integrity",
            errors=errors,
            warnings=warnings,
        )


class ConfidenceConsistencyValidator:
    """Verify that claim-level confidence is consistent with overall assessment.

    Catches: claims averaging 90%+ while overall confidence is 30%.
    This was the signal in Phase D that something was wrong.
    """

    def validate(
        self, claims: list[dict[str, Any]], overall_confidence: float
    ) -> SemanticValidationResult:
        errors = []
        warnings = []

        if not claims:
            return SemanticValidationResult(
                valid=True,
                validator="confidence_consistency",
            )

        claim_confs = []
        for c in claims:
            conf = c.get("confidence", 0)
            if isinstance(conf, (int, float)):
                claim_confs.append(conf)

        if not claim_confs:
            return SemanticValidationResult(
                valid=True,
                validator="confidence_consistency",
                warnings=["No numeric confidence values in claims"],
            )

        avg_claim_conf = sum(claim_confs) / len(claim_confs)

        # If claims average 80%+ but overall is below 35%, something is wrong
        if avg_claim_conf > 0.8 and overall_confidence < 0.35:
            errors.append(
                f"Confidence mismatch: claims average {avg_claim_conf:.0%} "
                f"but overall is {overall_confidence:.0%}. "
                f"Possibly hallucinated claims with inflated confidence."
            )

        # If more than 50% of claims have 100% confidence, flag for review
        perfect_claims = sum(1 for c in claim_confs if c >= 1.0)
        if perfect_claims > len(claim_confs) * 0.5 and len(claim_confs) > 1:
            errors.append(
                f"{perfect_claims}/{len(claim_confs)} claims have 100% confidence. "
                f"Model may be overconfident — possible hallucination."
            )

        # Warn if all claims have identical confidence
        if len(set(claim_confs)) == 1 and len(claim_confs) > 2:
            warnings.append(
                f"All {len(claim_confs)} claims have identical confidence "
                f"({claim_confs[0]:.2f}). May indicate template output."
            )

        return SemanticValidationResult(
            valid=len(errors) == 0,
            validator="confidence_consistency",
            errors=errors,
            warnings=warnings,
        )


class SourceEnrichmentValidator:
    """Verify that sources have meaningful content (not empty shells).

    Catches: sources with only IDs but no titles or abstracts,
    indicating the enrichment pipeline failed silently.
    """

    def validate(
        self, sources: list[dict[str, Any]]
    ) -> SemanticValidationResult:
        if not sources:
            return SemanticValidationResult(
                valid=True,
                validator="source_enrichment",
                warnings=["No sources to validate"],
            )

        empty_count = 0
        errors = []
        warnings = []

        for s in sources:
            has_title = bool((s.get("title") or "").strip())
            has_abstract = bool((s.get("abstract") or "").strip())
            has_content = bool((s.get("content") or "").strip())

            if not has_title and not has_abstract and not has_content:
                empty_count += 1
                source_ref = s.get("source_id", s.get("source_ref", "?"))
                warnings.append(
                    f"Source '{source_ref}' has no title, abstract, or content"
                )

        # If more than 50% of sources are empty, that's a pipeline failure
        if empty_count > len(sources) * 0.5:
            errors.append(
                f"{empty_count}/{len(sources)} sources are empty. "
                f"Source enrichment pipeline may be broken."
            )

        return SemanticValidationResult(
            valid=len(errors) == 0,
            validator="source_enrichment",
            errors=errors,
            warnings=warnings,
        )


class SourceRefValidityValidator:
    """Check for invalid source references after alias remapping.

    Catches: claims that cite fabricated IDs (marked [INVALID]).
    These are claims where the model invented a source ID not in the allowed set.
    """

    def validate(self, claims: list[dict[str, Any]]) -> SemanticValidationResult:
        errors = []
        warnings = []
        invalid_count = 0

        for claim in claims:
            claim_id = claim.get("claim_id", "?")
            for field in ("supporting_sources", "contradicting_sources"):
                for ref in claim.get(field, []):
                    if isinstance(ref, str) and "[INVALID]" in ref:
                        invalid_count += 1
                        errors.append(
                            f"Claim {claim_id} cites fabricated source in {field}: {ref}"
                        )

        if invalid_count:
            warnings.append(
                f"{invalid_count} fabricated source reference(s) detected. "
                f"These claims may have hallucinated citations."
            )

        return SemanticValidationResult(
            valid=invalid_count == 0,
            validator="source_ref_validity",
            errors=errors,
            warnings=warnings,
        )


class SemanticValidationPipeline:
    """Run all semantic validators and aggregate results."""

    def __init__(self) -> None:
        self.ref_validator = ReferentialIntegrityValidator()
        self.conf_validator = ConfidenceConsistencyValidator()
        self.enrichment_validator = SourceEnrichmentValidator()
        self.sourceref_validator = SourceRefValidityValidator()

    def validate_chain_output(
        self,
        evidence_output: dict[str, Any],
        response_output: dict[str, Any],
        sources: list[dict[str, Any]] | None = None,
    ) -> list[SemanticValidationResult]:
        """Run all semantic validators on chain outputs."""
        results = []

        # 1. Referential integrity: claims' sources must resolve
        claims = evidence_output.get("claims", [])
        all_sources = sources or evidence_output.get("sources", [])
        results.append(self.ref_validator.validate(claims, all_sources))

        # 2. Confidence consistency: claim vs overall
        overall = response_output.get("confidence_statement", {}).get("numeric", 0.0)
        results.append(self.conf_validator.validate(claims, overall))

        # 3. Source enrichment: sources must have content
        if all_sources:
            results.append(self.enrichment_validator.validate(all_sources))

        # 4. Source ref validity: no fabricated IDs
        results.append(self.sourceref_validator.validate(claims))

        return results

    def all_valid(self, results: list[SemanticValidationResult]) -> bool:
        return all(r.valid for r in results)

    def all_errors(self, results: list[SemanticValidationResult]) -> list[str]:
        errors = []
        for r in results:
            errors.extend(r.errors)
        return errors
