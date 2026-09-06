"""Deterministic, scan- and asset-scoped attack-chain generation."""

from __future__ import annotations

import hashlib
import json
from itertools import product
from pathlib import Path
from typing import (
    AbstractSet,
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from urllib.parse import urlparse

from app.attack_chain.mitre_mapping import (
    enrich_finding_model,
    is_environmental_fact,
)
from app.models.attack_chain import AttackChain, AttackChainStep
from app.models.finding import (
    Finding,
    STATUS_WEIGHT,
    ValidationStatus,
)


BACKEND_DIR = Path(__file__).resolve().parents[2]
EVIDENCE_FILE = BACKEND_DIR / "data" / "evidence_store.json"
QUEUE_FILE = BACKEND_DIR / "data" / "manual_review_queue.json"
PATHWAYS_FILE = BACKEND_DIR / "data" / "attack_paths.json"

BASE_CAPABILITIES = frozenset({"unauthenticated"})
DEFAULT_TERMINAL_CAPABILITIES: frozenset[str] = frozenset()

TERMINATION_TERMINAL_CAPABILITY_REACHED = "terminal_capability_reached"
TERMINATION_NO_NEW_CAPABILITY = "no_new_capability"


def _load_json(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open() as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list")
    return data


def _host_from_target(target: str) -> str:
    parsed = urlparse(target)
    return parsed.hostname or target


def _legacy_entry_to_finding(
    entry: Dict[str, Any],
    *,
    scan_id: str,
) -> Finding:
    """Adapt checked-in legacy JSON fixtures at the engine boundary."""
    data = dict(entry)
    target = data.get("target")
    if not isinstance(target, str) or not target:
        raise ValueError("legacy finding is missing target")

    host = data.get("host") or _host_from_target(target)
    data.setdefault("scan_id", scan_id)
    data.setdefault("asset_id", host)
    data.setdefault("host", host)
    data["source"] = (
        data.get("source")
        or data.get("validator")
        or "legacy_json"
    )
    data.setdefault(
        "endpoint",
        data.get("raw_evidence_url")
        or data.get("evidence", {}).get("endpoint"),
    )

    return Finding.from_legacy_evidence(
        data,
        scan_id=data["scan_id"],
        asset_id=data["asset_id"],
        host=data["host"],
    )


def load_all_findings(
    *,
    scan_id: str = "legacy-json-scan",
) -> List[Finding]:
    """Load legacy JSON fixtures into canonical Finding objects."""
    entries = [
        *_load_json(EVIDENCE_FILE),
        *_load_json(QUEUE_FILE),
    ]
    return [
        _legacy_entry_to_finding(entry, scan_id=scan_id)
        for entry in entries
    ]


def _requirements_satisfied(
    finding: Finding,
    available_capabilities: Set[str],
) -> bool:
    requires_all = set(finding.effective_requires_all)
    requires_any = set(finding.effective_requires_any)
    all_satisfied = requires_all.issubset(available_capabilities)
    any_satisfied = (
        not requires_any
        or bool(requires_any & available_capabilities)
    )
    return all_satisfied and any_satisfied


def _sequence_is_valid(sequence: Sequence[Finding]) -> bool:
    available = set(BASE_CAPABILITIES)
    for finding in sequence:
        if not _requirements_satisfied(finding, available):
            return False
        available.update(finding.provides)
    return True


def _progression_block_reason(
    finding: Finding,
    available_capabilities: Set[str],
    *,
    is_extension: bool,
    terminal_capabilities: AbstractSet[str],
) -> Optional[str]:
    if terminal_capabilities & available_capabilities:
        return TERMINATION_TERMINAL_CAPABILITY_REACHED
    if is_extension and not (
        set(finding.provides) - available_capabilities
    ):
        return TERMINATION_NO_NEW_CAPABILITY
    return None


def _sequence_is_meaningful_progression(
    sequence: Sequence[Finding],
    terminal_capabilities: AbstractSet[str],
) -> bool:
    """Require valid prerequisites and a capability gain at each extension."""
    available = set(BASE_CAPABILITIES)
    for index, finding in enumerate(sequence):
        if not _requirements_satisfied(finding, available):
            return False
        if _progression_block_reason(
            finding,
            available,
            is_extension=index > 0,
            terminal_capabilities=terminal_capabilities,
        ) is not None:
            return False
        available.update(finding.provides)
    return True


def _normalize_terminal_capabilities(
    terminal_capabilities: Iterable[str],
) -> frozenset[str]:
    if isinstance(terminal_capabilities, (str, bytes)):
        raise TypeError(
            "terminal_capabilities must be an iterable of non-empty strings"
        )
    try:
        normalized = frozenset(terminal_capabilities)
    except TypeError as exc:
        raise TypeError(
            "terminal_capabilities must be an iterable of non-empty strings"
        ) from exc
    if not all(
        isinstance(capability, str) and capability
        for capability in normalized
    ):
        raise TypeError(
            "terminal_capabilities must contain only non-empty strings"
        )
    return normalized


def _deduplicate_plans(
    plans: Iterable[Tuple[Finding, ...]],
) -> List[Tuple[Finding, ...]]:
    unique: Dict[frozenset[str], Tuple[Finding, ...]] = {}
    for plan in plans:
        key = frozenset(finding.finding_id for finding in plan)
        existing = unique.get(key)
        plan_ids = tuple(finding.finding_id for finding in plan)
        if existing is None:
            unique[key] = plan
            continue
        existing_ids = tuple(finding.finding_id for finding in existing)
        if plan_ids < existing_ids:
            unique[key] = plan
    return sorted(
        unique.values(),
        key=lambda plan: tuple(finding.finding_id for finding in plan),
    )


def _merge_support_plans(
    support_plans: Sequence[Tuple[Finding, ...]],
    finding: Finding,
) -> Tuple[Finding, ...]:
    merged: List[Finding] = []
    seen: Set[str] = set()
    for plan in support_plans:
        for provider in plan:
            if provider.finding_id not in seen:
                merged.append(provider)
                seen.add(provider.finding_id)
    if finding.finding_id not in seen:
        merged.append(finding)
    return tuple(merged)


def _plans_providing(
    capability: str,
    findings: Sequence[Finding],
    trail: frozenset[str],
    terminal_capabilities: AbstractSet[str],
) -> List[Tuple[Finding, ...]]:
    if capability in BASE_CAPABILITIES:
        return [tuple()]

    plans: List[Tuple[Finding, ...]] = []
    for provider in findings:
        if provider.finding_id in trail:
            continue
        if capability not in provider.provides:
            continue
        plans.extend(_plans_for_finding(
            provider,
            findings,
            trail,
            terminal_capabilities=terminal_capabilities,
        ))
    return _deduplicate_plans(plans)


def _plans_for_finding(
    finding: Finding,
    findings: Sequence[Finding],
    trail: frozenset[str] = frozenset(),
    *,
    terminal_capabilities: AbstractSet[str] = DEFAULT_TERMINAL_CAPABILITIES,
) -> List[Tuple[Finding, ...]]:
    if finding.finding_id in trail:
        return []

    next_trail = trail | {finding.finding_id}
    requirement_groups: List[List[Tuple[Finding, ...]]] = []

    for capability in finding.effective_requires_all:
        provider_plans = _plans_providing(
            capability,
            findings,
            next_trail,
            terminal_capabilities,
        )
        if not provider_plans:
            return []
        requirement_groups.append(provider_plans)

    requires_any = finding.effective_requires_any
    if requires_any:
        any_provider_plans: List[Tuple[Finding, ...]] = []
        for capability in requires_any:
            any_provider_plans.extend(_plans_providing(
                capability,
                findings,
                next_trail,
                terminal_capabilities,
            ))
        any_provider_plans = _deduplicate_plans(any_provider_plans)
        if not any_provider_plans:
            return []
        requirement_groups.append(any_provider_plans)

    if not requirement_groups:
        return [(finding,)]

    plans: List[Tuple[Finding, ...]] = []
    for selected_plans in product(*requirement_groups):
        merged = _merge_support_plans(selected_plans, finding)
        if _sequence_is_meaningful_progression(
            merged,
            terminal_capabilities,
        ):
            plans.append(merged)
    return _deduplicate_plans(plans)


def _maximal_plans(
    plans: Iterable[Tuple[Finding, ...]],
) -> List[Tuple[Finding, ...]]:
    unique = _deduplicate_plans(plans)
    finding_sets = [
        frozenset(finding.finding_id for finding in plan)
        for plan in unique
    ]

    maximal = []
    for index, plan in enumerate(unique):
        if any(
            finding_sets[index] < other
            for other_index, other in enumerate(finding_sets)
            if other_index != index
        ):
            continue
        maximal.append(plan)
    return maximal


def classify_path(path: Sequence[Finding]) -> str:
    """Confirmed only when every participating finding is confirmed."""
    if path and all(
        finding.validation_status == ValidationStatus.CONFIRMED
        for finding in path
    ):
        return "confirmed"
    return "potential"


def path_confidence(path: Sequence[Finding]) -> float:
    """
    Use the minimum step confidence as conservative chain confidence.

    Adding another step can preserve or lower confidence, never increase it.
    """
    if not path:
        return 0.0
    return min(finding.validation_confidence for finding in path)


def path_is_logically_connected(path: Sequence[Finding]) -> bool:
    """Validate ALL/ANY prerequisites against capabilities gained in order."""
    return bool(path) and _sequence_is_valid(path)


def _stable_chain_id(path: Sequence[Finding]) -> str:
    payload = {
        "scan_id": path[0].scan_id,
        "asset_id": path[0].asset_id,
        "steps": [
            {
                "finding_id": finding.finding_id,
                "status": finding.validation_status,
                "confidence": finding.validation_confidence,
                "requires_all": finding.effective_requires_all,
                "requires_any": finding.effective_requires_any,
                "provides": finding.provides,
                "technique_id": finding.mitre_technique_id,
            }
            for finding in path
        ],
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"AC-{digest.upper()}"


def _build_step(index: int, finding: Finding) -> AttackChainStep:
    return AttackChainStep(
        step_number=index + 1,
        finding_id=finding.finding_id,
        scan_id=finding.scan_id,
        asset_id=finding.asset_id,
        target=finding.target,
        vulnerability_type=finding.vulnerability_type,
        validation_status=finding.validation_status,
        validation_confidence=finding.validation_confidence,
        requires_all=finding.effective_requires_all,
        requires_any=finding.effective_requires_any,
        requires=list(finding.requires),
        provides=list(finding.provides),
        mitre_tactic=finding.mitre_tactic,
        mitre_technique_id=finding.mitre_technique_id,
        mitre_technique_name=finding.mitre_technique_name,
        evidence=dict(finding.evidence),
        evidence_refs=list(finding.evidence_refs),
        step_type=(
            "environmental_fact"
            if is_environmental_fact(finding.vulnerability_type)
            else "finding"
        ),
    )


def _build_chain(path: Sequence[Finding]) -> AttackChain:
    capabilities = list(dict.fromkeys(
        capability
        for finding in path
        for capability in finding.provides
    ))
    techniques = list(dict.fromkeys(
        finding.mitre_technique_id
        for finding in path
        if finding.mitre_technique_id
    ))
    evidence_refs = list(dict.fromkeys(
        reference
        for finding in path
        for reference in finding.evidence_refs
    ))

    return AttackChain(
        chain_id=_stable_chain_id(path),
        scan_id=path[0].scan_id,
        asset_id=path[0].asset_id,
        target=path[0].target,
        status=classify_path(path),
        confidence=path_confidence(path),
        steps=[
            _build_step(index, finding)
            for index, finding in enumerate(path)
        ],
        capabilities_gained=capabilities,
        mitre_techniques=techniques,
        evidence_refs=evidence_refs,
    )


def build_attack_paths(
    findings: Sequence[Finding],
    *,
    terminal_capabilities: Iterable[str] = DEFAULT_TERMINAL_CAPABILITIES,
) -> List[AttackChain]:
    """
    Build maximal deterministic chains from canonical Finding objects.

    Findings are grouped by (scan_id, asset_id). Capability providers from
    another scan or asset are never considered. Terminal capabilities are an
    explicit opt-in policy; none of the current capability vocabulary is
    terminal by default.
    """
    if not isinstance(findings, Sequence):
        raise TypeError("findings must be a sequence of Finding objects")
    if not all(isinstance(finding, Finding) for finding in findings):
        raise TypeError("build_attack_paths accepts only Finding objects")

    normalized_terminal_capabilities = _normalize_terminal_capabilities(
        terminal_capabilities
    )

    usable = [
        enrich_finding_model(finding)
        for finding in findings
        if finding.validation_status != ValidationStatus.REJECTED
    ]

    groups: Dict[Tuple[str, str], List[Finding]] = {}
    for finding in usable:
        groups.setdefault(
            (finding.scan_id, finding.asset_id),
            [],
        ).append(finding)

    chains: List[AttackChain] = []
    for group_key in sorted(groups):
        scoped_findings = sorted(
            groups[group_key],
            key=lambda finding: finding.finding_id,
        )
        finding_ids = [finding.finding_id for finding in scoped_findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError(
                "finding_id values must be unique within a scan and asset"
            )

        plans = []
        for finding in scoped_findings:
            plans.extend(_plans_for_finding(
                finding,
                scoped_findings,
                terminal_capabilities=normalized_terminal_capabilities,
            ))

        for plan in _maximal_plans(plans):
            if all(
                is_environmental_fact(finding.vulnerability_type)
                for finding in plan
            ):
                continue
            chains.append(_build_chain(plan))

    order = {"confirmed": 0, "potential": 1}
    chains.sort(key=lambda chain: (
        chain.scan_id,
        chain.asset_id,
        order[chain.status],
        chain.chain_id,
    ))
    return chains


def save_attack_paths(
    attack_paths: Sequence[AttackChain],
    path: Path = PATHWAYS_FILE,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        json.dump(
            [attack_path.to_dict() for attack_path in attack_paths],
            handle,
            indent=2,
        )


def print_summary(attack_paths: Sequence[AttackChain]) -> None:
    if not attack_paths:
        print("[attack_chain] No attack chains generated.")
        return
    for chain in attack_paths:
        techniques = " -> ".join(chain.mitre_techniques) or "(environmental facts)"
        print(
            f"[{chain.status.upper()}] {chain.chain_id} | "
            f"confidence={chain.confidence:.2f} | {techniques}"
        )


def main() -> None:
    findings = load_all_findings()
    attack_paths = build_attack_paths(findings)
    save_attack_paths(attack_paths)
    print_summary(attack_paths)


if __name__ == "__main__":
    main()
