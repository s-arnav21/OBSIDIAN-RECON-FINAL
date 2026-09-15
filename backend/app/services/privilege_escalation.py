"""Privilege escalation depth map with per-CVE scoring.

Analyzes confirmed vulnerabilities to compute escalation paths,
depth scores, and MITRE ATT&CK technique mappings for privilege
escalation chains.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from app.attack_chain.mitre_mapping import (
    TECHNIQUE_DEFINITIONS,
    TechniqueDefinition,
    get_technique,
    map_vulnerability_to_technique,
)
from app.db.models import FindingORM, MitreMappingORM

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EscalationPathNode:
    finding_id: str
    vulnerability_type: str
    technique_id: Optional[str]
    technique_name: Optional[str]
    tactic: Optional[str]
    severity: str
    cvss_score: float
    depth_from_initial: int
    capability_gained: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vulnerability_type": self.vulnerability_type,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "depth_from_initial": self.depth_from_initial,
            "capability_gained": self.capability_gained,
        }


@dataclass
class EscalationPath:
    path_id: str
    nodes: List[EscalationPathNode]
    total_depth: int
    max_cvss: float
    combined_risk_score: float
    techniques_involved: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "total_depth": self.total_depth,
            "max_cvss": self.max_cvss,
            "combined_risk_score": self.combined_risk_score,
            "techniques_involved": self.techniques_involved,
        }


@dataclass
class PrivilegeEscalationMap:
    scan_id: str
    asset_id: str
    paths: List[EscalationPath]
    deepest_path: Optional[EscalationPath]
    highest_risk_score: float
    total_unique_techniques: int
    capability_graph: Dict[str, List[str]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "asset_id": self.asset_id,
            "paths": [p.to_dict() for p in self.paths],
            "deepest_path": self.deepest_path.to_dict() if self.deepest_path else None,
            "highest_risk_score": self.highest_risk_score,
            "total_unique_techniques": self.total_unique_techniques,
            "capability_graph": self.capability_graph,
        }


_SEVERITY_CVSS_MAP = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
    "unknown": 3.0,
}


def _severity_to_cvss(severity: str) -> float:
    return _SEVERITY_CVSS_MAP.get(severity.lower().strip(), 3.0)


def _finding_technique(
    finding: FindingORM,
) -> Optional[TechniqueDefinition]:
    """Resolve the MITRE technique for a finding."""
    mapping: Optional[MitreMappingORM] = None
    for m in finding.mitre_mappings:
        mapping = m
        break

    if mapping is not None:
        definition = get_technique(mapping.technique_id)
        if definition is not None:
            return definition

    return map_vulnerability_to_technique(finding.vulnerability_type)


def _capability_for_technique(
    technique: TechniqueDefinition,
) -> str:
    """Extract the primary capability a technique provides."""
    if technique.provides:
        return technique.provides[0]
    return f"capability:{technique.technique_id}"


def _build_capability_graph(
    findings: List[FindingORM],
) -> Dict[str, List[str]]:
    """Build a graph of capabilities: what each finding provides and needs."""
    graph: Dict[str, List[str]] = {}
    finding_capabilities: Dict[str, str] = {}

    for finding in findings:
        technique = _finding_technique(finding)
        if technique is None:
            continue
        cap = _capability_for_technique(technique)
        finding_capabilities[finding.id] = cap
        graph.setdefault(cap, [])

    for finding in findings:
        technique = _finding_technique(finding)
        if technique is None:
            continue
        cap = finding_capabilities.get(finding.id, "")
        for req in technique.requires_any:
            if req in graph:
                graph[req].append(cap)

    return graph


def _find_escalation_paths(
    findings: List[FindingORM],
    capability_graph: Dict[str, List[str]],
) -> List[EscalationPath]:
    """Find all valid escalation paths through the capability graph."""
    finding_by_id = {f.id: f for f in findings}
    paths: List[EscalationPath] = []

    # Map findings to their techniques
    finding_techniques: Dict[str, TechniqueDefinition] = {}
    for finding in findings:
        tech = _finding_technique(finding)
        if tech is not None:
            finding_techniques[finding.id] = tech

    # Build prerequisite -> finding map
    prereq_to_findings: Dict[str, List[str]] = {}
    for finding_id, tech in finding_techniques.items():
        for prereq in tech.requires_any:
            prereq_to_findings.setdefault(prereq, []).append(finding_id)

    # Find chain starters (findings that need only discovered_services or unauthenticated)
    initial_capabilities = {"discovered_services", "unauthenticated", "reachable_web_application"}
    starters: List[str] = []
    for finding_id, tech in finding_techniques.items():
        if any(cap in initial_capabilities for cap in tech.requires_any):
            starters.append(finding_id)

    # BFS to find paths
    for start_id in starters:
        visited: Set[str] = set()
        queue: List[List[str]] = [[start_id]]
        visited.add(start_id)

        while queue:
            current_path = queue.pop(0)
            last_finding = finding_by_id.get(current_path[-1])
            if last_finding is None:
                continue

            last_tech = finding_techniques.get(current_path[-1])
            if last_tech is None:
                continue

            last_cap = _capability_for_technique(last_tech)

            # Find next findings that depend on this capability
            next_findings = prereq_to_findings.get(last_cap, [])
            for next_id in next_findings:
                if next_id in visited or next_id in current_path:
                    continue

                new_path = current_path + [next_id]
                visited.add(next_id)
                queue.append(new_path)

                # Build path node list
                nodes = []
                for idx, fid in enumerate(new_path):
                    f = finding_by_id[fid]
                    tech = finding_techniques.get(fid)
                    cap = _capability_for_technique(tech) if tech else ""
                    nodes.append(EscalationPathNode(
                        finding_id=fid,
                        vulnerability_type=f.vulnerability_type,
                        technique_id=tech.technique_id if tech else None,
                        technique_name=tech.technique_name if tech else None,
                        tactic=tech.tactic if tech else None,
                        severity=f.severity or "unknown",
                        cvss_score=_severity_to_cvss(f.severity or "unknown"),
                        depth_from_initial=idx,
                        capability_gained=cap,
                    ))

                if len(nodes) > 1:
                    max_cvss = max(n.cvss_score for n in nodes)
                    risk_score = (
                        max_cvss * 0.6
                        + len(nodes) * 1.5
                        + max(n.depth_from_initial for n in nodes) * 2.0
                    )
                    techniques = [
                        n.technique_id for n in nodes if n.technique_id
                    ]
                    path_id = hashlib.sha256(
                        "|".join(n.finding_id for n in nodes).encode()
                    ).hexdigest()[:16]

                    paths.append(EscalationPath(
                        path_id=f"path-{path_id}",
                        nodes=nodes,
                        total_depth=len(nodes) - 1,
                        max_cvss=max_cvss,
                        combined_risk_score=round(risk_score, 2),
                        techniques_involved=techniques,
                    ))

    return sorted(paths, key=lambda p: p.combined_risk_score, reverse=True)


def build_privilege_escalation_map(
    scan_id: str,
    asset_id: str,
    findings: List[FindingORM],
) -> PrivilegeEscalationMap:
    """Build a complete privilege escalation depth map for a scan/asset."""
    relevant_findings = [
        f for f in findings
        if f.status in {"confirmed", "manual_review"}
        and _finding_technique(f) is not None
    ]

    capability_graph = _build_capability_graph(relevant_findings)
    paths = _find_escalation_paths(relevant_findings, capability_graph)

    deepest = max(paths, key=lambda p: p.total_depth) if paths else None
    highest_risk = max(
        (p.combined_risk_score for p in paths), default=0.0
    )
    unique_techniques = set()
    for path in paths:
        unique_techniques.update(path.techniques_involved)

    return PrivilegeEscalationMap(
        scan_id=scan_id,
        asset_id=asset_id,
        paths=paths,
        deepest_path=deepest,
        highest_risk_score=round(highest_risk, 2),
        total_unique_techniques=len(unique_techniques),
        capability_graph=capability_graph,
    )
