"""Tests for deterministic, scoped, typed attack-chain generation."""

import unittest

from app.attack_chain.engine import (
    build_attack_paths,
    path_confidence,
    path_is_logically_connected,
)
from app.attack_chain.mitre_mapping import (
    get_technique,
    map_vulnerability_to_technique,
)
from app.models.attack_chain import AttackChain, AttackChainStep
from app.models.finding import Finding, ValidationStatus


def make_finding(
    finding_id,
    *,
    scan_id="scan-001",
    asset_id="asset-001",
    target="http://asset-001.test",
    vulnerability_type="custom_security_condition",
    status=ValidationStatus.CONFIRMED,
    confidence=1.0,
    requires_all=None,
    requires_any=None,
    requires=None,
    provides=None,
    evidence_refs=None,
):
    return Finding(
        finding_id=finding_id,
        scan_id=scan_id,
        asset_id=asset_id,
        target=target,
        host=asset_id,
        source="unit_test",
        vulnerability_type=vulnerability_type,
        validation_status=status,
        validation_confidence=confidence,
        requires_all=list(requires_all or []),
        requires_any=list(requires_any or []),
        requires=list(requires or []),
        provides=list(provides or []),
        evidence={"finding": finding_id},
        evidence_refs=list(evidence_refs or []),
    )


def make_scan(**overrides):
    values = {
        "finding_id": "f-scan",
        "vulnerability_type": "nmap_scan",
        "provides": [
            "discovered_hosts",
            "discovered_open_ports",
            "discovered_services",
        ],
        "evidence_refs": ["evidence://scan"],
    }
    values.update(overrides)
    return make_finding(**values)


def make_sqli(**overrides):
    values = {
        "finding_id": "f-sqli",
        "vulnerability_type": "sql_injection",
        "requires_any": ["discovered_services"],
        "provides": ["application_compromise"],
        "evidence_refs": ["evidence://sqli"],
    }
    values.update(overrides)
    return make_finding(**values)


def make_repository_access(**overrides):
    values = {
        "finding_id": "f-repository",
        "vulnerability_type": "database_repository_access",
        "requires_any": ["application_compromise"],
        "provides": ["repository_data_access"],
        "evidence_refs": ["evidence://repository"],
    }
    values.update(overrides)
    return make_finding(**values)


def make_command_execution(**overrides):
    values = {
        "finding_id": "f-command-execution",
        "vulnerability_type": "command_execution",
        "evidence_refs": ["evidence://command-execution"],
    }
    values.update(overrides)
    return make_finding(**values)


class TestConfirmedChain(unittest.TestCase):

    def test_produces_confirmed_chain(self):
        chains = build_attack_paths([make_scan(), make_sqli()])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].status, "confirmed")

    def test_chain_contains_both_findings(self):
        chain = build_attack_paths([make_scan(), make_sqli()])[0]
        self.assertEqual(
            [step.finding_id for step in chain.steps],
            ["f-scan", "f-sqli"],
        )

    def test_scanner_step_has_no_adversary_technique(self):
        chain = build_attack_paths([make_scan(), make_sqli()])[0]
        self.assertIsNone(chain.steps[0].mitre_technique_id)
        self.assertEqual(chain.steps[0].step_type, "environmental_fact")

    def test_scanner_fact_alone_is_not_an_attack_chain(self):
        self.assertEqual(build_attack_paths([make_scan()]), [])

    def test_sqli_step_maps_to_t1190(self):
        chain = build_attack_paths([make_scan(), make_sqli()])[0]
        self.assertEqual(chain.steps[1].mitre_technique_id, "T1190")
        self.assertEqual(chain.mitre_techniques, ["T1190"])

    def test_evidence_references_are_preserved(self):
        chain = build_attack_paths([make_scan(), make_sqli()])[0]
        self.assertEqual(
            chain.evidence_refs,
            ["evidence://scan", "evidence://sqli"],
        )
        self.assertEqual(
            chain.steps[1].evidence_refs,
            ["evidence://sqli"],
        )


class TestRejectedFindings(unittest.TestCase):

    def test_rejected_finding_never_enters_chain(self):
        chains = build_attack_paths([
            make_scan(),
            make_sqli(
                status=ValidationStatus.REJECTED,
                confidence=0.0,
            ),
        ])
        all_ids = {
            step.finding_id
            for chain in chains
            for step in chain.steps
        }
        self.assertNotIn("f-sqli", all_ids)

    def test_rejected_exploit_does_not_emit_t1190(self):
        chains = build_attack_paths([
            make_scan(),
            make_sqli(
                status=ValidationStatus.REJECTED,
                confidence=0.0,
            ),
        ])
        self.assertFalse(any(
            "T1190" in chain.mitre_techniques
            for chain in chains
        ))

    def test_all_rejected_findings_produce_no_chains(self):
        chains = build_attack_paths([
            make_sqli(
                status=ValidationStatus.REJECTED,
                confidence=0.0,
            ),
        ])
        self.assertEqual(chains, [])


class TestUnixShellProgression(unittest.TestCase):

    def test_confirmed_t1190_unlocks_confirmed_t1059_004(self):
        chain = build_attack_paths([
            make_scan(),
            make_sqli(),
            make_command_execution(),
        ])[0]

        self.assertEqual(
            [step.finding_id for step in chain.steps],
            ["f-scan", "f-sqli", "f-command-execution"],
        )
        self.assertEqual(chain.mitre_techniques, ["T1190", "T1059.004"])
        self.assertEqual(chain.status, "confirmed")
        self.assertIn("command_execution", chain.capabilities_gained)

    def test_rejected_t1190_cannot_satisfy_command_prerequisite(self):
        chains = build_attack_paths([
            make_scan(),
            make_sqli(
                status=ValidationStatus.REJECTED,
                confidence=0.0,
            ),
            make_command_execution(),
        ])

        self.assertFalse(any(
            "T1059.004" in chain.mitre_techniques
            for chain in chains
        ))

    def test_rejected_command_execution_never_enters_a_chain(self):
        chains = build_attack_paths([
            make_scan(),
            make_sqli(),
            make_command_execution(
                status=ValidationStatus.REJECTED,
                confidence=0.0,
            ),
        ])

        self.assertEqual(len(chains), 1)
        self.assertNotIn("T1059.004", chains[0].mitre_techniques)
        self.assertNotIn(
            "f-command-execution",
            [step.finding_id for step in chains[0].steps],
        )

    def test_manual_review_command_execution_is_potential(self):
        chain = build_attack_paths([
            make_scan(),
            make_sqli(),
            make_command_execution(
                status=ValidationStatus.MANUAL_REVIEW,
                confidence=0.6,
            ),
        ])[0]

        self.assertEqual(chain.status, "potential")
        self.assertEqual(chain.mitre_techniques, ["T1190", "T1059.004"])

    def test_command_prerequisite_is_scan_isolated(self):
        chains = build_attack_paths([
            make_scan(scan_id="scan-A"),
            make_sqli(scan_id="scan-A"),
            make_command_execution(scan_id="scan-B"),
        ])

        self.assertFalse(any(
            "T1059.004" in chain.mitre_techniques
            for chain in chains
        ))

    def test_command_prerequisite_is_asset_isolated(self):
        chains = build_attack_paths([
            make_scan(asset_id="asset-A"),
            make_sqli(asset_id="asset-A"),
            make_command_execution(asset_id="asset-B"),
        ])

        self.assertFalse(any(
            "T1059.004" in chain.mitre_techniques
            for chain in chains
        ))

    def test_three_step_chain_identity_and_order_are_stable(self):
        findings = [make_scan(), make_sqli(), make_command_execution()]
        first = build_attack_paths(findings)[0]
        second = build_attack_paths(list(reversed(findings)))[0]

        self.assertEqual(first.chain_id, second.chain_id)
        self.assertEqual(
            [step.finding_id for step in first.steps],
            [step.finding_id for step in second.steps],
        )


class TestPotentialChains(unittest.TestCase):

    def test_detected_finding_produces_potential_chain(self):
        chain = build_attack_paths([
            make_scan(),
            make_sqli(
                status=ValidationStatus.DETECTED,
                confidence=0.2,
            ),
        ])[0]
        self.assertEqual(chain.status, "potential")

    def test_likely_finding_produces_potential_chain(self):
        chain = build_attack_paths([
            make_scan(),
            make_sqli(
                status=ValidationStatus.LIKELY,
                confidence=0.5,
            ),
        ])[0]
        self.assertEqual(chain.status, "potential")

    def test_manual_review_produces_potential_chain(self):
        chain = build_attack_paths([
            make_scan(),
            make_sqli(
                status=ValidationStatus.MANUAL_REVIEW,
                confidence=0.6,
            ),
        ])[0]
        self.assertEqual(chain.status, "potential")

    def test_potential_chain_uses_weakest_confidence(self):
        chain = build_attack_paths([
            make_scan(confidence=1.0),
            make_sqli(
                status=ValidationStatus.DETECTED,
                confidence=0.2,
            ),
        ])[0]
        self.assertEqual(chain.confidence, 0.2)


class TestScopeIsolation(unittest.TestCase):

    def test_same_asset_and_scan_chain_succeeds(self):
        chains = build_attack_paths([make_scan(), make_sqli()])
        self.assertTrue(any(
            len(chain.steps) == 2
            for chain in chains
        ))

    def test_different_asset_does_not_chain(self):
        chains = build_attack_paths([
            make_scan(asset_id="asset-A"),
            make_sqli(asset_id="asset-B"),
        ])
        self.assertFalse(any(
            {step.finding_id for step in chain.steps}
            == {"f-scan", "f-sqli"}
            for chain in chains
        ))

    def test_different_scan_does_not_chain(self):
        chains = build_attack_paths([
            make_scan(scan_id="scan-A"),
            make_sqli(scan_id="scan-B"),
        ])
        self.assertFalse(any(
            {step.finding_id for step in chain.steps}
            == {"f-scan", "f-sqli"}
            for chain in chains
        ))


class TestPrerequisiteSemantics(unittest.TestCase):

    def test_all_requires_every_capability(self):
        first = make_finding("f-a", provides=["cap-a"])
        second = make_finding("f-b", provides=["cap-b"])
        child = make_finding(
            "f-child",
            requires_all=["cap-a", "cap-b"],
            provides=["cap-c"],
        )
        chain = build_attack_paths([first, second, child])[0]
        self.assertEqual(
            {step.finding_id for step in chain.steps},
            {"f-a", "f-b", "f-child"},
        )

    def test_all_fails_when_one_capability_is_missing(self):
        first = make_finding("f-a", provides=["cap-a"])
        child = make_finding(
            "f-child",
            requires_all=["cap-a", "cap-b"],
            provides=["cap-c"],
        )
        chains = build_attack_paths([first, child])
        self.assertFalse(any(
            any(step.finding_id == "f-child" for step in chain.steps)
            for chain in chains
        ))

    def test_any_accepts_one_available_capability(self):
        first = make_finding("f-a", provides=["cap-a"])
        child = make_finding(
            "f-child",
            requires_any=["cap-a", "cap-b"],
            provides=["cap-c"],
        )
        chain = build_attack_paths([first, child])[0]
        self.assertEqual(len(chain.steps), 2)

    def test_any_fails_when_no_capability_is_available(self):
        child = make_finding(
            "f-child",
            requires_any=["cap-a", "cap-b"],
            provides=["cap-c"],
        )
        self.assertEqual(build_attack_paths([child]), [])

    def test_legacy_requires_is_interpreted_as_any(self):
        first = make_finding("f-a", provides=["cap-a"])
        child = make_finding(
            "f-child",
            requires=["cap-a", "cap-b"],
            provides=["cap-c"],
        )
        chain = build_attack_paths([first, child])[0]
        self.assertEqual(len(chain.steps), 2)


class TestPathQuality(unittest.TestCase):

    def test_duplicate_equivalent_paths_collapse(self):
        root = make_finding(
            "f-root",
            provides=["cap-a", "cap-b"],
        )
        child = make_finding(
            "f-child",
            requires_any=["cap-a", "cap-b"],
            provides=["cap-c"],
        )
        chains = build_attack_paths([root, child])
        self.assertEqual(len(chains), 1)

    def test_prefix_is_removed_when_longer_chain_exists(self):
        chains = build_attack_paths([make_scan(), make_sqli()])
        self.assertEqual(len(chains), 1)
        self.assertEqual(len(chains[0].steps), 2)

    def test_multiple_branches_remain_separate(self):
        root = make_scan()
        sqli = make_sqli()
        credentials = make_finding(
            "f-creds",
            vulnerability_type="default_credentials",
            requires_any=["discovered_services"],
            provides=["authenticated_session"],
        )
        chains = build_attack_paths([root, sqli, credentials])
        finding_sets = [
            {step.finding_id for step in chain.steps}
            for chain in chains
        ]
        self.assertIn({"f-scan", "f-sqli"}, finding_sets)
        self.assertIn({"f-scan", "f-creds"}, finding_sets)

    def test_no_unresolved_capability_is_invented(self):
        finding = make_finding("f-leaf", provides=[])
        chain = build_attack_paths([finding])[0]
        self.assertEqual(chain.capabilities_gained, [])
        self.assertNotIn("unresolved_f-leaf", chain.capabilities_gained)

    def test_path_logical_connection_helper(self):
        self.assertTrue(path_is_logically_connected([
            make_scan(),
            make_sqli(),
        ]))
        self.assertFalse(path_is_logically_connected([
            make_sqli(),
            make_scan(),
        ]))


class TestCapabilityProgression(unittest.TestCase):

    def test_branch_stops_at_explicit_terminal_capability(self):
        entry = make_finding(
            "f-entry",
            provides=["test_foothold"],
        )
        goal = make_finding(
            "f-goal",
            requires_any=["test_foothold"],
            provides=["test_goal_reached"],
        )
        downstream = make_finding(
            "f-downstream",
            requires_any=["test_goal_reached"],
            provides=["test_post_goal_action"],
        )

        chains = build_attack_paths(
            [entry, goal, downstream],
            terminal_capabilities={"test_goal_reached"},
        )

        self.assertEqual(len(chains), 1)
        self.assertEqual(
            [step.finding_id for step in chains[0].steps],
            ["f-entry", "f-goal"],
        )

    def test_downstream_step_is_not_appended_after_terminal_capability(self):
        entry = make_finding(
            "f-entry",
            provides=["test_foothold"],
        )
        goal = make_finding(
            "f-goal",
            requires_any=["test_foothold"],
            provides=["test_goal_reached"],
        )
        downstream = make_finding(
            "f-downstream",
            requires_any=["test_goal_reached"],
            provides=["test_post_goal_action"],
        )

        chains = build_attack_paths(
            [entry, goal, downstream],
            terminal_capabilities={"test_goal_reached"},
        )
        chained_ids = {
            step.finding_id
            for chain in chains
            for step in chain.steps
        }

        self.assertNotIn("f-downstream", chained_ids)

    def test_chain_continues_when_extension_adds_a_new_capability(self):
        entry = make_finding(
            "f-entry",
            provides=["test_foothold"],
        )
        execution = make_finding(
            "f-execution",
            requires_any=["test_foothold"],
            provides=["test_execution"],
        )
        control = make_finding(
            "f-control",
            requires_any=["test_execution"],
            provides=["test_system_control"],
        )

        chain = build_attack_paths([entry, execution, control])[0]

        self.assertEqual(
            [step.finding_id for step in chain.steps],
            ["f-entry", "f-execution", "f-control"],
        )

    def test_extension_with_no_new_capability_is_suppressed(self):
        control = make_finding(
            "f-control",
            provides=["test_account_control"],
        )
        redundant_action = make_finding(
            "f-redundant-action",
            requires_any=["test_account_control"],
            provides=["test_account_control"],
        )

        chains = build_attack_paths([control, redundant_action])

        self.assertEqual(len(chains), 1)
        self.assertEqual(
            [step.finding_id for step in chains[0].steps],
            ["f-control"],
        )


class TestStableChainIdentity(unittest.TestCase):

    def test_identical_input_has_identical_chain_id(self):
        findings = [make_scan(), make_sqli()]
        first = build_attack_paths(findings)[0]
        second = build_attack_paths(findings)[0]
        self.assertEqual(first.chain_id, second.chain_id)

    def test_input_order_does_not_change_chain_id(self):
        first = build_attack_paths([make_scan(), make_sqli()])[0]
        second = build_attack_paths([make_sqli(), make_scan()])[0]
        self.assertEqual(first.chain_id, second.chain_id)

    def test_changed_validation_changes_chain_id(self):
        confirmed = build_attack_paths([make_scan(), make_sqli()])[0]
        potential = build_attack_paths([
            make_scan(),
            make_sqli(
                status=ValidationStatus.LIKELY,
                confidence=0.5,
            ),
        ])[0]
        self.assertNotEqual(confirmed.chain_id, potential.chain_id)


class TestConfidence(unittest.TestCase):

    def test_adding_perfect_step_cannot_increase_confidence(self):
        short_chain = build_attack_paths([
            make_scan(confidence=0.6),
            make_sqli(confidence=1.0),
        ])[0]
        long_chain = build_attack_paths([
            make_scan(confidence=0.6),
            make_sqli(confidence=1.0),
            make_repository_access(confidence=1.0),
        ])[0]
        self.assertLessEqual(long_chain.confidence, short_chain.confidence)

    def test_lower_confidence_step_lowers_chain_confidence(self):
        chain = build_attack_paths([
            make_scan(confidence=0.9),
            make_sqli(confidence=0.4),
        ])[0]
        self.assertEqual(chain.confidence, 0.4)

    def test_empty_path_confidence_is_zero(self):
        self.assertEqual(path_confidence([]), 0.0)


class TestMITRESemantics(unittest.TestCase):

    def test_nmap_does_not_map_to_t1595(self):
        self.assertIsNone(map_vulnerability_to_technique("nmap_scan"))

    def test_generic_disclosure_does_not_map_to_t1213(self):
        self.assertIsNone(
            map_vulnerability_to_technique("information_disclosure")
        )
        finding = make_finding(
            "f-disclosure",
            vulnerability_type="information_disclosure",
            provides=["disclosed_information"],
        )
        chain = build_attack_paths([finding])[0]
        self.assertNotIn("T1213", chain.mitre_techniques)
        self.assertNotIn("exfiltrated_data", chain.capabilities_gained)
        self.assertEqual(
            chain.capabilities_gained,
            ["potential_information_exposure"],
        )

    def test_validated_repository_access_maps_to_t1213(self):
        definition = map_vulnerability_to_technique(
            "database_repository_access"
        )
        self.assertIsNotNone(definition)
        self.assertEqual(definition.technique_id, "T1213")

    def test_unknown_condition_has_no_technique(self):
        chain = build_attack_paths([
            make_finding("f-unknown", provides=["custom_capability"]),
        ])[0]
        self.assertEqual(chain.mitre_techniques, [])

    def test_t1190_keeps_reachable_service_prerequisite(self):
        definition = get_technique("T1190")
        self.assertIn("discovered_services", definition.requires_any)


class TestTypedInputOutput(unittest.TestCase):

    def test_engine_rejects_dictionary_input(self):
        with self.assertRaisesRegex(TypeError, "only Finding objects"):
            build_attack_paths([{"finding_id": "legacy"}])

    def test_output_is_typed(self):
        chain = build_attack_paths([make_scan(), make_sqli()])[0]
        self.assertIsInstance(chain, AttackChain)
        self.assertTrue(all(
            isinstance(step, AttackChainStep)
            for step in chain.steps
        ))

    def test_typed_output_serializes_to_dictionary(self):
        chain = build_attack_paths([make_scan(), make_sqli()])[0]
        serialized = chain.to_dict()
        self.assertEqual(serialized["chain_id"], chain.chain_id)
        self.assertEqual(serialized["steps"][1]["finding_id"], "f-sqli")


if __name__ == "__main__":
    unittest.main()
