"""Contract tests for the planner training dataset and its validator."""

from __future__ import annotations

import copy
import json
import unittest

from app.agent.training_data import (
    TECHNIQUE_IDS,
    build_dataset,
    dumps_jsonl,
    validate_dataset,
    validate_jsonl,
    validate_record,
)


def _copy(record):
    return copy.deepcopy(record)


class PlannerDatasetTests(unittest.TestCase):
    def setUp(self):
        self.records = build_dataset()

    def test_dataset_is_valid_and_deterministic(self):
        self.assertTrue(self.records)
        self.assertEqual(validate_dataset(self.records), [])
        self.assertEqual(self.records, build_dataset())

    def test_every_record_has_exact_top_level_fields(self):
        expected = {
            "scenario_id",
            "step_index",
            "state",
            "available_tools",
            "output",
            "supervision",
        }
        for record in self.records:
            self.assertEqual(set(record), expected)

    def test_all_eight_techniques_are_covered(self):
        covered = {
            record["supervision"]["technique_id"]
            for record in self.records
        }
        self.assertEqual(covered, set(TECHNIQUE_IDS))

    def test_required_negative_cases_are_taught(self):
        codes = {
            rejected["code"]
            for record in self.records
            for rejected in record["supervision"]["rejected_candidates"]
        }
        self.assertTrue({
            "denied_duplicate",
            "denied_prerequisite",
            "denied_step_limit",
            "denied_unknown_tool",
            "denied_invalid_reference",
        }.issubset(codes))

    def test_planner_visible_data_has_no_cwe_owasp_or_raw_evidence(self):
        serialized = json.dumps(
            [
                {
                    "state": record["state"],
                    "available_tools": record["available_tools"],
                    "output": record["output"],
                }
                for record in self.records
            ]
        )
        for forbidden in (
            "CWE-",
            "OWASP",
            "CVSS",
            "raw_finding",
            "http_request_context",
            '"evidence"',
            '"password"',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_validator_requests_come_before_external_escalation(self):
        actions = [
            (record["scenario_id"], record["output"]["action"]["tool_id"])
            for record in self.records
            if record["output"]["action"] is not None
        ]
        t1190 = [tool for scenario, tool in actions if scenario.startswith("t1190")]
        self.assertEqual(t1190, ["validate-sql-injection", "sqlmap-exploit"])

    def test_jsonl_round_trip(self):
        text = dumps_jsonl(self.records)
        self.assertEqual(validate_jsonl(text), [])
        parsed = [json.loads(line) for line in text.splitlines()]
        self.assertEqual(parsed, self.records)


class PlannerDatasetNegativeTests(unittest.TestCase):
    def setUp(self):
        self.records = build_dataset()
        self.record = _copy(self.records[1])  # first action record

    def assert_invalid(self, record, needle):
        errors = validate_record(record)
        self.assertTrue(
            any(needle in error for error in errors),
            f"expected {needle!r} in {errors}",
        )

    def test_cwe_key_is_rejected(self):
        broken = _copy(self.record)
        broken["state"]["findings"][1]["cwe"] = "CWE-89"
        self.assert_invalid(broken, "non-planner fields")

    def test_cvss_value_is_rejected(self):
        broken = _copy(self.record)
        broken["state"]["findings"][1]["mitre_tactic"] = "CVSS:3.1/AV:N"
        self.assert_invalid(broken, "forbidden value pattern")

    def test_raw_evidence_key_is_rejected(self):
        broken = _copy(self.record)
        broken["state"]["findings"][1]["evidence"] = {"body": "secret"}
        self.assert_invalid(broken, "non-planner fields")

    def test_extra_tool_field_is_rejected(self):
        broken = _copy(self.record)
        broken["available_tools"][0]["command"] = "curl"
        self.assert_invalid(broken, "non-planner fields")

    def test_unsupported_option_key_is_rejected(self):
        broken = _copy(self.record)
        broken["output"]["action"]["options"]["payload"] = "<script>"
        self.assert_invalid(broken, "unsupported option")

    def test_cross_origin_endpoint_is_rejected(self):
        broken = _copy(self.record)
        broken["output"]["action"]["options"]["endpoint"] = "http://evil.test/x"
        self.assert_invalid(broken, "outside the trusted origin")

    def test_unadvertised_option_is_rejected(self):
        broken = _copy(self.record)
        broken["output"]["action"]["options"] = {"endpoint": "/items"}
        broken["available_tools"] = [
            tool for tool in broken["available_tools"]
            if tool["tool_id"] != "validate-sql-injection"
        ]
        tool = {
            "tool_id": "validate-sql-injection",
            "validator_id": "generic-http-sqli",
            "name": "SQLi",
            "description": "SQLi validator",
            "category": "validator",
            "available": True,
            "vulnerability_types": ["sql_injection"],
            "vuln_types": ["sql_injection"],
            "requires_all": [],
            "requires_any": ["discovered_services"],
            "provides": ["application_compromise"],
            "automatic_allowed": True,
            "allowed_options": ["http_method"],
        }
        broken["available_tools"].append(tool)
        self.assert_invalid(broken, "does not advertise option")

    def test_missing_prerequisite_is_rejected(self):
        broken = _copy(self.record)
        broken["state"]["capabilities"] = ["unauthenticated"]
        self.assert_invalid(broken, "prerequisites are unmet")

    def test_duplicate_action_is_rejected(self):
        broken = _copy(self.record)
        broken["state"]["executed_action_ids"] = [
            broken["output"]["action"]["action_id"]
        ]
        self.assert_invalid(broken, "already in executed_action_ids")

    def test_step_limit_action_is_rejected(self):
        broken = _copy(self.records[-1])  # complete at the step limit
        broken["output"] = {
            "decision": "action",
            "action": {
                "action_id": "action-over-budget",
                "tool_id": "validate-sql-injection",
                "scan_id": broken["state"]["scan_id"],
                "asset_id": broken["state"]["asset_id"],
                "finding_id": "finding-sqli",
                "target": broken["state"]["target"],
                "reason": "too late",
                "expected_capabilities": ["discovered_services"],
                "options": {"endpoint": "/items"},
            },
        }
        self.assert_invalid(broken, "step budget")

    def test_unknown_tool_is_rejected(self):
        broken = _copy(self.record)
        broken["output"]["action"]["tool_id"] = "shell-exec"
        self.assert_invalid(broken, "not in available_tools")

    def test_changed_identifier_is_rejected(self):
        broken = _copy(self.record)
        broken["output"]["action"]["scan_id"] = "scan-other"
        self.assert_invalid(broken, "changed state.scan_id")

    def test_complete_must_have_null_action(self):
        broken = _copy(self.record)
        broken["output"] = {"decision": "complete", "action": {}}
        self.assert_invalid(broken, "action=null")

    def test_incompatible_technique_is_rejected(self):
        broken = _copy(self.record)
        broken["output"]["action"]["tool_id"] = "technique:T1082"
        self.assert_invalid(broken, "not compatible")

    def test_dataset_missing_a_technique_is_rejected(self):
        reduced = [
            record for record in self.records
            if record["supervision"]["technique_id"] != "T1068"
        ]
        errors = validate_dataset(reduced)
        self.assertTrue(any("does not cover techniques" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
