"""Honest evidence adjudication for the privilege-escalation / collection scripts.

These tests pin the fixes that stop the automation from reporting capabilities it
cannot prove:

* T1548 no longer treats the echoed section headers as elevation vectors.
* T1068 grants ``root_access`` only on definitive uid-0 evidence.
* T1213 grants ``credential_material`` only when credentials were recovered.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from app.automation import runner
from app.automation.base import AutomationContext, TechniqueStatus
from app.automation.delivery import (
    count_elevation_vectors,
    summarize_elevation_controls,
    verify_root_evidence,
)


ORIGIN = "http://127.0.0.1:8090"

HEADER_ONLY_OUTPUT = (
    "== SUID ==\n"
    "== SGID ==\n"
    "== SUDO ==\n"
    "== CAPS ==\n"
    "== WRITABLE ==\n"
)

REAL_VECTOR_OUTPUT = (
    "== SUID ==\n"
    "/usr/bin/passwd\n"
    "/usr/bin/sudo\n"
    "== SGID ==\n"
    "== SUDO ==\n"
    "== CAPS ==\n"
    "== WRITABLE ==\n"
)


class _FakeToolResult:
    def __init__(self, *, success=True, output="", raw=None, extra=None):
        self.success = success
        self.output = output
        self.raw = raw if raw is not None else output
        self.extra = extra or {}


def _ctx() -> AutomationContext:
    return AutomationContext(target=ORIGIN, authorized=True)


class ElevationParserTests(unittest.TestCase):
    def test_headers_alone_yield_no_vectors(self):
        sections = summarize_elevation_controls(HEADER_ONLY_OUTPUT)
        self.assertEqual(count_elevation_vectors(sections), 0)

    def test_real_paths_are_counted_per_section(self):
        sections = summarize_elevation_controls(REAL_VECTOR_OUTPUT)
        self.assertEqual(sections["suid"], ["/usr/bin/passwd", "/usr/bin/sudo"])
        self.assertEqual(count_elevation_vectors(sections), 2)

    def test_root_evidence_requires_uid_zero(self):
        self.assertTrue(verify_root_evidence("uid=0(root) gid=0(root)"))
        self.assertTrue(verify_root_evidence("euid=0(root)"))
        self.assertFalse(verify_root_evidence("uid=1000(user) gid=1000(user)"))
        self.assertFalse(verify_root_evidence("== SUDO ==\nsudo -l output"))
        self.assertFalse(verify_root_evidence(""))


class ElevationControlTechniqueTests(unittest.TestCase):
    def _run(self, stdout):
        with patch(
            "app.automation.scripts.t1548_elevation_control.deliver_rce_command",
            return_value=(0, stdout, ""),
        ):
            return runner.run_technique("T1548", _ctx())

    def test_header_only_output_is_inconclusive(self):
        result = self._run(HEADER_ONLY_OUTPUT)
        self.assertEqual(result.status, TechniqueStatus.INCONCLUSIVE)
        self.assertEqual(result.capabilities_gained, ())

    def test_real_vector_confirms_local_privilege_escalation(self):
        result = self._run(REAL_VECTOR_OUTPUT)
        self.assertEqual(result.status, TechniqueStatus.CONFIRMED)
        self.assertIn("local_privilege_escalation", result.capabilities_gained)
        self.assertEqual(result.evidence["vector_count"], 2)


class PrivescTechniqueTests(unittest.TestCase):
    def _run(self, output):
        with patch(
            "app.automation.scripts.t1068_privesc_exploitation.cached_script_path",
            return_value="/cache/linpeas.sh",
        ), patch(
            "app.automation.adapters.run_real_tool",
            return_value=_FakeToolResult(success=True, output=output),
        ):
            return runner.run_technique("T1068", _ctx())

    def test_enumeration_without_root_is_inconclusive(self):
        result = self._run("== SUID ==\n/usr/bin/passwd\nPotential vectors\n")
        self.assertEqual(result.status, TechniqueStatus.INCONCLUSIVE)
        self.assertNotIn("root_access", result.capabilities_gained)

    def test_uid_zero_evidence_confirms_root(self):
        result = self._run("uid=0(root) gid=0(root) groups=0(root)\n")
        self.assertEqual(result.status, TechniqueStatus.CONFIRMED)
        self.assertIn("root_access", result.capabilities_gained)


class RepositoryDataTechniqueTests(unittest.TestCase):
    def _run(self, databases, credentials=None):
        with patch(
            "app.automation.adapters.tool_available", return_value=True
        ), patch(
            "app.automation.adapters.run_real_tool",
            return_value=_FakeToolResult(
                success=True,
                output="sqlmap completed",
                extra={
                    "databases": databases,
                    "credentials": credentials or [],
                },
            ),
        ):
            return runner.run_technique("T1213", _ctx())

    def test_database_names_do_not_grant_credential_material(self):
        result = self._run(["appdb", "users"])
        self.assertEqual(result.status, TechniqueStatus.CONFIRMED)
        self.assertIn("repository_data_access", result.capabilities_gained)
        self.assertNotIn("credential_material", result.capabilities_gained)

    def test_recovered_credentials_grant_credential_material(self):
        result = self._run(["appdb"], credentials=[("admin", "hunter2")])
        self.assertIn("credential_material", result.capabilities_gained)


if __name__ == "__main__":
    unittest.main()
