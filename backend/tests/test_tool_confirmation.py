"""Tests for the real external-tool confirmation layer (sqlmap)."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.models.finding import Finding, ValidationStatus
from app.validation import tool_confirmation
from app.validation.dispatcher import dispatch


class FakeResponse:
    def __init__(self, text, status_code=200, elapsed_seconds=0.01):
        self.text = text
        self.status_code = status_code
        self.elapsed_seconds = elapsed_seconds


class FakeSession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def request(self, method, url, timeout=None, **kwargs):
        self.calls.append({
            "method": method,
            "url": url,
            "timeout": timeout,
            **kwargs,
        })
        return next(self.responses)


def make_finding(**overrides):
    values = {
        "finding_id": "f-sqli-tool",
        "scan_id": "scan-sqli-tool",
        "asset_id": "asset-sqli-tool",
        "target": "http://app.test",
        "host": "app.test",
        "port": 80,
        "protocol": "http",
        "endpoint": "/items",
        "http_method": "GET",
        "parameter_name": "id",
        "parameter_location": "query",
        "source": "synthetic_scanner",
        "template_id": "scanner-template-sqli-001",
        "validator_id": "generic-http-sqli",
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "evidence": {"scanner_match": True},
        "http_request_context": {"query": {"id": "1"}},
    }
    values.update(overrides)
    return Finding(**values)


SQLMAP_CONFIRMING_OUTPUT = (
    "        ___\n"
    "       __H__\n"
    "sqlmap identified the following injection point(s) with a total of 22 "
    "HTTP(s) requests:\n"
    "---\n"
    "Parameter: id (GET)\n"
    "    Type: boolean-based blind\n"
    "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
    "    Payload: id=1 AND 7918=7918\n"
    "---\n"
    "[INFO] the back-end DBMS is MySQL\n"
    "back-end DBMS: MySQL >= 5.0\n"
    "available databases [2]:\n"
    "[*] information_schema\n"
    "[*] dvwa\n"
    "[INFO] fetching current database\n"
    "current database: 'dvwa'\n"
)

SQLMAP_NEGATIVE_OUTPUT = (
    "[INFO] testing connection to the target URL\n"
    "[INFO] testing if the target URL content is stable\n"
    "[CRITICAL] all tested parameters do not appear to be injectable. "
    "Try to increase values for '--level'/'--risk' options if you wish to "
    "perform more tests.\n"
)

SQLMAP_ERROR_CRITICAL_OUTPUT = (
    "[CRITICAL] unable to connect to the target URL or proxy. "
    "connection refused (Connection refused)\n"
)


class FakeSqlmapHarness:
    """Installs a fake `sqlmap` executable on PATH for the lifespan used."""

    def __init__(self, stdout="", returncode=0, sleep_seconds=0):
        self.tmpdir = tempfile.mkdtemp(prefix="obsidian-sqlmap-test-")
        (Path(self.tmpdir) / "stdout.txt").write_text(stdout)
        script = (
            "#!/bin/sh\n"
            f"sleep {sleep_seconds}\n"
            f"printf '%s\\n' \"$@\" > '{self.tmpdir}/sqlmap-args.log'\n"
            f"cat '{self.tmpdir}/stdout.txt'\n"
            f"exit {returncode}\n"
        )
        path = Path(self.tmpdir) / "sqlmap"
        path.write_text(script)
        path.chmod(0o755)

    def path_env(self):
        return f"{self.tmpdir}:{os.environ.get('PATH', '')}"

    def read_args(self):
        log_path = Path(self.tmpdir) / "sqlmap-args.log"
        if not log_path.exists():
            return ""
        return log_path.read_text().replace("\n", " ").strip()


class TestSqlmapConfirmationParsing(unittest.TestCase):

    def test_parse_confirming_output(self):
        harness = FakeSqlmapHarness(stdout=SQLMAP_CONFIRMING_OUTPUT)
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            result = tool_confirmation.sqlmap_confirmation(make_finding())

        self.assertTrue(result.available)
        self.assertTrue(result.ran)
        self.assertTrue(result.usable)
        self.assertTrue(result.confirmed)
        self.assertFalse(result.not_vulnerable)
        self.assertIn("MySQL", result.dbms or "")
        self.assertIn("dvwa", result.databases)
        self.assertIn("-p id", result.command)

    def test_parse_negative_output(self):
        harness = FakeSqlmapHarness(stdout=SQLMAP_NEGATIVE_OUTPUT)
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            result = tool_confirmation.sqlmap_confirmation(make_finding())

        self.assertTrue(result.ran)
        self.assertFalse(result.confirmed)
        self.assertTrue(result.not_vulnerable)

    def test_absent_tool_is_unavailable(self):
        with mock.patch.object(
            tool_confirmation, "binary_available", return_value=False
        ):
            result = tool_confirmation.sqlmap_confirmation(make_finding())

        self.assertFalse(result.available)
        self.assertFalse(result.ran)
        self.assertFalse(result.confirmed)
        self.assertFalse(result.usable)

    def test_timeout_reports_unusable(self):
        harness = FakeSqlmapHarness(
            stdout=SQLMAP_CONFIRMING_OUTPUT, sleep_seconds=5
        )
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            result = tool_confirmation.sqlmap_confirmation(
                make_finding(), timeout=0.5
            )

        self.assertTrue(result.ran)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.usable)

    def test_header_location_unsupported(self):
        harness = FakeSqlmapHarness()
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            result = tool_confirmation.sqlmap_confirmation(
                make_finding(parameter_location="header"),
            )

        self.assertTrue(result.available)
        self.assertFalse(result.ran)
        self.assertEqual(
            result.error, "header_parameter_location_unsupported_by_sqlmap"
        )


class TestSqlmapCommandShape(unittest.TestCase):

    def test_get_query_command(self):
        harness = FakeSqlmapHarness()
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            tool_confirmation.sqlmap_confirmation(make_finding())
        args = harness.read_args()

        self.assertIn("-u http://app.test/items?id=1", args)
        self.assertIn("-p id", args)
        self.assertIn("--batch", args)
        self.assertIn("--level 1 --risk 1", args)
        self.assertIn("--dbs", args)
        self.assertIn("--output-dir /tmp/obsidian_sqlmap/f-sqli-tool", args)

    def test_post_form_command(self):
        harness = FakeSqlmapHarness()
        finding = make_finding(
            http_method="POST",
            parameter_location="form",
            http_request_context={"form": {"id": "1", "Submit": "Go"}},
        )
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            tool_confirmation.sqlmap_confirmation(finding)
        args = harness.read_args()

        self.assertIn("--method POST", args)
        self.assertIn("--data id=1&Submit=Go", args)

    def test_json_body_command(self):
        harness = FakeSqlmapHarness()
        finding = make_finding(
            http_method="POST",
            parameter_location="json",
            http_request_context={"json": {"id": "1"}},
        )
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            tool_confirmation.sqlmap_confirmation(finding)
        args = harness.read_args()

        self.assertIn("--method POST", args)
        self.assertIn('--data {"id": "1"}', args)

    def test_cookie_command(self):
        harness = FakeSqlmapHarness()
        finding = make_finding(
            http_method="GET",
            parameter_location="cookie",
            http_request_context={"cookie": {"session": "abc123"}},
        )
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            tool_confirmation.sqlmap_confirmation(finding)
        args = harness.read_args()

        self.assertIn("--cookie session=abc123", args)


def clear_differential_responses():
    baseline = "<html><body>account available " + ("A" * 500) + "</body></html>"
    false_result = "<html><body>request denied " + ("Z" * 500) + "</body></html>"
    return [
        FakeResponse(baseline),
        *[
            response
            for _ in range(3)
            for response in (
                FakeResponse(baseline),
                FakeResponse(false_result),
            )
        ],
        FakeResponse("normal application error"),
        FakeResponse("normal application error"),
    ]


def same_responses(count=17):
    same = "<html><body>same application response</body></html>"
    return [FakeResponse(same) for _ in range(count)]


class TestSqlmapIntegrationInSqlValidator(unittest.TestCase):

    def test_sqlmap_confirmation_beats_ambiguous_heuristics(self):
        harness = FakeSqlmapHarness(stdout=SQLMAP_CONFIRMING_OUTPUT)
        session = FakeSession(same_responses())
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            result = dispatch(make_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(
            result.evidence["reason"], "real_tool_sqlmap_confirmation"
        )
        self.assertIn("sqlmap", result.method)
        self.assertTrue(result.evidence["real_tool"]["confirmed"])
        self.assertGreaterEqual(result.confidence, 0.95)
        self.assertEqual(len(session.calls), 17)

    def test_conflict_when_sqlmap_negative_but_heuristics_confirm(self):
        harness = FakeSqlmapHarness(stdout=SQLMAP_NEGATIVE_OUTPUT)
        session = FakeSession(clear_differential_responses())
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            result = dispatch(make_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(
            result.evidence["reason"], "real_tool_conflict_requires_human_review"
        )
        self.assertTrue(result.evidence["real_tool"]["not_vulnerable"])

    def test_reject_when_sqlmap_and_heuristics_agree_negative(self):
        harness = FakeSqlmapHarness(stdout=SQLMAP_NEGATIVE_OUTPUT)
        session = FakeSession(same_responses())
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            result = dispatch(make_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["reason"], "heuristics_and_real_tool_negative"
        )

    def test_heuristic_verdict_survives_sqlmap_timeout(self):
        harness = FakeSqlmapHarness(
            stdout=SQLMAP_CONFIRMING_OUTPUT, sleep_seconds=5
        )
        session = FakeSession(clear_differential_responses())
        with mock.patch.object(
            tool_confirmation,
            "_DEFAULT_TOOL_TIMEOUT_SECONDS",
            0.5,
        ):
            with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
                result = dispatch(make_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(
            result.evidence["reason"],
            "one_or_more_detection_methods_confirmed",
        )
        self.assertTrue(result.evidence["real_tool"]["timed_out"])

    def test_heuristic_verdict_when_sqlmap_unavailable(self):
        session = FakeSession(clear_differential_responses())
        with mock.patch.object(
            tool_confirmation, "binary_available", return_value=False
        ):
            result = dispatch(make_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(
            result.evidence["reason"],
            "one_or_more_detection_methods_confirmed",
        )
        self.assertFalse(result.evidence["real_tool"]["available"])

    def test_confirmed_finding_keeps_session_call_count(self):
        harness = FakeSqlmapHarness(stdout=SQLMAP_CONFIRMING_OUTPUT)
        session = FakeSession(same_responses())
        with mock.patch.dict(os.environ, {"PATH": harness.path_env()}):
            result = dispatch(make_finding(), session=session)

        self.assertEqual(len(session.calls), 17)
        self.assertTrue(all(call["method"] == "GET" for call in session.calls))
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)


if __name__ == "__main__":
    unittest.main()