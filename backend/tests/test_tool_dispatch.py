"""Bounded tool-call dispatch (VulnClaw tool_call_manager pattern)."""
from __future__ import annotations

import unittest

from app.automation.dispatch import ToolCall, ToolDispatcher


class _Result:
    def __init__(self, success=True, output="out", extra=None, error=None):
        self.success = success
        self.output = output
        self.extra = extra or {}
        self.error = error


class DispatchTests(unittest.TestCase):
    def test_success_is_recorded(self):
        dispatcher = ToolDispatcher(runner=lambda tool, opts: _Result(extra={"n": 1}))
        outcome = dispatcher.dispatch(ToolCall("nmap-scan", {"target": "h"}))
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.extra["n"], 1)
        self.assertEqual(dispatcher.outcomes[-1].tool_id, "nmap-scan")

    def test_runner_exception_becomes_recorded_failure(self):
        def _boom(tool, opts):
            raise RuntimeError("kaboom")

        dispatcher = ToolDispatcher(runner=_boom)
        outcome = dispatcher.dispatch(ToolCall("nikto-scan", {}))
        self.assertFalse(outcome.success)
        self.assertIn("RuntimeError", outcome.error)
        self.assertEqual(len(dispatcher.failures), 1)

    def test_failed_tool_result_is_recorded(self):
        dispatcher = ToolDispatcher(runner=lambda t, o: _Result(success=False, error="nope"))
        outcome = dispatcher.dispatch(ToolCall("gobuster-dir", {}))
        self.assertFalse(outcome.success)
        self.assertEqual(outcome.error, "nope")

    def test_parallel_dispatch_preserves_order_and_records_all(self):
        calls = [ToolCall(f"tool-{i}", {"i": i}) for i in range(5)]
        dispatcher = ToolDispatcher(runner=lambda tool, opts: _Result(output=f"{tool}:{opts['i']}"))
        outcomes = dispatcher.dispatch_many(calls, parallel=True, max_workers=3)
        self.assertEqual([o.tool_id for o in outcomes], [f"tool-{i}" for i in range(5)])
        self.assertEqual(len(dispatcher.outcomes), 5)

    def test_recorder_is_called_and_cannot_break_dispatch(self):
        seen = []

        def _recorder(outcome):
            seen.append(outcome.tool_id)
            raise ValueError("recorder is noisy")

        dispatcher = ToolDispatcher(
            runner=lambda t, o: _Result(), recorder=_recorder
        )
        outcome = dispatcher.dispatch(ToolCall("nuclei-scan", {}))
        self.assertTrue(outcome.success)
        self.assertEqual(seen, ["nuclei-scan"])

    def test_none_result_is_failure(self):
        dispatcher = ToolDispatcher(runner=lambda t, o: None)
        outcome = dispatcher.dispatch(ToolCall("t", {}))
        self.assertFalse(outcome.success)
        self.assertIn("no result", outcome.error)


if __name__ == "__main__":
    unittest.main()
