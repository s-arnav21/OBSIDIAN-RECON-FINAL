"""Metasploit RPC adapter is gated on the optional pymetasploit3 dependency."""
from __future__ import annotations

import unittest
from unittest import mock

from app.automation import metasploit_rpc


class AvailabilityTests(unittest.TestCase):
    def test_availability_is_reported_without_raising(self):
        status = metasploit_rpc.availability()
        self.assertIn("available", status)
        self.assertEqual(status["package"], "pymetasploit3")
        self.assertEqual(status["daemon"], "msfrpcd")

    def test_connect_without_dependency_raises_bounded_error(self):
        with mock.patch.object(metasploit_rpc, "MsfRpcClient", None):
            self.assertFalse(metasploit_rpc.available())
            with self.assertRaises(metasploit_rpc.MetasploitUnavailable):
                metasploit_rpc.connect(password="x")

    def test_sessions_empty_when_unavailable(self):
        class _Client:
            class sessions:  # noqa: N801 - mimic pymetasploit3 shape
                list = {}

        self.assertEqual(metasploit_rpc.sessions(_Client()), [])

    def test_run_module_reports_unavailable_without_raising(self):
        with mock.patch.object(metasploit_rpc, "MsfRpcClient", None):
            outcome = metasploit_rpc.run_module(
                object(), module_type="exploit", module_name="x/y"
            )
        self.assertFalse(outcome["executed"])
        self.assertTrue(outcome["error"])

    def test_run_module_fail_soft_on_client_error(self):
        class _Client:
            class modules:  # noqa: N801
                @staticmethod
                def use(_type, _name):
                    raise RuntimeError("rpc down")

            class sessions:  # noqa: N801
                list = {}

        with mock.patch.object(metasploit_rpc, "MsfRpcClient", object):
            outcome = metasploit_rpc.run_module(
                _Client(), module_type="exploit", module_name="x/y"
            )
        self.assertFalse(outcome["executed"])
        self.assertIn("RuntimeError", outcome["error"])


class MetasploitToolRpcWiringTests(unittest.TestCase):
    """The metasploit-* tools prefer msfrpcd when it is configured."""

    def test_eternalblue_prefers_rpc_and_reports_session(self):
        from app.agent import tools as tools_mod

        with mock.patch.object(tools_mod, "_msf_rpc_client", return_value=object()), \
             mock.patch.object(
                 metasploit_rpc,
                 "run_module",
                 return_value={"executed": True, "session_created": "3", "error": None},
             ):
            result = tools_mod._exec_metasploit_eternalblue({"target": "10.0.0.5"})
        self.assertTrue(result.success)
        self.assertTrue(result.shell_obtained)
        self.assertEqual(result.shell_info["session_id"], "3")
        self.assertEqual(result.shell_info["transport"], "rpc")

    def test_eternalblue_falls_back_to_msfconsole_requirement(self):
        from app.agent import tools as tools_mod

        with mock.patch.object(tools_mod, "_msf_rpc_client", return_value=None), \
             mock.patch.object(tools_mod, "_binary_available", return_value=False):
            result = tools_mod._exec_metasploit_eternalblue({"target": "10.0.0.5"})
        self.assertFalse(result.success)
        self.assertIn("msfconsole", result.error)

    def test_web_rce_prefers_rpc(self):
        from app.agent import tools as tools_mod

        with mock.patch.object(tools_mod, "_msf_rpc_client", return_value=object()), \
             mock.patch.object(
                 metasploit_rpc,
                 "run_module",
                 return_value={"executed": True, "session_created": None, "error": None},
             ):
            result = tools_mod._exec_metasploit_web_rce(
                {"target": "10.0.0.5", "module": "exploit/linux/http/x"}
            )
        self.assertTrue(result.success)
        self.assertEqual(result.shell_info["transport"], "rpc")


class MsfAvailabilityWiringTests(unittest.TestCase):
    """Metasploit tools become available over RPC without msfconsole on PATH."""

    def test_rpc_disabled_by_default(self):
        from app.agent import tools as tools_mod

        with mock.patch("app.core.config.settings.MSF_RPC_ENABLED", False):
            self.assertFalse(tools_mod._msf_rpc_configured())

    def test_tool_is_available_when_rpc_configured(self):
        from app.agent import tools as tools_mod

        tool = tools_mod.TOOL_REGISTRY["metasploit-eternalblue"]
        with mock.patch.object(tools_mod, "_binary_available", return_value=False), \
             mock.patch.object(tools_mod, "_msf_rpc_configured", return_value=True):
            self.assertTrue(tools_mod._tool_is_available(tool))
            catalog = {t["tool_id"]: t for t in tools_mod.get_tool_catalog()}
            self.assertTrue(catalog["metasploit-eternalblue"]["available"])

    def test_tool_unavailable_without_binary_or_rpc(self):
        from app.agent import tools as tools_mod

        tool = tools_mod.TOOL_REGISTRY["metasploit-eternalblue"]
        with mock.patch.object(tools_mod, "_binary_available", return_value=False), \
             mock.patch.object(tools_mod, "_msf_rpc_configured", return_value=False):
            self.assertFalse(tools_mod._tool_is_available(tool))


if __name__ == "__main__":
    unittest.main()
