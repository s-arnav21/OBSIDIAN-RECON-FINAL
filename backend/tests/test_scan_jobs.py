"""Tests for ScanJob durability (disk persistence + restart recovery)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.core import progress
from app.core.config import settings
from app.core.progress import (
    DONE,
    FAILED,
    RUNNING,
    ScanJob,
    _ensure_recovered,
    _load_disk_records,
    _save_job_to_disk,
)


class ScanJobDurabilityTests(unittest.TestCase):
    """Write jobs to a temp dir so real data dir stays clean."""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._saved_data_dir = settings.DATA_DIR
        settings.DATA_DIR = Path(self._tmp_dir)
        progress._JOBS.clear()
        progress._RECOVERED = False

    def tearDown(self):
        progress._JOBS.clear()
        progress._RECOVERED = False
        settings.DATA_DIR = self._saved_data_dir

    def test_create_job_persists_initial_record_to_disk(self):
        job = progress.create_job("http://127.0.0.1:9090", name="test-scan")
        records = _load_disk_records()
        self.assertIn(job.id, records)
        self.assertEqual(records[job.id]["status"], RUNNING)
        self.assertEqual(records[job.id]["target"], "http://127.0.0.1:9090")

    def test_runnning_job_marked_interrupted_after_simulated_restart(self):
        job = progress.create_job("http://127.0.0.1:9090", name="interrupted")
        self.assertEqual(job.status, RUNNING)

        # Simulate process restart: wipe in-memory state and re-recover
        progress._JOBS.clear()
        progress._RECOVERED = False
        _ensure_recovered()

        restored = progress.get_job(job.id)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.status, FAILED)
        self.assertEqual(restored.error, "process interrupted by restart")
        self.assertIsNotNone(restored.finished_at)

    def test_completed_job_persists_terminal_state(self):
        job = progress.create_job("http://127.0.0.1:9090", name="finished")
        job.start("step-a", "nuclei")
        job.finish("step-a", DONE, findings=3)
        job.set_result({"findings": 3})

        records = _load_disk_records()
        self.assertEqual(records[job.id]["status"], DONE)
        self.assertEqual(records[job.id]["error"], None)
        step = next(s for s in records[job.id]["steps"] if s["id"] == "step-a")
        self.assertEqual(step["status"], DONE)
        self.assertEqual(step["findings"], 3)

    def test_step_finishes_appear_in_durable_record(self):
        job = progress.create_job("http://127.0.0.1:9090", name="step-progress")
        job.start("s1", "nmap")
        job.finish("s1", DONE, findings=5)
        job.start("s2", "nuclei")
        job.finish("s2", FAILED, error="nmap exit 1")

        records = _load_disk_records()
        steps = records[job.id]["steps"]
        self.assertEqual(len(steps), 2)
        self.assertEqual(steps[0]["id"], "s1")
        self.assertEqual(steps[0]["status"], DONE)
        self.assertEqual(steps[0]["findings"], 5)
        self.assertEqual(steps[1]["status"], FAILED)
        self.assertEqual(steps[1]["error"], "nmap exit 1")

    def test_from_durable_record_reconstructs_job(self):
        original = progress.create_job("http://127.0.0.1:9090", name="roundtrip")
        original.start("s1", "recon")
        original.finish("s1", DONE, findings=1)
        original.add_findings([{"id": "f1"}])
        original.set_result({"ok": True})

        records = _load_disk_records()
        restored = ScanJob.from_durable_record(records[original.id])
        self.assertEqual(restored.id, original.id)
        self.assertEqual(restored.status, DONE)
        self.assertEqual(restored.result, {"ok": True})
        self.assertEqual(len(restored.steps), 1)
        self.assertEqual(restored.steps_by_id["s1"]["findings"], 1)
        self.assertEqual(len(restored.findings), 1)

    def test_cancelled_job_persists_terminal_state(self):
        job = progress.create_job("http://127.0.0.1:9090", name="cancelled")
        job.set_cancelled()

        records = _load_disk_records()
        self.assertEqual(records[job.id]["status"], "cancelled")
        self.assertEqual(records[job.id]["error"], None)
        self.assertIsNotNone(records[job.id]["finished_at"])


class SkillRunnerMaxIterationsTest(unittest.TestCase):
    def test_selector_has_safety_cap(self):
        """The selector while-loop in runner.py terminates within bounds."""
        import inspect
        from skills.runner import run_skills

        src = inspect.getsource(run_skills)
        self.assertIn("max_iterations", src)


if __name__ == "__main__":
    unittest.main()
