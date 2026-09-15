"""In-memory scan job store for the async console flow.

A ScanJob holds an ordered journal of live steps (the tick list the UI polls)
plus the final report once the background thread finishes. Jobs are ephemeral
and purely in-memory — this is a dev-console feature, not durable state.
"""
from __future__ import annotations

import threading
import time
import uuid

DONE, FAILED, RUNNING, PENDING, SKIPPED, CANCELLED = (
    "done", "failed", "running", "pending", "skipped", "cancelled",
)


class ScanJob:
    def __init__(self, target: str, name: str | None = None):
        self.id = uuid.uuid4().hex[:12]
        self.target = target
        self.name = name
        self.status = "running"
        self.error: str | None = None
        self.result: dict | None = None
        self.handoff: dict | None = None
        self.steps: list[dict] = []
        self.steps_by_id: dict[str, dict] = {}
        self.findings: list[dict] = []
        self.cancel_event = threading.Event()
        self.created_at = time.time()
        self.finished_at: float | None = None
        self._lock = threading.Lock()
        self._seq_counter = 0

    def preseed(self, step_id: str, label: str, phase: str = "") -> None:
        """Register a step that may or may not run (starts as 'pending')."""
        with self._lock:
            if step_id in self.steps_by_id:
                return
            step = {
                "id": step_id,
                "label": label,
                "phase": phase,
                "status": PENDING,
                "started_at": None,
                "duration_ms": None,
                "findings": 0,
                "error": None,
            }
            self.steps.append(step)
            self.steps_by_id[step_id] = step

    def start(self, step_id: str, label: str, phase: str = "") -> None:
        with self._lock:
            step = self.steps_by_id.get(step_id)
            if step is None:
                step = {
                    "id": step_id,
                    "label": label,
                    "phase": phase,
                    "status": PENDING,
                    "started_at": None,
                    "duration_ms": None,
                    "findings": 0,
                    "error": None,
                }
                self.steps.append(step)
                self.steps_by_id[step_id] = step
            step["status"] = RUNNING
            step["started_at"] = time.time()
            step["duration_ms"] = None
            step["error"] = None
            self._assign_seq(step)

    def finish(self, step_id: str, status: str, findings: int = 0,
               error: str | None = None) -> None:
        with self._lock:
            step = self.steps_by_id.get(step_id)
            if not step:
                return
            step["status"] = status if status in (DONE, FAILED, SKIPPED, CANCELLED) else DONE
            step["findings"] = findings
            step["error"] = error
            if step.get("started_at"):
                step["duration_ms"] = int((time.time() - step["started_at"]) * 1000)
            self._assign_seq(step)

    def _assign_seq(self, step: dict) -> None:
        """Stamp the run-sequence number once (first time the step goes live).
        The console sorts the journal by this so tasks always list 1-after-1
        in actual run order rather than manifest/alphabetical order."""
        if step.get("seq") is None:
            self._seq_counter += 1
            step["seq"] = self._seq_counter

    def add_findings(self, rows: list[dict]) -> None:
        """Stream findings into the job as the pipeline discovers them."""
        if not rows:
            return
        with self._lock:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                self.findings.append(row)

    def set_handoff(self, report: dict | None) -> None:
        """Journal the recon→exploit automatic handoff state for the UI."""
        with self._lock:
            self.handoff = report

    def set_result(self, result: dict | None, error: str | None = None) -> None:
        with self._lock:
            self.result = result
            self.error = error
            self.status = FAILED if error else DONE
            self.finished_at = time.time()
            self._finalize_leftover_steps(pending_reason="not selected",
                                          running_mark=FAILED,
                                          running_error="interrupted")

    def request_cancel(self) -> bool:
        """Signal the running job to halt as soon as it can. Returns True when
        the job was still running (cancel accepted)."""
        with self._lock:
            already_terminal = self.status not in (RUNNING,)
            if already_terminal:
                return False
            self.cancel_event.set()
            return True

    def set_cancelled(self) -> None:
        """Terminate the job as 'cancelled' (called by the job worker thread)."""
        with self._lock:
            self.status = CANCELLED
            self.error = None
            self.result = None
            self.finished_at = time.time()
            self.cancel_event.set()
            self._finalize_leftover_steps(pending_reason="not selected",
                                          running_mark=CANCELLED,
                                          running_error="cancelled by user")

    def _finalize_leftover_steps(self, pending_reason: str,
                                 running_mark: str, running_error: str) -> None:
        """Under the lock: mark unfinished completed steps as skipped, and any
        step that was mid-flight as interrupted/cancelled."""
        for step in self.steps:
            if step["status"] == PENDING:
                step["status"] = SKIPPED
                step["reason"] = pending_reason
            elif step["status"] == RUNNING:
                step["status"] = running_mark
                step["error"] = running_error

    def snapshot(self) -> dict:
        with self._lock:
            total = len(self.steps)
            # "executed" means the step actually ran and reached a verdict
            # (finished or failed mid-run). Pending and skipped steps must NOT
            # count as completed — otherwise the progress bar fills up with
            # work that never happened.
            executed = sum(1 for s in self.steps
                           if s["status"] in (DONE, FAILED))
            pending = sum(1 for s in self.steps if s["status"] == PENDING)
            skipped = sum(1 for s in self.steps if s["status"] == SKIPPED)
            return {
                "id": self.id,
                "target": self.target,
                "name": self.name,
                "status": self.status,
                "error": self.error,
                "steps": [dict(s) for s in self.steps],
                "done": executed,
                "executed": executed,
                "pending": pending,
                "skipped": skipped,
                "total": total,
                "findings": list(self.findings),
                "findings_count": len(self.findings),
                "handoff": self.handoff,
                "elapsed_ms": int((time.time() - self.created_at) * 1000),
                "finished_at": self.finished_at,
            }


_JOBS: dict[str, ScanJob] = {}
_JOBS_LOCK = threading.Lock()


def create_job(target: str, name: str | None = None) -> ScanJob:
    job = ScanJob(target, name=name)
    with _JOBS_LOCK:
        _JOBS[job.id] = job
    return job


def get_job(job_id: str) -> ScanJob | None:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def prune_jobs(max_age: float = 7200) -> None:
    """Drop finished jobs older than max_age seconds (best-effort cleanup)."""
    now = time.time()
    with _JOBS_LOCK:
        for jid in [j for j, jb in _JOBS.items()
                    if jb.finished_at and now - jb.finished_at > max_age]:
            del _JOBS[jid]


def make_progress_callback(job: ScanJob):
    """Return a pipeline progress callback that journals into the job."""
    def on_event(event: dict) -> None:
        kind = event.get("kind")
        if kind == "step_start":
            job.start(event["id"], event.get("label", event["id"]),
                      event.get("phase", ""))
        elif kind == "step_finish":
            job.finish(event["id"], event.get("status", DONE),
                       event.get("findings", 0), event.get("error"))
        elif kind == "findings":
            job.add_findings(event.get("findings") or [])
    return on_event


_SCANNER_MANIFEST = [
    # Order matches the pipeline's actual run order (subdomains first so the
    # chained deep-scan benefits, then the web/port probes, then nuclei).
    ("subdomains", "subdomain enumeration"),
    ("http_probe", "http probe"),
    ("nmap", "nmap"),
    ("nuclei", "nuclei"),
    ("nmap_tls", "nmap tls"),
    ("content", "content discovery"),
    ("waf_detect", "waf detect"),
]

# Skill-category → manifest position (pre-scanner skills). The seed list (and
# therefore the live journal) is ordered exactly like the runner executes:
# passive recon first, then network protocol probes, then web — the scanners
# are seeded right after these, then the post-scanner skill categories
# (exploit → post → report), then the finalize step.
_SKILL_PHASE_ORDER = {"recon": 0, "network": 1, "web": 2}

# Skill-category → manifest position for the skills that run AFTER the
# scanners (in the post-scanner skill pass).
_POST_SCANNER_PHASE_ORDER = {"exploit": 0, "post": 1, "report": 2}


def seed_manifest(job: ScanJob, include: list[str] | None = None,
                  skip: list[str] | None = None,
                  allow_exploit: bool = False,
                  profile=None) -> None:
    """Pre-register every step the pipeline may run so the whole tick list is
    visible up front as 'pending', ticking off in real time as it runs.

    `include`/`skip` mirror the scan request so excluded tools are seeded as
    skipped rather than left dangling. When a `profile` (ScanProfile) is
    supplied its skill skip/include lists mark excluded skills as skipped too,
    and exploit skills are only seeded when the profile (or request) enables
    the exploit phase.

    Steps are seeded in the SAME order the pipeline executes them (recon →
    recon skills → network → web → scanners → web reprobe → exploit → post →
    report → chain → finalize) so the journal reads top-to-bottom in run order
    instead of alphabetical manifest order.
    """
    include = set(include or [])
    skip = set(skip or [])

    skill_skip = set()
    skill_include = None
    if profile is not None:
        skill_skip = set(profile.skip_skills)
        skill_include = set(profile.include_only_skills) or None
        skip.update(profile.skip_scanners)

    def wanted(name: str) -> bool:
        if include and name not in include:
            return False
        if name in skip:
            return False
        return True

    job.preseed("recon", "recon (passive OSINT + DNS)", phase="recon")

    from skills import load_all_skills, all_skills
    load_all_skills()

    def seed_skill(sk) -> None:
        """Preseed one skill step, honouring the profile include/skip lists."""
        cat = sk.category.value
        job.preseed(f"skill:{sk.name}", sk.display_name or sk.name, phase=cat)
        mark = job.steps_by_id.get(f"skill:{sk.name}")
        if mark is None:
            return
        if skill_include and sk.name not in skill_include:
            mark["status"] = SKIPPED
            mark["reason"] = "excluded by profile"
        elif sk.name in skill_skip:
            mark["status"] = SKIPPED
            mark["reason"] = "excluded by profile"

    # Pre-scanner skills (recon → network → web) seed first because the
    # pipeline runs them before the scanners.
    pre_skills = sorted(
        (s for s in all_skills() if s.category.value in ("recon", "network", "web")),
        key=lambda s: (_SKILL_PHASE_ORDER.get(s.category.value, 9), s.name),
    )
    for sk in pre_skills:
        seed_skill(sk)

    for name, label in _SCANNER_MANIFEST:
        if not wanted(name):
            job.preseed(f"scanner:{name}", f"{label} (excluded)", phase="scanner")
            mark = job.steps_by_id.get(f"scanner:{name}")
            if mark:
                mark["status"] = SKIPPED
                mark["reason"] = "excluded by request"
            continue
        job.preseed(f"scanner:{name}", label, phase="scanner")

    # Post-scanner skills (exploit → post → report) seed after the scanners
    # because the pipeline runs them once the scanners are done. The exploit
    # phase only seeds when the profile/request enables it.
    post_skills = sorted(
        (s for s in all_skills() if s.category.value in ("exploit", "post", "report")),
        key=lambda s: (_POST_SCANNER_PHASE_ORDER.get(s.category.value, 9), s.name),
    )
    for sk in post_skills:
        if sk.category.value == "exploit" and not allow_exploit:
            continue
        seed_skill(sk)

    job.preseed("subdomain_chain", "subdomain chained deep-scan", phase="chain")
    job.preseed("origin_hunt", "origin hunt (behind WAF)", phase="chain")
    job.preseed("finalize", "triage · validation · normalization", phase="chain")


__all__ = [
    "ScanJob", "create_job", "get_job", "prune_jobs",
    "make_progress_callback", "seed_manifest",
]