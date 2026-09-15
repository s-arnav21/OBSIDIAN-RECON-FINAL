"""Skill Runner — executes the selected skills against a SkillContext,
merging each skill's context_updates back into the shared context and
collecting all findings and evidence.
"""
import logging
import time

from .base import SkillContext, SkillResult
from .selector import select_skills
from . import load_all_skills
from pipeline._errors import ScanCancelled

logger = logging.getLogger(__name__)


def run_skills(ctx: SkillContext,
               phase: str = "all",
               on_step=None,
               cancel_event=None,
               profile=None) -> list[SkillResult]:
    """Main entry point. Call this after base recon.

    Args:
        ctx: shared SkillContext, mutated in place as skills run.
        phase: "all" or one of the SkillCategory values to restrict to.
        on_step: optional per-skill progress callback. Receives events:
            {"kind": "step_start", "id": "skill:<name>", "label": display_name, "phase": ...}
            {"kind": "step_finish", "id": "skill:<name>", "status": "done"|"failed",
             "findings": n, "error": str|None}
        cancel_event: optional threading.Event; when set, the runner stops and
            raises ScanCancelled (so a cancelled scan is not reported as failed).
        profile: optional ScanProfile whose include_only_skills / skip_skills
            are applied by the selector during selection.

    Returns:
        List of SkillResult — one per skill run (or failed attempt).

    Raises:
        ScanCancelled: when cancel_event is set. A skill that raises
            ScanCancelled while running is NOT converted into a failed result —
            the cancellation propagates up to the scan job.
    """
    load_all_skills()
    results = []

    # Selection is re-evaluated whenever the accumulated context changes, so a
    # skill gated on a condition another skill produces mid-phase (e.g. a
    # discovered login form enabling default-creds) still gets selected and run.
    # Each iteration consumes at least one new skill (seen_names grows), but a
    # hard cap protects against a pathological selector that keeps yielding new
    # skills forever.
    seen_names: set[str] = set()
    max_iterations = 100
    while max_iterations > 0:
        max_iterations -= 1
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled()

        batch = [s for s in select_skills(ctx, phase, profile=profile)
                 if s.name not in seen_names]
        if not batch:
            break
        seen_names.update(s.name for s in batch)

        logger.info(f"Skill selector chose {len(batch)} skill(s) "
                    f"for {ctx.host}")

        for skill in batch:
            if cancel_event is not None and cancel_event.is_set():
                raise ScanCancelled()
            ctx.cancel_event = cancel_event
            logger.info(f"Running skill: {skill.display_name}")
            if on_step is not None:
                on_step({"kind": "step_start", "id": f"skill:{skill.name}",
                         "label": skill.display_name or skill.name,
                         "phase": phase})
            t0 = time.time()
            try:
                result = skill.run(ctx)
                result.duration_ms = int((time.time() - t0) * 1000)

                # Merge context updates back into shared context
                for key, value in result.context_updates.items():
                    if hasattr(ctx, key):
                        existing = getattr(ctx, key)
                        if isinstance(existing, list):
                            existing.extend(value)
                        elif isinstance(existing, dict):
                            existing.update(value)
                        else:
                            setattr(ctx, key, value)

                # Accumulate skill findings onto the shared context so the
                # selector can derive finding-type conditions (login_form_found,
                # sql_error_found, high_finding_exists) for the next batch and
                # post-phase skills (correlate) can consume them.
                ctx.raw_findings.extend(result.findings)

                results.append(result)
                logger.info(f"  -> {len(result.findings)} findings "
                            f"({result.duration_ms}ms)")

            except ScanCancelled:
                logger.info(f"Skill {skill.name} cancelled by operator")
                raise
            except Exception as e:  # noqa: BLE001 — a failing skill never stops the pipeline
                logger.error(f"Skill {skill.name} failed: {e}")
                results.append(SkillResult(
                    skill_name=skill.name,
                    success=False,
                    findings=[],
                    error=str(e)
                ))

            if on_step is not None:
                last = results[-1]
                on_step({"kind": "step_finish", "id": f"skill:{skill.name}",
                         "status": "done" if last.success else "failed",
                         "findings": len(last.findings), "error": last.error})

    return results