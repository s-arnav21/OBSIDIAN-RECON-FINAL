"""Bounded tool-call dispatch with result/failure recording.

Adapted from VulnClaw's ``tool_call_manager.py``: a single place that dispatches
tool calls, records every outcome (including failures), and can run independent
calls in parallel — without the caller needing to know which adapter backs a
tool.

It sits *above* :mod:`app.automation.adapters` (which delegates to the agent tool
registry) so technique scripts and the technique chain share one dispatch path.
Every call is fail-soft: an exception becomes a recorded failure, never a
propagated error, so one broken tool cannot abort a chain.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from app.automation import adapters


@dataclass
class ToolCall:
    """A request to run one registered tool."""

    tool_id: str
    options: Dict[str, Any] = field(default_factory=dict)
    label: Optional[str] = None

    def describe(self) -> Dict[str, Any]:
        return {"tool_id": self.tool_id, "label": self.label, "options": dict(self.options)}


@dataclass
class ToolCallOutcome:
    """Structured result of one dispatched call (success *or* failure)."""

    tool_id: str
    label: Optional[str]
    success: bool
    duration_ms: int
    output: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def describe(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "label": self.label,
            "success": self.success,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


def _coerce_outcome(call: ToolCall, result: Any, duration_ms: int) -> ToolCallOutcome:
    if result is None:
        return ToolCallOutcome(
            tool_id=call.tool_id,
            label=call.label,
            success=False,
            duration_ms=duration_ms,
            error="tool returned no result",
        )
    output = getattr(result, "output", "") or ""
    extra = getattr(result, "extra", None) or {}
    success = bool(getattr(result, "success", False))
    error = getattr(result, "error", None)
    return ToolCallOutcome(
        tool_id=call.tool_id,
        label=call.label,
        success=success,
        duration_ms=duration_ms,
        output=str(output)[:200_000],
        extra=dict(extra) if isinstance(extra, dict) else {},
        error=str(error)[:512] if error else None,
    )


class ToolDispatcher:
    """Dispatch tool calls and keep a bounded ledger of their outcomes."""

    def __init__(
        self,
        *,
        runner: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
        recorder: Optional[Callable[[ToolCallOutcome], None]] = None,
        max_workers: int = 4,
        max_outcomes: int = 200,
    ) -> None:
        self._runner = runner or adapters.run_real_tool
        self._recorder = recorder
        self._max_workers = max(1, int(max_workers))
        self._max_outcomes = max(1, int(max_outcomes))
        self._outcomes: List[ToolCallOutcome] = []

    # -- introspection -------------------------------------------------------
    @property
    def outcomes(self) -> List[ToolCallOutcome]:
        return list(self._outcomes)

    @property
    def failures(self) -> List[ToolCallOutcome]:
        return [o for o in self._outcomes if not o.success]

    def _record(self, outcome: ToolCallOutcome) -> ToolCallOutcome:
        self._outcomes.append(outcome)
        overflow = len(self._outcomes) - self._max_outcomes
        if overflow > 0:
            del self._outcomes[:overflow]
        if self._recorder is not None:
            try:
                self._recorder(outcome)
            except Exception:  # noqa: BLE001 — recording never breaks dispatch
                pass
        return outcome

    # -- execution -----------------------------------------------------------
    def dispatch(self, call: ToolCall) -> ToolCallOutcome:
        """Run one tool call; never raises."""
        started = time.monotonic()
        try:
            result = self._runner(call.tool_id, dict(call.options))
        except Exception as exc:  # noqa: BLE001 — fail-soft dispatch
            outcome = ToolCallOutcome(
                tool_id=call.tool_id,
                label=call.label,
                success=False,
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"{type(exc).__name__}: {exc}"[:512],
            )
            return self._record(outcome)
        outcome = _coerce_outcome(
            call, result, int((time.monotonic() - started) * 1000)
        )
        return self._record(outcome)

    def dispatch_many(
        self,
        calls: Sequence[ToolCall],
        *,
        parallel: bool = True,
        max_workers: Optional[int] = None,
    ) -> List[ToolCallOutcome]:
        """Run several calls, optionally in parallel, preserving input order."""
        calls = list(calls)
        if not calls:
            return []
        if not parallel or len(calls) == 1:
            return [self.dispatch(call) for call in calls]

        workers = min(max_workers or self._max_workers, len(calls))
        results: List[Optional[ToolCallOutcome]] = [None] * len(calls)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(self.dispatch, call): index
                for index, call in enumerate(calls)
            }
            for future in as_completed(future_map):
                index = future_map[future]
                try:
                    results[index] = future.result()
                except Exception as exc:  # noqa: BLE001 — defensive
                    call = calls[index]
                    results[index] = self._record(
                        ToolCallOutcome(
                            tool_id=call.tool_id,
                            label=call.label,
                            success=False,
                            duration_ms=0,
                            error=f"{type(exc).__name__}: {exc}"[:512],
                        )
                    )
        return [r for r in results if r is not None]


__all__ = ["ToolCall", "ToolCallOutcome", "ToolDispatcher"]
