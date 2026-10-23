#!/usr/bin/env python3
"""Validate an Obsidian Recon planner training JSONL file.

Usage:
    python backend/scripts/validate_planner_dataset.py \
        backend/data/planner_training.jsonl

Checks the exact planner state/finding/observation/tool field contracts, the
exact output schema, option and origin rules, capability prerequisites,
deduplication, step budget, identifier preservation, forbidden content, and
dataset-level coverage of the eight MITRE ATT&CK Enterprise techniques plus the
required negative cases. Exits non-zero when any check fails.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.agent.training_data import validate_jsonl  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="JSONL file to validate")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.path.exists():
        print(f"ERROR: {args.path} does not exist", file=sys.stderr)
        return 2
    text = args.path.read_text(encoding="utf-8")
    errors = validate_jsonl(text)
    if errors:
        print(f"{len(errors)} validation error(s) in {args.path}:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    line_count = sum(1 for line in text.splitlines() if line.strip())
    print(f"OK: {line_count} records in {args.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
