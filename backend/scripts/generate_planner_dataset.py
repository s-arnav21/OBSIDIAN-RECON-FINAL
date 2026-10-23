#!/usr/bin/env python3
"""Generate the Obsidian Recon planner training dataset as JSONL.

Usage:
    python backend/scripts/generate_planner_dataset.py \
        [--output backend/datasets/planner_training.jsonl]

The output is deterministic. Every record is validated before it is written;
a validation failure exits non-zero and leaves no partial file behind.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.agent.training_data import (  # noqa: E402
    build_dataset,
    dumps_jsonl,
    validate_dataset,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=BACKEND_ROOT / "datasets" / "planner_training.jsonl",
        help="Destination JSONL path (default: backend/datasets/planner_training.jsonl)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print errors.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    records = build_dataset()
    errors = validate_dataset(records)
    if errors:
        print("Dataset validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    payload = dumps_jsonl(records)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(args.output)

    if not args.quiet:
        techniques = Counter(
            record["supervision"]["technique_id"] for record in records
        )
        negatives = Counter(
            rejected["code"]
            for record in records
            for rejected in record["supervision"]["rejected_candidates"]
        )
        print(f"Wrote {len(records)} records to {args.output}")
        print("Technique coverage:")
        for technique_id, count in sorted(techniques.items()):
            print(f"  {technique_id}: {count}")
        print("Negative-case coverage:")
        for code, count in sorted(negatives.items()):
            print(f"  {code}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
