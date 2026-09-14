"""JSON file persistence for pipeline artifacts under backend/data/."""
import json
import os
from pathlib import Path
from typing import Any, List

from app.core.config import data_file


def _ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def write_json(path: str, data: Any) -> None:
    _ensure_parent(path)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def read_json(path: str, default: Any = None) -> Any:
    if not os.path.exists(path):
        return [] if default is None else default
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return [] if default is None else default


def append_json(path: str, entry: Any) -> None:
    data = read_json(path, [])
    if not isinstance(data, list):
        data = []
    data.append(entry)
    write_json(path, data)


ARTIFACT_PATHS = {
    "recon": "recon/recon.json",
    "findings": "findings/findings.json",
    "evidence": "evidence/evidence_store.json",
    "attack_paths": "attack_paths/attack_paths.json",
    "queues": "queues/manual_review_queue.json",
}


def load_list(key: str) -> List[dict]:
    path = ARTIFACT_PATHS.get(key)
    if path is None:
        raise KeyError(f"unknown artifact: {key}")
    return read_json(data_file(path), [])


def save(key: str, data: Any) -> str:
    path = ARTIFACT_PATHS.get(key)
    if path is None:
        raise KeyError(f"unknown artifact: {key}")
    full = data_file(path)
    write_json(full, data)
    return full
