"""
audit_logger.py  —  v2.1
-------------------------
Immutable, SHA-256 chained audit log.
Every entry is cryptographically linked to the previous.

FIXES over v2.0:
  - Chain verification no longer mutates entries before hashing (critical bug fix)
  - _prev_hash is restored from the last log entry on module load (persistence fix)
  - Log path accepted as parameter; falls back to env var SANCTUM_LOG_FILE
"""

import hashlib
import json
import os
from datetime import datetime, timezone

_DEFAULT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'audit_logs', 'audit.jsonl')
LOG_FILE     = os.environ.get("SANCTUM_LOG_FILE", _DEFAULT_LOG)


def _sha256_of(data: dict) -> str:
    raw = json.dumps(data, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def _load_last_hash(log_file: str) -> str:
    """Read the log and return the entry_hash of the last entry, or 64 zeros."""
    if not os.path.exists(log_file):
        return "0" * 64
    last_hash = "0" * 64
    try:
        with open(log_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        if "entry_hash" in entry:
                            last_hash = entry["entry_hash"]
                    except Exception:
                        pass
    except Exception:
        pass
    return last_hash


# Restore chain continuity across restarts
_prev_hash = _load_last_hash(LOG_FILE)


def log_event(action: str, filename: str, detail: str, result: str,
              log_file: str = LOG_FILE) -> dict:
    global _prev_hash
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action":    action,
        "file":      filename,
        "detail":    detail,
        "result":    result,
        "prev_hash": _prev_hash,
    }
    entry["entry_hash"] = _sha256_of(entry)
    _prev_hash = entry["entry_hash"]

    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
    with open(log_file, 'a', encoding='utf-8') as fh:
        fh.write(json.dumps(entry) + '\n')
    return entry


def read_log(log_file: str = LOG_FILE) -> list:
    if not os.path.exists(log_file):
        return []
    entries = []
    with open(log_file, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    return entries


def verify_chain(log_file: str = LOG_FILE) -> bool:
    """
    Verify the SHA-256 chain of the audit log.

    FIX: We work on a copy of each entry so we never mutate the
    original dict. The stored prev_hash is already in the entry as
    loaded from disk — we do NOT overwrite it before hashing.
    """
    entries = read_log(log_file)
    if not entries:
        return True

    prev = "0" * 64
    for entry in entries:
        # Work on a shallow copy so we don't disturb the caller's data
        check = dict(entry)
        stored_hash = check.pop("entry_hash", None)
        if stored_hash is None:
            return False  # Malformed entry — chain broken

        # The entry already contains prev_hash as stored; do NOT overwrite it.
        computed = _sha256_of(check)
        if computed != stored_hash:
            return False
        if check.get("prev_hash") != prev:
            return False  # Chain linkage broken
        prev = stored_hash

    return True