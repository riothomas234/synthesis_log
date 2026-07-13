"""
log.py — append-only log storage.

Spec: design.md §9 ("append-only log; persist to JSONL").

Written by the agent (design.md marks this file as agent-OK). Its whole
job is file plumbing: given "here's a new entry's content," figure out
its index and prev_hash from what's already on disk, hand the actual
hashing/signing off to logentry.py (treated here as a black box), and
write the result as one line of JSON.

Contains NO cryptographic logic. If you're looking for the code that
computes entry_hash or checks signatures, this is the wrong file — see
logentry.py (writes/signs) and verify.py (independently re-checks).

IMPORTANT — design.md §7: "append-only" here is a claim, not a
guarantee. This is an ordinary file opened in append mode on a normal
filesystem. Nothing below stops a process with filesystem access (e.g.
attack.py, deliberately) from truncating, editing, or replacing it
outright. That's expected: the threat model (§2) assumes the operator
CAN do this, and the chain hash + signature (logentry.py) are what make
doing it detectable rather than what make it impossible. Do not add
file permission tricks or locking here as if they were a real defense —
that would misrepresent what this prototype demonstrates.
"""

import json
import os
from datetime import datetime, timezone

from canonical import canonical
from logentry import build_entry

DEFAULT_LOG_PATH = "synthlog.jsonl"


def _read_lines(path: str) -> list[dict]:
    """Parse every line of the JSONL log into a dict, in file order.
    A missing file is treated as a valid empty log (device that has
    never logged anything yet), not an error."""
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def get_last_entry(path: str = DEFAULT_LOG_PATH) -> dict | None:
    """Return the most recently appended entry, or None if the log is
    empty. This is how the next append() call learns what index/
    prev_hash to use next — the caller never has to track chain state
    itself."""
    entries = _read_lines(path)
    return entries[-1] if entries else None


def append_entry(
    seq_commit: str,
    metadata: dict,
    private_key,
    path: str = DEFAULT_LOG_PATH,
) -> dict:
    """
    Append one new signed entry to the log and return it.

    Derives `index` and `prev_hash` from the current tail of the file
    (index 0 / prev_hash "" if the log is empty, per design.md §5),
    generates the timestamp, delegates all hashing/signing to
    logentry.build_entry, then writes exactly one line to disk and
    flushes/closes it (the `with` block closing the file forces an OS
    flush — important for an append-only log where "did this actually
    hit disk" matters).

    NOTE on timestamps: generated here, at append time, from the local
    system clock (UTC). A device with a compromised or simply
    mis-set clock can therefore lie about WHEN an event happened, even
    though — per the rest of this design — it cannot lie about WHAT was
    recorded or falsify the chain without detection. Trustworthy time
    (e.g. a signed timestamp from an external time-stamping authority)
    is a separate, currently unaddressed problem. Flag it in the
    write-up if your threat model cares about timestamp accuracy, not
    just content integrity.
    """
    last = get_last_entry(path)
    index = last["index"] + 1 if last else 0
    prev_hash = last["entry_hash"] if last else ""

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    entry = build_entry(
        index=index,
        timestamp=timestamp,
        seq_commit=seq_commit,
        metadata=metadata,
        prev_hash=prev_hash,
        private_key=private_key,
    )

    with open(path, "a", encoding="utf-8") as f:
        # Deliberately reuse canonical() for the on-disk bytes too, not
        # a fresh json.dumps() call. This means the bytes sitting in the
        # file are byte-for-byte identical to what compute_entry_hash
        # would produce if you canonicalized this same dict again later
        # — there's no second serialization path to drift out of sync
        # with the one that actually matters cryptographically.
        f.write(canonical(entry).decode("utf-8") + "\n")

    return entry


def read_log(path: str = DEFAULT_LOG_PATH) -> list[dict]:
    """Return every entry currently in the log, in file order. Used by
    verify.py (to check it) and attack.py (to corrupt it)."""
    return _read_lines(path)
