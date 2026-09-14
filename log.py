"""
log.py — append-only log storage.

Spec: design.md §9.

Written by the agent (design.md marks this file as agent-OK). Its whole
job is file plumbing: given "here's a new entry's content," build the
entry, rebuild the whole Merkle tree over the existing entries plus the new
one, sign a fresh checkpoint over that tree's root, and write both to disk.
Delegates all hashing/signing to logentry.py and all tree construction
to merkletree.py (both treated here as black boxes).

Contains NO cryptographic logic. If you're looking for the code that
computes leaf_hash, builds the tree, or signs anything, this is the
wrong file — see logentry.py (entry/checkpoint building, signing),
merkletree.py (tree construction, proofs), and verify.py (independently
re-checks).

IMPORTANT — design.md §7: "append-only" here is a claim, not a
guarantee. This is an ordinary pair of files opened in append mode on a
normal filesystem. Nothing below stops a process with filesystem access
(e.g. attack.py, deliberately) from truncating, editing, or replacing
either one outright. That's expected: the threat model (§2) assumes the
operator CAN do this, and the tree + checkpoint signature (logentry.py,
merkletree.py) are what make doing it detectable rather than what make
it impossible. Do not add file permission tricks or locking here as if
they were a real defense — that would misrepresent what this prototype
demonstrates.

Rebuild strategy: every append reads the ENTIRE log and recomputes the
WHOLE tree from scratch via merkletree.compute_root — O(n) work per
append, not incremental (no MMR). This is a deliberate simplicity
choice for this prototype: dead simple to reason about and verify by
hand, at the cost of redoing work on every append. An MMR would avoid
the full rebuild; that's a known, deferred optimization (design.md
§8.1), not an oversight.
"""

import json
import os
from datetime import datetime, timezone

from canonical import canonical
from logentry import build_entry, build_checkpoint
from merkletree import compute_root


DEFAULT_LOG_PATH = "synthlog.jsonl"
DEFAULT_CHECKPOINTS_PATH = "checkpoints.jsonl"


def _read_lines(path: str) -> list[dict]:
    """Parse every line of a JSONL file into a dict, in file order.
    A missing file is treated as empty (a device that hasn't logged or
    checkpointed anything yet), not an error. Shared by both the entry
    log and the checkpoint log — same format, same parsing."""
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
    empty. This is how the next append_entry() call learns what index
    to use next — the caller never has to track that itself."""
    entries = _read_lines(path)
    return entries[-1] if entries else None


def get_last_checkpoint(path: str = DEFAULT_CHECKPOINTS_PATH) -> dict | None:
    """Return the most recently written checkpoint, or None if none
    exist yet. verify.py uses this to get the root_hash it trusts;
    attack.py uses it as a target to corrupt or leave stale."""
    checkpoints = _read_lines(path)
    return checkpoints[-1] if checkpoints else None


def append_entry(
    raw_sequence: str,
    metadata: dict,
    private_key,
    auditor_public_key,
    path: str = DEFAULT_LOG_PATH,
    checkpoints_path: str = DEFAULT_CHECKPOINTS_PATH,
    rollback_guard=None,
) -> dict:
    """
    Append one new entry to the log, then rebuild the whole tree and
    append a freshly signed checkpoint over it. Returns the new entry
    (not the checkpoint — callers who want that can read it back via
    get_last_checkpoint()).

    Two writes happen here, in order:
      1. The entry itself (unsigned — see logentry.build_entry; only
         checkpoints get signed now, not individual entries). raw_sequence
         and auditor_public_key are passed straight through to
         logentry.build_entry, which is the only place a raw sequence is
         ever handled — this function never sees seq_ciphertext's
         contents as anything other than an opaque field in the dict
         build_entry hands back.
      2. A checkpoint: the ENTIRE tree is rebuilt from the existing entries
         plus the new one, and the resulting root gets signed fresh. This is
         "sign every append" per the
         design decision — no batching, no periodic checkpoints, so the
         log is immediately independently verifiable after every single
         append, same as the old chain design's behavior.

    NOTE on timestamps: same caveat as before this file's Merkle-tree
    rewrite — generated here, at append time, from the local system
    clock (UTC). A device with a compromised or mis-set clock can lie
    about WHEN something happened; it still can't lie about WHAT was
    recorded, or forge a checkpoint, without the private key. The same
    timestamp is used for both the entry and the checkpoint produced
    alongside it, since they're conceptually one atomic append.
    """
    if rollback_guard is not None:
        with rollback_guard.lock():
            rollback_guard.recover(path, checkpoints_path)
            return _append_entry(
                raw_sequence,
                metadata,
                private_key,
                auditor_public_key,
                path,
                checkpoints_path,
                rollback_guard,
            )
    return _append_entry(
        raw_sequence,
        metadata,
        private_key,
        auditor_public_key,
        path,
        checkpoints_path,
        None,
    )


def _append_entry(
    raw_sequence,
    metadata,
    private_key,
    auditor_public_key,
    path,
    checkpoints_path,
    rollback_guard,
) -> dict:
    last = get_last_entry(path)
    index = last["index"] + 1 if last else 0

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    entry = build_entry(
        index=index,
        timestamp=timestamp,
        raw_sequence=raw_sequence,
        metadata=metadata,
        auditor_public_key=auditor_public_key,
    )

    all_entries = _read_lines(path) + [entry]
    leaf_hashes = [bytes.fromhex(e["leaf_hash"]) for e in all_entries]
    root_hash = compute_root(leaf_hashes)

    checkpoint = build_checkpoint(
        tree_size=len(all_entries),
        root_hash=root_hash,
        timestamp=timestamp,
        private_key=private_key,
    )

    if rollback_guard is not None:
        rollback_guard.commit(
            entry=entry,
            checkpoint=checkpoint,
            prior_checkpoints=_read_lines(checkpoints_path),
            log_path=path,
            checkpoints_path=checkpoints_path,
        )
        return entry

    with open(path, "a", encoding="utf-8") as f:
        # Same reasoning as before this file's rewrite: reuse canonical()
        # for the on-disk bytes, not a fresh json.dumps() call, so what's
        # sitting in the file is byte-for-byte what re-canonicalizing
        # this dict later would produce — no second serialization path
        # to drift out of sync with the one that matters cryptographically.
        f.write(canonical(entry).decode("utf-8") + "\n")

    with open(checkpoints_path, "a", encoding="utf-8") as f:
        f.write(canonical(checkpoint).decode("utf-8") + "\n")

    return entry


def read_log(path: str = DEFAULT_LOG_PATH) -> list[dict]:
    """Return every entry currently in the log, in file order. Used by
    verify.py (to check it) and attack.py (to corrupt it)."""
    return _read_lines(path)


def read_checkpoints(path: str = DEFAULT_CHECKPOINTS_PATH) -> list[dict]:
    """Return every checkpoint currently on disk, in file order. Used
    by verify.py (to check the latest one) and attack.py (to corrupt
    or forge one)."""
    return _read_lines(path)
