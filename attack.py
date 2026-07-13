"""
attack.py — adversarial test harness.

Spec: design.md §9, §11 (acceptance demo).

Written by the agent (design.md marks this file as agent-OK). Plays the
role of the operator-adversary from design.md §2: full filesystem access
to synthlog.jsonl, no access to the private key. Each attack_* function
below corresponds to one of the adversary goals listed in §2. The
run_acceptance_demo() at the bottom reproduces §11's table exactly:

    append 3 entries            -> verify: OK
    delete entry 2              -> verify: chain broken at 3
    modify entry 1 metadata     -> verify: hash mismatch at 1
    rewrite tail after modify   -> verify: signature invalid at 1

That last line is the actual thesis of the project: an operator with
root access can recompute hashes to make a tampered chain internally
consistent again, but cannot forge the signatures, so the tamper is
still caught. Everything before it exists to make that payoff land —
you have to see the weaker attacks get caught by the weaker checks
first to understand why the signature layer is the one that matters.

Deliberately reads/writes the JSONL file directly with plain json
(rather than going through log.py's append_entry) because the adversary
here is attacking the FILE log.py produces, not calling into log.py's
API — a real attacker doesn't get to use the honest append path.
"""

import json
import os

from canonical import canonical
from logentry import generate_keypair
from log import append_entry
from verify import verify_log

DEMO_LOG_PATH = "attack_demo.jsonl"


def _load_lines(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _save_lines(path: str, entries: list[dict]) -> None:
    # Same canonical() call log.py uses to write entries, for the same
    # reason: whatever ends up on disk should be exactly what a
    # re-hash of that dict would produce, so the only thing under test
    # here is the CONTENT of the tamper, not an incidental formatting
    # difference from writing with plain json.dumps.
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(canonical(entry).decode("utf-8") + "\n")


def _fresh_log(path: str, private_key, n: int = 3) -> None:
    """Build a clean, honestly-signed n-entry log at `path`, deleting
    anything already there. Each demo row starts from this known-good
    state so the attacks don't compound in confusing ways."""
    if os.path.exists(path):
        os.remove(path)
    for i in range(n):
        append_entry(
            seq_commit=f"deadbeef{i:04d}",
            metadata={"length_bp": 100 + i},
            private_key=private_key,
            path=path,
        )


def attack_delete_entry(path: str, index: int) -> None:
    """Adversary goal 1 (design.md §2): delete a log entry outright.

    Every entry after the deleted one still has the OLD prev_hash
    pointing at the now-missing entry's hash — check_chain_linkage
    catches this as a broken link at the entry immediately after the
    gap.
    """
    entries = _load_lines(path)
    entries = [e for e in entries if e["index"] != index]
    _save_lines(path, entries)


def attack_modify_metadata(path: str, index: int, new_metadata: dict) -> None:
    """Adversary goal 2 (design.md §2): change what a specific entry
    says, WITHOUT fixing up its own entry_hash or anything downstream.
    This is the "sloppy" tamper — caught by hash integrity alone, before
    the chain-linkage or signature checks even get a chance to matter,
    because entry_hash now visibly doesn't match the entry's own new
    content.
    """
    entries = _load_lines(path)
    for e in entries:
        if e["index"] == index:
            e["metadata"] = new_metadata
    _save_lines(path, entries)


def attack_rewrite_tail(path: str, from_index: int) -> None:
    """
    The payoff attack (design.md §5, §11): after modifying an entry, an
    operator with root access recomputes entry_hash (and the following
    entries' prev_hash, chained off each new entry_hash) for every entry
    from from_index onward — repairing check_chain_linkage and
    check_hash_integrity. What they deliberately do NOT do is re-sign,
    because they don't have the private key: every rewritten entry keeps
    its OLD signature sitting on top of its NEW entry_hash. That
    signature was valid for the old hash and is not valid for the new
    one, so check_signature fails starting at from_index — the log is
    internally "consistent" and still detectably forged.

    Uses logentry.compute_entry_hash to do the recomputation — the same
    function the honest writer uses — because the adversary, per the
    threat model (§2), has root-level software access. They can run any
    hashing code that exists in the codebase; that's not a privileged
    capability being borrowed here, it's exactly what "root access, no
    private key" means.
    """
    from logentry import compute_entry_hash

    entries = _load_lines(path)
    prev_hash = entries[from_index - 1]["entry_hash"] if from_index > 0 else ""
    for e in entries[from_index:]:
        e["prev_hash"] = prev_hash
        new_hash = compute_entry_hash(
            index=e["index"],
            timestamp=e["timestamp"],
            seq_commit=e["seq_commit"],
            metadata=e["metadata"],
            prev_hash=e["prev_hash"],
        )
        e["entry_hash"] = new_hash.hex()
        # `e["signature"]` is intentionally left untouched here — the
        # adversary cannot produce a new one. This one omission is the
        # entire point of the attack.
        prev_hash = e["entry_hash"]
    _save_lines(path, entries)


def run_acceptance_demo() -> None:
    """Reproduces design.md §11's table row by row, printing results to
    stdout in the same format used there. Each row rebuilds a fresh,
    honest log first so the four scenarios don't interfere with each
    other (except the last, which deliberately builds "modify" and
    "rewrite tail" on top of one another, matching §11)."""
    private_key, public_key = generate_keypair()

    _fresh_log(DEMO_LOG_PATH, private_key)
    print(f"append 3 entries            -> verify: {verify_log(DEMO_LOG_PATH, public_key)}")

    _fresh_log(DEMO_LOG_PATH, private_key)
    attack_delete_entry(DEMO_LOG_PATH, 2)
    print(f"delete entry 2              -> verify: {verify_log(DEMO_LOG_PATH, public_key)}")

    _fresh_log(DEMO_LOG_PATH, private_key)
    attack_modify_metadata(DEMO_LOG_PATH, 1, {"length_bp": 999})
    print(f"modify entry 1 metadata     -> verify: {verify_log(DEMO_LOG_PATH, public_key)}")

    _fresh_log(DEMO_LOG_PATH, private_key)
    attack_modify_metadata(DEMO_LOG_PATH, 1, {"length_bp": 999})
    attack_rewrite_tail(DEMO_LOG_PATH, from_index=1)
    print(f"rewrite tail after modify   -> verify: {verify_log(DEMO_LOG_PATH, public_key)}")

    os.remove(DEMO_LOG_PATH)


if __name__ == "__main__":
    run_acceptance_demo()
