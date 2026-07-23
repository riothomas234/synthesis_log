"""
attack.py — adversarial test harness.

Spec: design.md §9, §13 (acceptance demo) — updated for the encrypted-
sequence design (seq_ciphertext replaces seq_commit; see design.md §8).

Written by the agent (design.md marks this file as agent-OK). Plays the
role of the operator-adversary from design.md §2: full filesystem access
to synthlog.jsonl and checkpoints.jsonl, no access to the device's
private signing key, no access to the auditor's private decryption key.
They DO have the auditor's PUBLIC key — it's provisioned to the device,
not secret (see sequence_crypto.py) — so they can produce valid-looking
ciphertext, just never decrypt anything or forge a signature.

Each attack_* function below corresponds to one of the adversary goals
listed in §2. run_acceptance_demo() at the bottom reproduces the
acceptance demo:

    append 3 entries               -> verify: OK
    delete entry 1                 -> verify: tree size mismatch
    modify entry 1 metadata        -> verify: root mismatch
    swap entry 1 ciphertext        -> verify: root mismatch
    modify + forge checkpoint      -> verify: signature invalid

The new fourth row (swap entry 1 ciphertext) exists specifically to
validate a claim from this project's design discussion: that
seq_ciphertext being opaque (even to someone with full log access)
doesn't make it a blind spot. It still feeds into leaf_hash exactly like
every other field, so swapping it for a differently-encrypted sequence
is caught by check_root_integrity the same way a metadata edit is — the
operator can produce VALID ciphertext (they have the auditor's public
key), just not ciphertext that reproduces the original leaf_hash without
also knowing what was actually inside it.

The LAST row is still the actual thesis of the project: an operator with
root access can recompute a tampered tree's root correctly, but cannot
forge the checkpoint's signature over it, so the tamper is still caught.
Everything before it exists to make that payoff land — you have to see
the weaker attacks get caught by the weaker check first to understand
why the signature layer is the one that matters.

Deliberately reads/writes the JSONL files directly with plain json
(rather than going through log.py's append_entry) because the adversary
here is attacking the FILES log.py produces, not calling into log.py's
API — a real attacker doesn't get to use the honest append path.
"""

import json
import os

from canonical import canonical
from logentry import generate_keypair
from sequence_crypto import generate_auditor_keypair, encrypt_sequence
from log import append_entry
from verify import verify_log

DEMO_LOG_PATH = "attack_demo.jsonl"
DEMO_CHECKPOINTS_PATH = "attack_demo_checkpoints.jsonl"
DEMO_AUDITOR_PRIVATE_KEY_PATH = "attack_demo_auditor_keys/auditor_private_key.pem"
DEMO_AUDITOR_PUBLIC_KEY_PATH = "attack_demo_auditor_keys/auditor_public_key.pem"


def _load_lines(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _save_lines(path: str, entries: list[dict]) -> None:
    # Same canonical() call log.py uses to write entries/checkpoints,
    # for the same reason: whatever ends up on disk should be exactly
    # what a re-hash of that dict would produce, so the only thing
    # under test here is the CONTENT of the tamper, not an incidental
    # formatting difference from writing with plain json.dumps.
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(canonical(entry).decode("utf-8") + "\n")


def _fresh_log(
    path: str,
    checkpoints_path: str,
    private_key,
    auditor_public_key,
    n: int = 3,
) -> None:
    """Build a clean, honestly-signed n-entry log (and its matching
    checkpoints) at `path`/`checkpoints_path`, deleting anything
    already there. Each demo row starts from this known-good state so
    the attacks don't compound in confusing ways."""
    for p in (path, checkpoints_path):
        if os.path.exists(p):
            os.remove(p)
    for i in range(n):
        append_entry(
            raw_sequence=f"ACGT{'ACGT' * i}TTAACCGG",
            metadata={"length_bp": 100 + i},
            private_key=private_key,
            auditor_public_key=auditor_public_key,
            path=path,
            checkpoints_path=checkpoints_path,
        )


def attack_delete_entry(path: str, index: int) -> None:
    """Adversary goal 1 (design.md §2): delete a log entry outright,
    without touching checkpoints.jsonl.

    Unlike the old chain design (which needed a specific downstream
    entry to reveal a broken prev_hash link, so deleting the very last
    entry of a short log was invisible), deleting ANY entry now changes
    the total entry COUNT, which check_root_integrity checks first and
    cheaply — no need to pick a "middle" index or pad the log to make
    the deletion visible.
    """
    entries = _load_lines(path)
    entries = [e for e in entries if e["index"] != index]
    _save_lines(path, entries)


def attack_modify_metadata(path: str, index: int, new_metadata: dict) -> None:
    """Adversary goal 2 (design.md §2): change what a specific entry
    says, without touching checkpoints.jsonl. Entry count stays the
    same, but the entry's own leaf_hash field is now stale (still the
    hash of the OLD metadata) and, more importantly, recomputing the
    whole tree from this entry's new content no longer matches the
    last checkpoint's root_hash — check_root_integrity catches this via
    the root comparison rather than the (cheaper, count-only) tree_size
    check that catches attack_delete_entry above.
    """
    entries = _load_lines(path)
    for e in entries:
        if e["index"] == index:
            e["metadata"] = new_metadata
    _save_lines(path, entries)


def attack_swap_ciphertext(path: str, index: int, auditor_public_key) -> None:
    """
    New adversary tactic, enabled by encryption replacing seq_commit:
    swap a specific entry's seq_ciphertext for the encryption of a
    DIFFERENT sequence, without touching checkpoints.jsonl. The operator
    has the auditor's PUBLIC key — it's provisioned to the device, not
    secret (sequence_crypto.py's central asymmetry) — so they can
    produce perfectly VALID ciphertext, just for the wrong content.

    This validates a specific claim from the design discussion: that
    seq_ciphertext being opaque doesn't make it a blind spot for routine
    verification. It still feeds into leaf_hash exactly like every other
    field, so this is caught by check_root_integrity's root comparison
    the same way attack_modify_metadata is — the operator being able to
    produce valid-LOOKING ciphertext doesn't help them reproduce the
    original leaf_hash without knowing what was actually encrypted
    inside it originally.
    """
    entries = _load_lines(path)
    for e in entries:
        if e["index"] == index:
            e["seq_ciphertext"] = encrypt_sequence(
                "GATTACAGATTACAGATTACA", auditor_public_key
            ).hex()
    _save_lines(path, entries)


def attack_forge_checkpoint(path: str, checkpoints_path: str) -> None:
    """
    The payoff attack (design.md §13's analogue in this design): after
    tampering with entries (attack_modify_metadata above), an operator
    with root access recomputes the CORRECT new root from the CURRENT
    (tampered) entries and overwrites the last checkpoint to claim that
    root — repairing check_root_integrity. What they deliberately do
    NOT do is produce a NEW signature over that root, because they
    don't have the private key: the forged checkpoint keeps the OLD
    checkpoint's signature, which was valid for the OLD root and is not
    valid for this new one. check_signature fails — the tampered log is
    internally "consistent" with its own claimed root and still
    detectably forged.

    Uses logentry.compute_leaf_hash and merkletree.compute_root to do
    the recomputation — the same functions the honest writer uses —
    because the adversary, per the threat model (§2), has root-level
    software access. They can run any hashing code that exists in the
    codebase; that's not a privileged capability being borrowed here,
    it's exactly what "root access, no private key" means.
    """
    from logentry import compute_leaf_hash
    from merkletree import compute_root

    entries = _load_lines(path)
    checkpoints = _load_lines(checkpoints_path)
    stale_signature = checkpoints[-1]["signature"]

    leaf_hashes = [
        compute_leaf_hash(
            index=e["index"],
            timestamp=e["timestamp"],
            seq_ciphertext=e["seq_ciphertext"],
            metadata=e["metadata"],
        )
        for e in entries
    ]
    new_root = compute_root(leaf_hashes)

    checkpoints[-1] = {
        "tree_size": len(entries),
        "root_hash": new_root.hex(),
        "timestamp": checkpoints[-1]["timestamp"],
        # `signature` is intentionally left as the OLD, stale value —
        # the adversary cannot produce a new one. This one omission is
        # the entire point of the attack.
        "signature": stale_signature,
    }
    _save_lines(checkpoints_path, checkpoints)


def run_acceptance_demo() -> None:
    """Reproduces the acceptance demo row by row, printing results to
    stdout. Each row rebuilds a fresh, honest log first so the scenarios
    don't interfere with each other (except the last, which deliberately
    builds "modify" and "forge checkpoint" on top of one another,
    matching the structure of the original demo)."""
    private_key, public_key = generate_keypair()
    auditor_private_key, auditor_public_key = generate_auditor_keypair(
        private_key_path=DEMO_AUDITOR_PRIVATE_KEY_PATH,
        public_key_path=DEMO_AUDITOR_PUBLIC_KEY_PATH,
    )

    _fresh_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, private_key, auditor_public_key)
    print(f"append 3 entries               -> verify: {verify_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, public_key)}")

    _fresh_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, private_key, auditor_public_key)
    attack_delete_entry(DEMO_LOG_PATH, 1)
    print(f"delete entry 1                 -> verify: {verify_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, public_key)}")

    _fresh_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, private_key, auditor_public_key)
    attack_modify_metadata(DEMO_LOG_PATH, 1, {"length_bp": 999})
    print(f"modify entry 1 metadata        -> verify: {verify_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, public_key)}")

    _fresh_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, private_key, auditor_public_key)
    attack_swap_ciphertext(DEMO_LOG_PATH, 1, auditor_public_key)
    print(f"swap entry 1 ciphertext        -> verify: {verify_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, public_key)}")

    _fresh_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, private_key, auditor_public_key)
    attack_modify_metadata(DEMO_LOG_PATH, 1, {"length_bp": 999})
    attack_forge_checkpoint(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH)
    print(f"modify + forge checkpoint      -> verify: {verify_log(DEMO_LOG_PATH, DEMO_CHECKPOINTS_PATH, public_key)}")

    os.remove(DEMO_LOG_PATH)
    os.remove(DEMO_CHECKPOINTS_PATH)


if __name__ == "__main__":
    run_acceptance_demo()
