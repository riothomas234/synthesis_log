"""
verify.py — the auditor's tool.

Spec: design.md §9, §11.

Written by the agent (design.md marks this file as agent-OK, with a
footnote worth repeating in full since it's the whole design brief for
this file):

    verify.py must check all three: (1) chain linkage via prev_hash,
    (2) entry_hash recomputation, (3) signature validity. A verifier
    that silently skips one is worse than none. Read every line before
    trusting it.

So: three checks, each its own clearly-named function, each raising a
TamperDetected with a specific reason, run in a fixed order by
verify_log(). Nothing is skipped, nothing is combined, on purpose — so
it's easy for you (or anyone auditing this code) to confirm each one is
really happening and see exactly which one caught what.

Why these three and not fewer:
  - Chain linkage alone catches deletion/reordering, but an operator who
    edits one entry AND recomputes every downstream prev_hash/entry_hash
    defeats it completely — the chain looks perfectly linked, just
    linked to different content.
  - Hash integrity alone catches a lazy in-place edit (content changed,
    stored entry_hash not updated) but does nothing against the same
    "recompute everything downstream" attack.
  - Signature is the one an operator with root but no private key
    genuinely cannot defeat — this is the payoff check in design.md
    §11's acceptance demo ("rewrite tail after modify -> signature
    invalid"). But signature alone, without chain linkage, wouldn't
    catch a whole valid-looking entry being deleted from the middle
    (every remaining entry is still individually well-signed).
  All three together is the point.
"""

import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from log import read_log
from logentry import compute_entry_hash


class TamperDetected(Exception):
    """Raised with a human-readable reason naming which check failed and
    at which entry. verify_log() catches this at the top level and turns
    it into the report string design.md §11 expects."""


def check_chain_linkage(entries: list[dict]) -> None:
    """
    Check (1): every entry's prev_hash equals the PREVIOUS entry's
    entry_hash, and index runs 0, 1, 2, ... with no gaps.

    Catches: deleted entries (the gap shows up as a broken link or a
    skipped index), reordered entries, and entries inserted out of
    sequence. Does NOT by itself catch an in-place edit where the
    attacker also fixed up every downstream hash — see check_hash_integrity
    and check_signature for that.
    """
    for i, entry in enumerate(entries):
        if entry["index"] != i:
            raise TamperDetected(
                f"index gap or reorder at position {i}: expected index "
                f"{i}, found {entry['index']}"
            )
        expected_prev = entries[i - 1]["entry_hash"] if i > 0 else ""
        if entry["prev_hash"] != expected_prev:
            raise TamperDetected(
                f"chain broken at entry {entry['index']}: prev_hash "
                f"does not match the previous entry's entry_hash "
                f"(a deleted, reordered, or forged entry)"
            )


def check_hash_integrity(entries: list[dict]) -> None:
    """
    Check (2): recompute entry_hash from each entry's own stored fields
    and compare to the entry_hash stored alongside it.

    Uses logentry.compute_entry_hash — the SAME pure function log.py
    used to write the entry in the first place — rather than
    reimplementing hashing here. That's intentional, not a trust
    shortcut: compute_entry_hash takes no secrets and has no side
    effects, so re-running it here is exactly "recompute the hash from
    scratch," not "ask the writer if it was honest." Having two
    divergent hash implementations (one to write, one to check) would be
    a bug waiting to happen, not an independence guarantee.
    """
    for entry in entries:
        recomputed = compute_entry_hash(
            index=entry["index"],
            timestamp=entry["timestamp"],
            seq_commit=entry["seq_commit"],
            metadata=entry["metadata"],
            prev_hash=entry["prev_hash"],
        )
        # NOTE: assumes entry_hash is stored hex-encoded, per the
        # encoding choice flagged as a TODO in logentry.build_entry.
        # If you choose base64 there instead, change .hex() to match.
        if recomputed.hex() != entry["entry_hash"]:
            raise TamperDetected(
                f"hash mismatch at entry {entry['index']}: stored "
                f"entry_hash does not match a fresh hash of this "
                f"entry's own fields (entry was edited in place)"
            )


def check_signature(entries: list[dict], public_key: Ed25519PublicKey) -> None:
    """
    Check (3): entry_hash's signature verifies under the device's public
    key. This is the check design.md §11 calls "the payoff" — an
    operator can freely recompute hashes (they're root, they can run any
    code), but cannot produce a valid signature without the private key,
    so a tail-rewrite that passes checks (1) and (2) still fails here.

    Deliberately takes public_key as a parameter rather than loading it
    itself: the auditor is supposed to already know/trust the device's
    public key from some out-of-band source (provisioning record,
    certificate, etc.) — this function must never read the "correct"
    key from the same log file it's auditing, or the whole check is
    circular.
    """
    for entry in entries:
        entry_hash_bytes = bytes.fromhex(entry["entry_hash"])
        signature_bytes = bytes.fromhex(entry["signature"])
        try:
            public_key.verify(signature_bytes, entry_hash_bytes)
        except InvalidSignature:
            raise TamperDetected(
                f"signature invalid at entry {entry['index']}: "
                f"entry_hash is not validly signed by the device key "
                f"(chain content was rewritten without the private key)"
            )


def verify_log(path: str, public_key: Ed25519PublicKey) -> str:
    """
    Run all three checks, in order, and return a human-readable report
    in the format design.md §11 uses:
        "OK, N entries, chain intact"
        "TAMPER: <reason>"

    Order matters for readability of the report (chain linkage errors
    are usually the "root cause" and easiest to explain; signature
    failures are checked last since they're the most expensive check
    and the most likely to already be explained by an earlier one) but
    NOT for correctness — any one of the three failing is sufficient to
    reject the log.
    """
    entries = read_log(path)
    if not entries:
        return "OK, 0 entries, chain intact"
    try:
        check_chain_linkage(entries)
        check_hash_integrity(entries)
        check_signature(entries, public_key)
    except TamperDetected as e:
        return f"TAMPER: {e}"
    return f"OK, {len(entries)} entries, chain intact"


if __name__ == "__main__":
    # TODO (you): once logentry.py's key persistence is implemented,
    # load the device's PUBLIC key here (not the private key — the
    # auditor should never need it) and pass it to verify_log(), e.g.:
    #
    #   from logentry import load_public_key
    #   public_key = load_public_key("device_public_key.pem")
    #   path = sys.argv[1] if len(sys.argv) > 1 else "synthlog.jsonl"
    #   print(verify_log(path, public_key))
    print(
        "verify.py: wire up public-key loading once logentry.py is "
        "implemented (see TODO in this file's __main__ block)."
    )
