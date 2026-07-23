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

That footnote describes the original hash-chain design. Since the
switch to a Merkle tree + signed checkpoints, chain linkage and hash
integrity collapse into a single check — see check_root_integrity's
docstring for why that's a deliberate simplification, not a dropped
guarantee. Two checks now, not three, each its own clearly-named
function, each raising a TamperDetected with a specific reason, run in
a fixed order by verify_log(). Nothing is skipped, nothing is combined
silently — so it's easy for you (or anyone auditing this code) to
confirm each one is really happening and see exactly which one caught
what.

Why these two and not fewer:
  - Root integrity alone catches deletion, in-place edits, reordering,
    and insertion — in a Merkle tree, ANY change to ANY entry changes
    the root, so a single recompute-and-compare catches all of them at
    once (the old chain design needed two separate checks for this;
    the tree gets it in one, at the cost of losing per-entry
    localization in the report — see that check's docstring).
  - Signature is the one an operator with root but no private key
    genuinely cannot defeat — this is still the payoff check (design.md
    §11's original acceptance demo, "rewrite tail after modify ->
    signature invalid," has a direct analogue here: an operator can
    freely recompute a tampered tree's root, but can't produce a valid
    signature for it). But signature alone, without root integrity,
    wouldn't catch entries that were changed while a STALE checkpoint
    (signed over the old, honest root) was left in place.
  Both together is the point.
"""

import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from log import read_log, get_last_checkpoint, DEFAULT_LOG_PATH, DEFAULT_CHECKPOINTS_PATH
from logentry import compute_leaf_hash
from merkletree import compute_root


class TamperDetected(Exception):
    """Raised with a human-readable reason naming which check failed.
    verify_log() catches this at the top level and turns it into the
    report string design.md §11's format expects."""


def check_root_integrity(entries: list[dict], checkpoint: dict) -> None:
    """
    Recompute every entry's leaf hash from its own stored fields,
    rebuild the WHOLE tree via merkletree.compute_root, and compare the
    result to the last checkpoint's stored root_hash (and tree_size).

    Replaces the old chain-linkage + hash-integrity checks, combined
    into one: in a Merkle tree, ANY change to ANY entry — a deleted
    entry, an edited field, a reordered or inserted entry — changes the
    tree's root, so this single check catches all of them. The
    tradeoff, made deliberately: this reports "the log doesn't match
    the checkpoint," not which entry or why. The old chain design could
    localize a hash mismatch to a specific index; this can't, without
    also walking an inclusion proof per entry, which this prototype
    doesn't attempt (see design.md's Merkle-tree transition notes).

    tree_size is checked first, cheaply, for a clearer message in the
    common case (entries added or removed since the checkpoint) before
    falling back to the root comparison, which is the real cryptographic
    check and the only one that catches an edit that keeps entry COUNT
    the same (e.g. one entry swapped for another).

    Uses logentry.compute_leaf_hash — the SAME pure function log.py
    used to write each entry in the first place — rather than
    reimplementing hashing here, for the same reason the old
    check_hash_integrity did: recomputing with the real writer's own
    function is "recompute from scratch," not "ask the writer if it
    was honest."
    """
    if len(entries) != checkpoint["tree_size"]:
        raise TamperDetected(
            f"tree size mismatch: log has {len(entries)} entries but "
            f"the last checkpoint claims tree_size {checkpoint['tree_size']}"
        )

    recomputed_leaf_hashes = [
        compute_leaf_hash(
            index=entry["index"],
            timestamp=entry["timestamp"],
            seq_ciphertext=entry["seq_ciphertext"],
            metadata=entry["metadata"],
        )
        for entry in entries
    ]
    recomputed_root = compute_root(recomputed_leaf_hashes)

    # NOTE: assumes root_hash is stored hex-encoded, per the encoding
    # choice in logentry.build_checkpoint. If you choose base64 there
    # instead, update this .hex() call to match.
    if recomputed_root.hex() != checkpoint["root_hash"]:
        raise TamperDetected(
            "root mismatch: recomputing the tree from every entry "
            "currently in the log does not match the last signed "
            "checkpoint's root_hash (an entry was deleted, edited, "
            "reordered, or inserted)"
        )


def check_signature(checkpoint: dict, public_key: Ed25519PublicKey) -> None:
    """
    The checkpoint's signature verifies over its own root_hash, under
    the device's public key. This is the payoff check (design.md §11)
    — an operator can recompute leaf hashes and rebuild the tree freely
    (they have root), but cannot produce a valid signature over a
    DIFFERENT root without the private key. A forged checkpoint, or an
    honest-looking checkpoint paired with tampered entries whose new
    root the private key never actually signed, fails here.

    Deliberately takes public_key as a parameter rather than loading it
    itself: the auditor's trusted key must come from an out-of-band
    source (provisioning record, certificate, etc.), never from the
    same log being audited — otherwise the check is circular.
    """
    root_hash_bytes = bytes.fromhex(checkpoint["root_hash"])
    signature_bytes = bytes.fromhex(checkpoint["signature"])
    try:
        public_key.verify(signature_bytes, root_hash_bytes)
    except InvalidSignature:
        raise TamperDetected(
            "signature invalid: the last checkpoint's root_hash is not "
            "validly signed by the device key (the checkpoint was "
            "forged, or paired with a root the private key never "
            "actually signed)"
        )


def verify_log(
    path: str,
    checkpoints_path: str,
    public_key: Ed25519PublicKey,
) -> str:
    """
    Run both checks, in order, and return a human-readable report:
        "OK, N entries, root matches signed checkpoint"
        "TAMPER: <reason>"

    Order: root integrity first (recomputation from the entries
    themselves, giving the clearer root-cause message if the log was
    edited), signature last (the payoff check) — same "readability over
    strict necessity" ordering philosophy as the old three-check
    version; either check failing is sufficient to reject the log.

    An empty log with no checkpoint at all is valid — a device that has
    never logged anything yet. Entries with no checkpoint is NOT valid:
    every honest append_entry() call writes a checkpoint alongside its
    entry (log.py), so a missing checkpoint file for a non-empty log
    means the checkpoints file was deleted or never written — itself a
    form of tampering, not something to silently skip past. (A
    checkpoint present alongside zero entries falls through to
    check_root_integrity below, which catches the tree_size mismatch.)
    """
    entries = read_log(path)
    checkpoint = get_last_checkpoint(checkpoints_path)

    if checkpoint is None:
        if not entries:
            return "OK, 0 entries, root matches signed checkpoint"
        return "TAMPER: no checkpoint found for a non-empty log"

    try:
        check_root_integrity(entries, checkpoint)
        check_signature(checkpoint, public_key)
    except TamperDetected as e:
        return f"TAMPER: {e}"
    return f"OK, {len(entries)} entries, root matches signed checkpoint"


#following runs as a standalone command line tool.

if __name__ == "__main__":
    from logentry import load_public_key

    public_key = load_public_key()
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG_PATH
    checkpoints_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_CHECKPOINTS_PATH
    print(verify_log(path, checkpoints_path, public_key))
