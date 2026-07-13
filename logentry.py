"""
logentry.py — build and sign a single log entry. The crypto core.

Spec: design.md §5 ("Log entry structure") and the "What the signature
covers — BE EXACT" subsection.

HAND-WRITTEN FILE. Per design.md §9 this file is off limits to the
coding agent. This is deliberately left as a SCAFFOLD, not a stub-only
blank file: function names, signatures, and docstrings quoting the spec
are filled in so (a) log.py and verify.py have a stable interface to
import against and (b) you're not staring at a blank page deciding what
the shape of things should be. But every function body that does actual
cryptographic work raises NotImplementedError — that part is yours to
write, because this is the file where "I understand what I built"
matters most for this project.

Depends on the `cryptography` package for Ed25519 (design.md §3):
    pip install cryptography
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from canonical import canonical

# The fields that get hashed into entry_hash, per design.md §5.
# Deliberately does NOT include entry_hash or signature — see
# compute_entry_hash below and the "BE EXACT" section of §5.
ENTRY_FIELDS = ("index", "timestamp", "seq_commit", "metadata", "prev_hash")


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """
    Produce (or load) this device's Ed25519 keypair.

    design.md §7 is blunt about this: on the prototype, "device-bound
    key" is aspirational. A key that lives in a file on the Pi's SD card
    is extractable by exactly the adversary this project defends
    against (root-level physical access) — the ATECC608 secure element
    (Month 2) is what would make the key actually non-extractable.
    Until then, this function is simulating that property, and the
    write-up should say so plainly rather than imply otherwise.

    TODO (you): decide and implement:
      - Generate-once-and-persist vs. regenerate every run. You want
        the former — a new key each run breaks the story that every
        entry in the log is signed by "the device's" one key. Probably:
        check for an existing private key file, load it if present,
        generate + save if not.
      - Where the private key file lives, and what file permissions it
        gets (0600, not world-readable — even though on this threat
        model the adversary has root anyway, so this is a courtesy, not
        a real control).
      - What format to persist in (cryptography's Ed25519PrivateKey
        supports PEM export via `private_bytes`) and whether the public
        key gets written out separately for verify.py to load without
        needing the private key at all.
    """
    raise NotImplementedError


def compute_entry_hash(
    index: int,
    timestamp: str,
    seq_commit: str,
    metadata: dict,
    prev_hash: str,
) -> bytes:
    """
    entry_hash = SHA256(canonical({index, timestamp, seq_commit, metadata, prev_hash}))

    design.md §5, "BE EXACT": entry_hash covers every field in
    ENTRY_FIELDS and nothing else — specifically NOT entry_hash itself
    (obviously) and NOT signature (which doesn't exist yet when this
    runs, and which must never be part of what gets hashed — see
    sign_entry_hash below for why that matters).

    Also used independently by verify.py to RECOMPUTE the hash of a
    stored entry and check it against what's on disk — that's the
    "hash integrity" check. Keep this function pure (no side effects,
    no reliance on anything outside its arguments) so both callers get
    identical behavior.

    TODO (you):
      1. Build a dict containing exactly ENTRY_FIELDS with these values.
      2. Pass it through canonical() from canonical.py — do not
         re-implement serialization here, that's the one-true-function
         canonical.py exists to be.
      3. hashlib.sha256(...).digest() the result and return the raw
         bytes (encoding to hex/base64 for storage is build_entry's job,
         not this function's — keep this one returning raw bytes so
         sign_entry_hash can consume it directly).
    """
    raise NotImplementedError


def sign_entry_hash(entry_hash: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """
    signature = Ed25519_sign(entry_hash) under the device-bound key.

    design.md §5: "Do not sign the raw dict; sign the hash." This
    matters for a subtle reason: if you signed the dict directly, the
    signature primitive would need its own serialization step, and now
    you have TWO places that turn a dict into bytes (this one and
    canonical()) which can drift apart. Signing the already-computed
    entry_hash means canonicalization happens exactly once, upstream,
    and this function's only job is a raw Ed25519 sign over 32 bytes.

    Because entry_hash already transitively includes prev_hash (see
    compute_entry_hash), signing entry_hash also transitively commits to
    the entire prior chain, not just this one entry. That's what makes
    "rewrite the tail" the payoff attack in design.md §11 — an operator
    who edits an old entry must reproduce a valid signature for every
    entry after it too, and can't, because they don't have this key.

    TODO (you): private_key.sign(entry_hash) — see the `cryptography`
    library's Ed25519PrivateKey.sign() docs. Note Ed25519 signing does
    not take a separate hash step internally the way some ECDSA APIs do
    — you're signing the 32 raw SHA-256 bytes directly.
    """
    raise NotImplementedError


def build_entry(
    index: int,
    timestamp: str,
    seq_commit: str,
    metadata: dict,
    prev_hash: str,
    private_key: Ed25519PrivateKey,
) -> dict:
    """
    Orchestrate one complete entry per design.md §5's field table:
    index, timestamp, seq_commit, metadata, prev_hash, entry_hash,
    signature. This is the one function log.py calls — it should not
    need to know anything about hashing or signing internals.

    TODO (you):
      1. Call compute_entry_hash(...) with the five input fields.
      2. Call sign_entry_hash(...) on the result.
      3. Return a dict with all seven fields. entry_hash and signature
         are raw bytes at this point — JSON can't serialize bytes, so
         encode them (hex is the simplest choice — `.hex()` /
         `bytes.fromhex()` round-trips cleanly and is easy to eyeball
         in the JSONL file, which matters for a tool whose whole point
         is inspectability). Pick one encoding and use it consistently;
         verify.py's hash/signature comparisons assume hex below — if
         you choose base64 instead, update verify.py's `.hex()` calls
         to match.
    """
    raise NotImplementedError
