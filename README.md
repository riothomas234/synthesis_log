# Tamper-Evident Local Synthesis Log

Records DNA synthesis events into an append-only log such that any later
deletion, modification, reordering, or forgery of entries is **detectable**
by a verifier who does not trust the operator of the device.

This is an integrity / non-repudiation tool, not a screening tool — it does
not inspect sequences for danger (cf. SecureDNA). It proves that a record of
a synthesis event exists and has not been altered. Sequence *confidentiality*
is a separate, orthogonal property: each entry stores only an encrypted
`seq_ciphertext`, decryptable solely by an auditor-held key the device never
possesses.

Full design, threat model, and open questions live in [`design.md`](design.md)
— this file is the source of truth; code must conform to it.

## Status

This is a prototype under active development. Integrity is built on a
**Merkle tree with signed checkpoints** (RFC 6962-style), not a hash chain,
and sequences are **encrypted**, not just hashed.

| file                | status                                                          |
|---------------------|------------------------------------------------------------------|
| `canonical.py`      | `canonical()` implemented. `canonical_sequence()` raises `NotImplementedError` — open design question, see `design.md` §4/§10.2. |
| `merkletree.py`     | implemented — tree construction, inclusion proofs, consistency proofs. Proofs are not yet wired into `verify.py` (full recompute is used instead). |
| `sequence_crypto.py`| implemented — hybrid X25519 + HKDF-SHA256 + AES-GCM encryption of sequences to an auditor-held key. |
| `logentry.py`       | implemented — leaf hashing, device Ed25519 keypair management, checkpoint signing. |
| `log.py`            | implemented. |
| `verify.py`         | implemented. |
| `attack.py`         | implemented. |

`canonical_sequence()` is deliberately left unimplemented; everything else
is functional end-to-end.

## Off-limits files

`canonical.py`, `merkletree.py`, `sequence_crypto.py`, and `logentry.py` are
hand-written by design and off limits to the coding agent — see `design.md`
§11 and `CLAUDE.md`. `log.py`, `verify.py`, and `attack.py` are agent-editable.

## Threat model, in one paragraph

The adversary is the **device operator** — someone with physical possession
and root access to the device, who wants to delete, alter, or forge log
entries to avoid an audit. They hold the auditor's *public* encryption key
(so they can produce valid-looking ciphertext) but not the auditor's private
decryption key, and not the device's private signing key. The design must
make deletion, modification, insertion, and rollback **detectable**, even
though — on this prototype — none of them are actually **prevented**
(append-only is assumed, not enforced; see `design.md` §9). Full detail in
`design.md` §2.

## How it works

Each log entry is a leaf in a Merkle tree:

```
index | timestamp | seq_ciphertext | metadata  ->  leaf_hash
```

- `seq_ciphertext` is the raw sequence hybrid-encrypted to the auditor's
  X25519 public key (`sequence_crypto.encrypt_sequence`) — a fresh ephemeral
  keypair per call means the same sequence encrypts differently every time.
- `leaf_hash = hash_leaf(canonical({index, timestamp, seq_ciphertext, metadata}))`,
  using RFC 6962 domain-separated hashing (`hash_leaf`/`hash_node` in
  `merkletree.py`).
- On every append, the **entire tree is rebuilt** from every entry on disk,
  the root is computed, and a **checkpoint** — `{tree_size, root_hash,
  signature}` — is signed with the device's Ed25519 private key and appended
  to `checkpoints.jsonl`. Individual entries are never signed on their own.

The operator can recompute the tree's root (they have root access, and they
can encrypt valid-looking ciphertext with the auditor's public key) but
cannot forge the checkpoint's signature over that root without the device's
private signing key — that gap is the whole argument. Full field-by-field
spec in `design.md` §5–§8.

## File plan

| file                | responsibility                                         |
|---------------------|---------------------------------------------------------|
| `canonical.py`      | dict -> deterministic bytes; the one serialization function everything hashes through. |
| `merkletree.py`     | RFC 6962-style Merkle tree: root computation, inclusion proofs, consistency proofs. |
| `sequence_crypto.py`| hybrid-encrypts raw sequences to the auditor's X25519 public key; decryption is auditor-only. |
| `logentry.py`       | builds a leaf entry, computes `leaf_hash`, manages the device's Ed25519 keypair, signs checkpoints. |
| `log.py`            | append-only JSONL storage (`synthlog.jsonl` + `checkpoints.jsonl`); rebuilds the tree and signs a checkpoint on every append. |
| `verify.py`         | the auditor's tool; independently recomputes the root from every entry and verifies the checkpoint signature under a trusted public key. |
| `attack.py`         | corrupts a log file in the ways an operator-adversary would, then runs `verify.py` against it. |

## Setup

```
pip install -r requirements.txt
```

Requires Python 3.10+ and the `cryptography` package (Ed25519 + X25519 +
AES-GCM support).

## Usage

```python
from logentry import generate_keypair
from sequence_crypto import generate_auditor_keypair
from log import append_entry

private_key, public_key = generate_keypair()                    # device signing key
auditor_private_key, auditor_public_key = generate_auditor_keypair()  # auditor encryption key

append_entry(
    raw_sequence="ACGTACGTGGCCTTAACCGGATCG",
    metadata={"length_bp": 500},
    private_key=private_key,
    auditor_public_key=auditor_public_key,
)
```

```python
from verify import verify_log

print(verify_log("synthlog.jsonl", "checkpoints.jsonl", public_key))
# raises TamperDetected(reason) on failure, returns normally on success
```

Decrypting a sequence is auditor-only, and requires the auditor's private key:

```python
from sequence_crypto import decrypt_sequence

print(decrypt_sequence(bytes.fromhex(entry["seq_ciphertext"]), auditor_private_key))
```

Run the acceptance demo (appends 3 entries, then runs each attack from
`design.md` §13 and prints what `verify.py` catches):

```
python3 attack.py
```

Expected output:

```
append 3 entries               -> verify: OK
delete entry 1                 -> verify: tree size mismatch
modify entry 1 metadata        -> verify: root mismatch
swap entry 1 ciphertext        -> verify: root mismatch
modify + forge checkpoint      -> verify: signature invalid   <- the payoff
```

Unlike the earlier hash-chain design, delete/modify/ciphertext-swap are now
all caught by the *same* check (`check_root_integrity`) — any change to any
entry changes the Merkle root. The last line is the core argument of the
whole project: an operator can recompute a tampered tree's root correctly,
but cannot forge the checkpoint's signature over that root without the
device's private key — so a "repaired" tree is still detectably forged.

## Open questions

Tracked in full in `design.md` §10. Highest priority right now:

1. Moving to an incremental MMR as the log grows (current tree is fully
   rebuilt on every append), and wiring `merkletree.py`'s inclusion/
   consistency proofs into `verify.py`'s audit flow.
2. `canonical_sequence()` — not yet specified; now determines exactly what
   bytes get encrypted.
3. Which metadata fields are actually forensically meaningful.
4. Auditor key management/recovery — there is no backup or escrow path for
   the auditor's private decryption key; losing it forfeits every historical
   sequence's plaintext.

## What this prototype does *not* claim

- **Not append-only in any enforced sense.** `synthlog.jsonl` and
  `checkpoints.jsonl` are plain files; nothing stops a root process from
  truncating or replacing them. Detecting *tampering* is strong; detecting
  *total deletion* is weaker and depends on external anchoring/witnessing
  not yet built. See `design.md` §9.
- **Confidentiality depends on the auditor's private key staying private.**
  `seq_ciphertext` is semantically secure (fresh ephemeral key per
  encryption), but there is no key-recovery mechanism if that private key is
  lost. See `design.md` §8/§10 item 4.
- **Key storage is simulated, not hardware-enforced**, until the optional
  ATECC608 secure element (Month 2) lands, for the device's signing key.
