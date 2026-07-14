# Tamper-Evident Local Synthesis Log

Records DNA synthesis events into an append-only log such that any later
deletion, modification, reordering, or forgery of entries is **detectable**
by a verifier who does not trust the operator of the device.

This is an integrity / non-repudiation tool, not a screening tool — it does
not inspect sequences for danger (cf. SecureDNA). It proves that a record of
a synthesis event exists and has not been altered.

Full design, threat model, and open questions live in [`design.md`](design.md)
— this file is the source of truth; code must conform to it.

## Status

This is a prototype under active development. Two files are intentionally
**incomplete scaffolds**, not bugs:

| file          | status                                                          |
|---------------|------------------------------------------------------------------|
| `canonical.py`| `canonical()` implemented. `canonical_sequence()` raises `NotImplementedError` — open design question, see `design.md` §4/§8.3. |
| `logentry.py` | scaffolded (signatures + docstrings match `design.md` §5); all bodies raise `NotImplementedError` — the crypto core, hand-written by design. |
| `log.py`      | implemented. |
| `verify.py`   | implemented. |
| `attack.py`   | implemented. |

Until `canonical.py` and `logentry.py` are filled in, `log.py`/`verify.py`/
`attack.py` will import fine but fail at runtime the moment they hit real
hashing or signing.

## Threat model, in one paragraph

The adversary is the **device operator** — someone with physical possession
and root access to the device, who wants to delete, alter, or forge log
entries to avoid an audit. They cannot break SHA-256 or extract a private
key held in a secure element. The design must make deletion, modification,
insertion, and rollback **detectable**, even though — on this prototype —
none of them are actually **prevented** (append-only is assumed, not
enforced; see `design.md` §7). Full detail in `design.md` §2.

## How it works

Each log entry is a signed, hash-chained record:

```
index | timestamp | seq_commit | metadata | prev_hash | entry_hash | signature
```

- `prev_hash` links each entry to the one before it, so deleting, reordering,
  or inserting an entry breaks the chain.
- `entry_hash` is `SHA256` of every other field, canonically serialized.
- `signature` is an Ed25519 signature over `entry_hash` under a device-bound
  key. Because `entry_hash` already commits to `prev_hash`, one signature
  transitively commits to the entire history up to that point.

The operator can recompute hashes (they have root) but cannot forge
signatures (they don't have the private key) — that gap is the whole
argument. Full field-by-field spec in `design.md` §5.

## File plan

| file          | responsibility                                         |
|---------------|---------------------------------------------------------|
| `canonical.py`| dict -> deterministic bytes; the one serialization function everything hashes/signs through. |
| `logentry.py` | builds and signs a single entry — the crypto core. |
| `log.py`      | append-only JSONL storage; derives `index`/`prev_hash` from the file tail. |
| `verify.py`   | the auditor's tool; independently re-checks chain linkage, hash integrity, and signature validity. |
| `attack.py`   | corrupts a log file in the ways an operator-adversary would, then runs `verify.py` against it. |

## Setup

```
pip install -r requirements.txt
```

Requires Python 3.10+ and the `cryptography` package (Ed25519 support).

## Usage

Once `canonical.py` and `logentry.py` are filled in:

```python
from logentry import generate_keypair
from log import append_entry

private_key, public_key = generate_keypair()
append_entry(seq_commit="...", metadata={"length_bp": 500}, private_key=private_key)
```

```python
from verify import verify_log

print(verify_log("synthlog.jsonl", public_key))
# "OK, N entries, chain intact"  or  "TAMPER: <reason>"
```

Run the acceptance demo (appends 3 entries, then runs each attack from
`design.md` §11 and prints what `verify.py` catches):

```
python3 attack.py
```

Expected output once the crypto core is implemented:

```
append 3 entries            -> verify: OK
delete entry 2              -> verify: chain broken at 3
modify entry 1 metadata     -> verify: hash mismatch at 1
rewrite tail after modify   -> verify: signature invalid at 1
```

The last line is the core argument: an operator can recompute hashes to
make a tampered chain internally consistent, but cannot re-sign it.

## Open questions

Tracked in full in `design.md` §8. Highest priority right now:

1. Hash chain vs. Merkle tree/MMR for the log structure.
2. Salted vs. unsalted sequence commitment, and who would hold the nonce.
3. The sequence canonicalization rule (`canonical_sequence`) — not yet
   specified.
4. Which metadata fields are actually forensically meaningful.

## What this prototype does *not* claim

- **Not append-only in any enforced sense.** `synthlog.jsonl` is a plain
  file; nothing stops a root process from truncating or replacing it.
  Detecting *tampering* is strong; detecting *total deletion* is weaker and
  depends on external anchoring/witnessing not yet built. See `design.md` §7.
- **Not a confidentiality system.** `seq_commit` is presently an unsalted
  hash — binding but not hiding over DNA's small alphabet; a short sequence
  can be brute-forced by an adversary with candidate sequences to check
  against the log. See `design.md` §6.
- **Key storage is simulated, not hardware-enforced**, until the optional
  ATECC608 secure element (Month 2) lands.
