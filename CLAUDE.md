# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A tamper-evident append-only log for DNA synthesis events. It proves a
synthesis record existed and was not altered after the fact — it does not
screen sequences for danger (that's a different kind of tool, cf. SecureDNA).
The threat model is unusual: the adversary is the device operator, who has
physical/root access to the machine running the log but does not have the
Ed25519 private key. See `design.md` for the full design — it is the source
of truth; code must conform to it, not the other way around.

Log integrity is built on a Merkle tree over entries (RFC 6962-style), with
a signed checkpoint written on every append — not a hash chain. See
`design.md` §6/§7 for the structure and §10 item 1 for why.

## Off-limits files — read this before editing anything

`design.md` §11 draws a hard line between hand-written and agent-editable
files. This is not a stylistic preference:

- **`canonical.py`, `merkletree.py`, and `logentry.py` are OFF LIMITS to
  the coding agent.** Do not modify, "clean up," or fill in bodies in these
  files unless the user explicitly instructs otherwise in the moment. These
  are the crypto core, the tree/proof construction, and the one
  serialization chokepoint; the project's whole point is that the human
  understands and owns this code. `merkletree.py` earns this status for the
  same reason the other two do: a subtle bug in tree/proof construction
  (missing hash domain-separation, or an unsound consistency-proof check —
  both real mistakes made and caught during this file's development) can
  silently defeat the whole security property while looking correct on
  every "does a real proof verify" test.
- **`log.py`, `verify.py`, `attack.py` are agent-OK.**

`canonical_sequence()` (in `canonical.py`) remains deliberately
unimplemented — an open design question (see below), not a bug.

## Commands

```bash
pip install -r requirements.txt              # only dependency: cryptography (Ed25519)
python3 attack.py                             # acceptance demo: append 3 entries, run each
                                               # attack from design.md §13, print what
                                               # verify.py catches
python3 verify.py [path] [checkpoints_path]   # verify a log (defaults to synthlog.jsonl /
                                               # checkpoints.jsonl)
```

There is no test suite, linter, or build step configured — `attack.py`'s
acceptance demo is the closest thing to an integration test, and its
expected output is fixed in `design.md` §13:

```
append 3 entries             -> verify: OK
delete entry 1                -> verify: tree size mismatch
modify entry 1 metadata       -> verify: root mismatch
modify + forge checkpoint     -> verify: signature invalid   <- the payoff
```

The last line is the core argument of the whole project: an operator can
recompute a tampered tree's root correctly (they have root access, they can
run any hashing code that exists in the codebase), but cannot forge the
checkpoint's signature over that root without the private key — so a
"repaired" tree is still detectably forged.

Note the shape of this changed from the original hash-chain design's
acceptance demo: delete and modify used to be caught by two *different*
checks (chain linkage vs. hash integrity) with distinguishable messages. In
a Merkle tree, any change to any entry changes the root, so both are now
caught by the *same* check — a deliberate tradeoff (losing per-entry
localization in the report) documented in `design.md` §10 item 1 and §13.

## Architecture

Six files. Every write and every check funnels through the same chokepoints
— canonical serialization, tree construction, and signing — each owned by
exactly one file:

- **`canonical.py`** — the *only* dict→bytes serialization in the codebase.
  `canonical()` is fully specified (sorted keys, no whitespace, no ASCII
  escaping) and must never be duplicated elsewhere — a second
  `json.dumps()` call anywhere else would let write-time and verify-time
  bytes drift apart for reasons unrelated to tampering, silently breaking
  every hash check. `canonical_sequence()` (sequence normalization before
  hashing into `seq_commit`) is an intentionally unimplemented open design
  question — see `design.md` §4/§10.3.

- **`merkletree.py`** — Merkle tree construction (RFC 6962-style). Two
  domain-separated hash functions, `hash_leaf(data) = SHA256(0x00||data)`
  and `hash_node(l,r) = SHA256(0x01||l||r)` — the domain separation is the
  single most important correctness detail here (`design.md` §6): without
  it, a leaf's hash and an internal node's hash share an input space,
  opening a second-preimage forgery. `compute_root` builds the tree's root
  via RFC 6962's recursive `MTH(D[n])` (split at the largest power of two
  `< n`); the tree is fully rebuilt from every leaf on each append (no
  incremental MMR yet — a deferred optimization, `design.md` §10 item 1).
  Also implements RFC 6962 inclusion proofs (prove one leaf is in a tree
  without seeing the rest) and consistency proofs (prove an older tree is
  a genuine append-only prefix of a newer one) — both exist and are
  tested, but are **not yet wired into `verify.py`'s audit flow**, which
  currently does a full recompute instead (`design.md` §6, §10 item 1).

- **`logentry.py`** — the crypto core. Builds one entry's leaf hash:
  `leaf_hash = hash_leaf(canonical({index, timestamp, seq_commit, metadata}))`
  (`compute_leaf_hash`), and signs a checkpoint's root:
  `signature = Ed25519_sign(root_hash)` (`sign_root`/`build_checkpoint`).
  Individual entries are **not signed**; only the tree root is, once per
  append (`design.md` §7 — "sign every append"). `leaf_hash`/`root_hash`/
  `signature` are hex-encoded when persisted — `verify.py` assumes hex via
  `.hex()`/`bytes.fromhex()`; changing the encoding means updating both
  files. Also owns key management (`generate_keypair`, `load_public_key`)
  — unaffected by the chain→tree change, PEM-encoded, unencrypted at rest
  (see the function's own docstring for why that's a deliberate choice
  given the threat model, not an oversight).

- **`log.py`** — append-only JSONL storage, two files. Pure plumbing: on
  each `append_entry` call, writes the new entry to `synthlog.jsonl` (via
  `logentry.build_entry`), then rebuilds the *entire* tree from every entry
  now on disk (`merkletree.compute_root`), signs a fresh checkpoint over
  that root (`logentry.build_checkpoint`), and appends it to
  `checkpoints.jsonl`. Contains no cryptographic logic itself. Note:
  append-only is *assumed*, not enforced — these are ordinary files on a
  normal filesystem (`design.md` §9); nothing here should ever add
  file-locking or permission tricks that would misrepresent that as a real
  guarantee.

- **`verify.py`** — the auditor's tool. Runs two independent checks, in a
  fixed order, each raising `TamperDetected` with a specific reason:
  1. `check_root_integrity` — checks `tree_size` first (cheap), then
     recomputes every entry's leaf hash and the whole tree's root, and
     compares to the last checkpoint's `root_hash` (catches deletion,
     edit, reorder, or insertion — any change to any entry changes the
     root, so one check now covers what used to take two).
  2. `check_signature` — verifies the checkpoint's Ed25519 signature over
     its own `root_hash` under a caller-supplied public key (catches a
     tree that was correctly "repaired" in content but couldn't be
     re-signed — the payoff check).

  Both must run; a verifier that silently skips one is worse than none.
  `check_signature` takes `public_key` as a parameter rather than loading
  it from the log itself — the auditor's trusted key must come from an
  out-of-band source, or the check becomes circular.

- **`attack.py`** — adversarial test harness playing the operator-adversary
  role: full filesystem access to both JSONL files, no private key.
  Deliberately reads/writes the files directly with plain `json` rather
  than going through `log.py`'s API, because a real attacker doesn't get to
  use the honest append path. `attack_forge_checkpoint` is the key
  scenario: it recomputes the correct new root for a tampered set of
  entries (which an operator with root *can* do) but leaves the old
  `signature` in place, since it's valid for the old root and not the new
  one (which they can't fix without the private key) — that mismatch is
  what `check_signature` catches.

**Data flow:** `log.append_entry` → writes an entry via `logentry.build_entry`
(→ `compute_leaf_hash` → `canonical.canonical` → `merkletree.hash_leaf`) →
rebuilds the tree via `merkletree.compute_root` → signs a checkpoint via
`logentry.build_checkpoint` (→ `sign_root`) → two JSONL lines (one per
file). `verify.verify_log` reads both files and independently reruns the
hash side of that pipeline (never the signing side — it only ever verifies)
against a trusted public key.

## Known open design questions

Documented in full in `design.md` §10; keep these in mind before "fixing"
something that looks incomplete:

1. Hash chain vs. Merkle tree/MMR — **resolved: Merkle tree** (this repo's
   current state). Still open within that: moving to an incremental MMR as
   the log grows large enough that full-rebuild-per-append becomes costly,
   and when/whether to start actually using the inclusion/consistency proof
   machinery already built in `merkletree.py`.
2. Salted vs. unsalted `seq_commit` — currently unsalted, which is binding
   but not hiding over DNA's small alphabet (brute-forceable for short
   sequences). Salting requires deciding who holds the nonce, given the
   operator is the adversary.
3. `canonical_sequence()` — not yet specified (see above).
4. Which metadata fields are actually forensically meaningful.

Also note: key storage in `generate_keypair()` is simulated (a key in a
file is extractable by this project's own adversary); true
non-extractability is deferred to an optional ATECC608 secure element
(Month 2), not part of this prototype.
