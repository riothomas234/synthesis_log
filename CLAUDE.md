# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A tamper-evident append-only log for DNA synthesis events. It proves a
synthesis record existed and was not altered after the fact — it does not
screen sequences for danger (that's a different kind of tool, cf. SecureDNA).
The threat model is unusual: the adversary is the device operator, who has
physical/root access to the machine running the log but does not have the
device's Ed25519 signing private key, nor the auditor's X25519 decryption
private key. See `design.md` for the full design — it is the source of
truth; code must conform to it, not the other way around.

Log integrity is built on a Merkle tree over entries (RFC 6962-style), with
a signed checkpoint written on every append — not a hash chain. See
`design.md` §6/§7 for the structure and §10 item 1 for why. Sequence
confidentiality is separate from that integrity mechanism: each entry's
sequence is stored only as `seq_ciphertext`, encrypted to an auditor-held
key the device never possesses — see `design.md` §8.

## Off-limits files — read this before editing anything

`design.md` §11 draws a hard line between hand-written and agent-editable
files. This is not a stylistic preference:

- **`canonical.py`, `merkletree.py`, `sequence_crypto.py`, and
  `logentry.py` are OFF LIMITS to the coding agent.** Do not modify,
  "clean up," or fill in bodies in these files unless the user explicitly
  instructs otherwise in the moment. These are the crypto core, the
  tree/proof construction, the sequence-encryption module, and the one
  serialization chokepoint; the project's whole point is that the human
  understands and owns this code. `merkletree.py` and `sequence_crypto.py`
  earn this status for the same reason `canonical.py`/`logentry.py` do: a
  subtle bug (missing hash domain-separation, an unsound consistency-proof
  check, a reused nonce/key in the encryption assembly — all real classes
  of mistake, some actually made and caught during this project's
  development) can silently defeat the whole security property while
  looking correct on every "does it work" test.
- **`log.py`, `verify.py`, `attack.py` are agent-OK.**

`canonical_sequence()` (in `canonical.py`) is now implemented: uppercase,
strip whitespace, validate against the IUPAC nucleotide alphabet, keep
ambiguity/degenerate codes as-is, do not collapse reverse complement. See
`design.md` §10 item 2.

## Commands

```bash
pip install -r requirements.txt              # only dependency: cryptography
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
append 3 entries               -> verify: OK
delete entry 1                 -> verify: tree size mismatch
modify entry 1 metadata        -> verify: root mismatch
swap entry 1 ciphertext        -> verify: root mismatch
modify + forge checkpoint      -> verify: signature invalid   <- the payoff
```

The last line is the core argument of the whole project: an operator can
recompute a tampered tree's root correctly (they have root access, they can
run any hashing code that exists in the codebase, and they hold the
auditor's *public* encryption key so they can even produce valid-looking
ciphertext), but cannot forge the checkpoint's signature over that root
without the device's private signing key — so a "repaired" tree is still
detectably forged.

Note the shape of this changed from the original hash-chain design's
acceptance demo: delete and modify used to be caught by two *different*
checks (chain linkage vs. hash integrity) with distinguishable messages. In
a Merkle tree, any change to any entry changes the root, so delete, modify,
and ciphertext-swap are all now caught by the *same* check — a deliberate
tradeoff (losing per-entry localization in the report) documented in
`design.md` §10 item 1 and §13. The "swap entry 1 ciphertext" row exists
specifically to confirm `seq_ciphertext` being opaque doesn't make it a
blind spot for that check.

## Architecture

Seven files. Every write and every check funnels through the same
chokepoints — canonical serialization, tree construction, sequence
encryption, and signing — each owned by exactly one file:

- **`canonical.py`** — the *only* dict→bytes serialization in the codebase.
  `canonical()` is fully specified (sorted keys, no whitespace, no ASCII
  escaping) and must never be duplicated elsewhere — a second
  `json.dumps()` call anywhere else would let write-time and verify-time
  bytes drift apart for reasons unrelated to tampering, silently breaking
  every hash check. `canonical_sequence()` (sequence normalization before
  it's encrypted) is now resolved: uppercase, strip whitespace, validate
  against the IUPAC nucleotide alphabet, keep ambiguity codes as-is, don't
  collapse reverse complement — see `design.md` §4/§10.2.

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

- **`sequence_crypto.py`** — sequence confidentiality, entirely separate
  from `logentry.py`'s signing keypair. A second X25519 keypair belonging
  to the **auditor**, not the device — the device only ever holds the
  auditor's *public* key (provisioned out-of-band, same idea as the
  auditor getting the device's public signing key out-of-band for
  `verify.py`), and can encrypt but never decrypt. `encrypt_sequence`
  hybrid-encrypts (fresh ephemeral X25519 keypair per call → HKDF-SHA256 →
  AESGCM) so the same sequence encrypts to different ciphertext every
  time — load-bearing, since the auditor's public key isn't secret, and
  deterministic encryption would let anyone brute-force guess candidate
  sequences by re-encrypting and comparing (`design.md` §8).
  `decrypt_sequence` is auditor-side only; the device's own code never
  calls it.

- **`logentry.py`** — the crypto core. Builds one entry's leaf hash:
  `leaf_hash = hash_leaf(canonical({index, timestamp, seq_ciphertext, metadata}))`
  (`compute_leaf_hash`), encrypts a raw sequence via
  `sequence_crypto.encrypt_sequence` (`build_entry` — the only place a raw
  sequence is ever handled; it's consumed into `seq_ciphertext` and never
  written anywhere in its own right), and signs a checkpoint's root:
  `signature = Ed25519_sign(root_hash)` (`sign_root`/`build_checkpoint`).
  Individual entries are **not signed**; only the tree root is, once per
  append (`design.md` §7 — "sign every append"). `leaf_hash`/`root_hash`/
  `signature`/`seq_ciphertext` are hex-encoded when persisted — `verify.py`
  assumes hex via `.hex()`/`bytes.fromhex()`; changing the encoding means
  updating both files. Also owns the *device's* key management
  (`generate_keypair`, `load_public_key`) — PEM-encoded, unencrypted at
  rest (see the function's own docstring for why that's a deliberate
  choice given the threat model, not an oversight). Note this is a
  *different* keypair from `sequence_crypto.py`'s auditor keypair —
  different algorithm (Ed25519 vs. X25519), different purpose (signing vs.
  encryption), different owner (device vs. auditor).

- **`log.py`** — append-only JSONL storage, two files. Pure plumbing:
  `append_entry` now takes `raw_sequence` and `auditor_public_key` (not a
  pre-made `seq_commit`) and threads both straight through to
  `logentry.build_entry` without inspecting either — it never sees a raw
  sequence as anything other than an opaque parameter. Writes the new
  entry to `synthlog.jsonl`, rebuilds the *entire* tree from every entry
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
     edit, reorder, insertion, or a swapped `seq_ciphertext` — any change
     to any entry changes the root). Never decrypts anything — it just
     re-hashes whatever `seq_ciphertext` bytes are already stored, same as
     any other field.
  2. `check_signature` — verifies the checkpoint's Ed25519 signature over
     its own `root_hash` under a caller-supplied public key (catches a
     tree that was correctly "repaired" in content but couldn't be
     re-signed — the payoff check).

  Both must run; a verifier that silently skips one is worse than none.
  `check_signature` takes `public_key` as a parameter rather than loading
  it from the log itself — the auditor's trusted key must come from an
  out-of-band source, or the check becomes circular.

- **`attack.py`** — adversarial test harness playing the operator-adversary
  role: full filesystem access to both JSONL files, the auditor's *public*
  encryption key (provisioned to the device, not secret), no device
  private signing key, no auditor private decryption key. Deliberately
  reads/writes the files directly with plain `json` rather than going
  through `log.py`'s API, because a real attacker doesn't get to use the
  honest append path. `attack_swap_ciphertext` demonstrates the operator
  can produce *valid* ciphertext (they have the public key to encrypt
  with) for the *wrong* content, and it's still caught by
  `check_root_integrity` like any other field tamper.
  `attack_forge_checkpoint` is the key scenario: it recomputes the correct
  new root for a tampered set of entries (which an operator with root
  *can* do) but leaves the old `signature` in place, since it's valid for
  the old root and not the new one (which they can't fix without the
  private key) — that mismatch is what `check_signature` catches.

**Data flow:** `log.append_entry` → `logentry.build_entry` (→
`sequence_crypto.encrypt_sequence` for `seq_ciphertext` → `compute_leaf_hash`
→ `canonical.canonical` → `merkletree.hash_leaf`) → rebuilds the tree via
`merkletree.compute_root` → signs a checkpoint via `logentry.build_checkpoint`
(→ `sign_root`) → two JSONL lines (one per file). `verify.verify_log` reads
both files and independently reruns the hash side of that pipeline (never
the signing side, never the decryption side — it only ever verifies)
against a trusted public key.

## Known open design questions

Documented in full in `design.md` §10; keep these in mind before "fixing"
something that looks incomplete:

1. Hash chain vs. Merkle tree/MMR — **resolved: Merkle tree** (this repo's
   current state). Still open within that: moving to an incremental MMR as
   the log grows large enough that full-rebuild-per-append becomes costly,
   and when/whether to start actually using the inclusion/consistency proof
   machinery already built in `merkletree.py`.
2. Sequence canonicalization — **resolved** (see above): uppercase, strip
   whitespace, validate against the IUPAC nucleotide alphabet, keep
   ambiguity codes as-is, don't collapse reverse complement. Still open:
   this only partially closes the "resubmit in a cosmetically different
   form" laundering concern — it doesn't address the reverse-complement
   case, which would need a separate cross-check elsewhere if wanted.
3. Which metadata fields are actually forensically meaningful.
4. Auditor key management/recovery — there is deliberately no backup or
   escrow path for the auditor's private decryption key; losing it
   permanently forfeits every historical sequence's plaintext (tamper
   evidence itself is unaffected). Whether that's acceptable as-is is
   unresolved (`design.md` §8/§10 item 4).

Also note: key storage in `generate_keypair()`/`generate_auditor_keypair()`
is simulated (a key in a file is extractable by this project's own
adversary, for the device's signing key; the auditor's own system security
is outside this project's threat model entirely); true non-extractability
for the device's signing key is deferred to an optional ATECC608 secure
element (Month 2), not part of this prototype.
