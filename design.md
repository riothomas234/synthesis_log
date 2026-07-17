# DESIGN.md — Tamper-Evident Local Synthesis Log

This file is the source of truth for the design. Code must conform to it.
When a decision changes, update this file — do not just change the code.

---

## 1. Purpose

Record DNA synthesis events into an append-only log such that any later
deletion, modification, reordering, or forgery of entries is **detectable**
by a verifier who does not trust the operator of the device.

This is an integrity / non-repudiation system, not a confidentiality system.
It does not screen sequences (cf. SecureDNA, which does). It proves that a
record of a synthesis event exists and has not been altered.

---

## 2. Threat model (summary — full version lives in the threat model doc)

**Primary adversary: the device operator.**
This is the distinguishing feature of the project. Unlike standard device
security, the adversary physically possesses the device *and* has an incentive
to tamper with its own records (audit avoidance, plausible deniability).

Adversary capabilities:
- Physical possession of the device.
- Root-level software access.
- May be able to reflash firmware.

Adversary limitations (assumptions the guarantees rest on):
- Cannot break SHA-256 (preimage / second-preimage / collision resistance).
- Cannot extract a private key held inside a secure element (SE).

Adversary goals, in order:
1. Delete a log entry (destroy record of a flagged synthesis).
2. Modify a log entry (change what sequence is recorded).
3. Insert a fake entry (confuse forensic reconstruction).
4. Roll the log back to an earlier state.
5. Clone another device's log and present it as this device's.

The design must make every one of these **detectable**. Note that
detectable ≠ preventable — see §9.

---

## 3. Cryptographic primitives

- **Hash:** SHA-256.
- **Signatures:** Ed25519 (fast, small keys, deterministic, well-understood).

Do not substitute these without updating this file and justifying the change.

---

## 4. Canonicalization

Everything that is hashed or signed must first pass through a single
canonicalization function. This is non-negotiable and load-bearing: if
serialization is not deterministic, hashes differ between write and verify
for reasons unrelated to tampering.

```python
import json

def canonical(obj: dict) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
```

There is a second, harder canonicalization problem specific to this domain:
the **sequence identifier**. The same biological sequence can be written in
multiple valid ways (case, line breaks, reverse complement, flanking regions,
modified bases). The sequence must be canonicalized *before* it is committed
to, or two identical syntheses will produce different commitments and the log
becomes gameable. The sequence-canonicalization rule is an OPEN QUESTION
(see §10) and is not yet fully specified.

---

## 5. Log entry structure

Each entry is a dict with exactly these fields:

| field       | meaning                                                        |
|-------------|-----------------------------------------------------------------|
| `index`     | monotonic counter, starts at 0                                 |
| `timestamp` | ISO 8601 UTC, e.g. "2026-07-13T14:22:01Z"                      |
| `seq_commit`| commitment to the synthesized sequence (see §8)                |
| `metadata`  | forensically relevant synthesis params (length, etc.)          |
| `leaf_hash` | this entry's hash as a Merkle tree leaf — see §6               |

An individual entry is **not signed on its own**. Chaining/commitment no
longer lives in the entry itself (there is no `prev_hash`); it comes from
the entry's position as a leaf in a Merkle tree instead (§6), and it is the
tree's *root* that gets signed, once per append, as part of a checkpoint
(§7) — not each entry individually.

This is a change from the original hash-chain design (`prev_hash` +
per-entry `entry_hash` + per-entry `signature`). See §10 item 1 for why, and
§6/§7 for the replacement structure.

---

## 6. Merkle tree structure

Entries are leaves of an RFC 6962-style Merkle tree. Two hash functions,
domain-separated with a one-byte prefix:

```
hash_leaf(data)        = SHA256(0x00 || data)
hash_node(left, right) = SHA256(0x01 || left || right)
```

### Why domain separation — BE EXACT

Without the `0x00`/`0x01` prefix, a leaf's hash and an internal node's hash
would come from the same input space — a node's input is `left || right`
(64 bytes), and nothing would stop that from colliding with, or being
mistaken for, some leaf's own 64-byte serialized content. This is the
classic Merkle tree **second-preimage weakness**: without domain
separation, an attacker can potentially forge a tree with the same root but
different structure or content. The prefix makes leaf hashes and node
hashes come from disjoint input spaces, closing this off by construction.
Get this wrong (e.g. hash leaves and nodes the same way) and the whole tree
stops being trustworthy, even if every other check is implemented
correctly.

A leaf's hash is computed as:

```
leaf_hash = hash_leaf(canonical({index, timestamp, seq_commit, metadata}))
```

### Root construction

The tree root over `n` leaf hashes is `MTH(D[n])`, RFC 6962's recursive
Merkle Tree Hash:

```
MTH({})       = SHA256("")                                   # empty tree
MTH({d(0)})   = d(0)                                          # single leaf
MTH(D[n])     = hash_node(MTH(D[0:k]), MTH(D[k:n]))            # n > 1
                where k = largest power of two strictly < n
```

This specific split rule (not a naive down-the-middle split) is what makes
the tree compatible with the standard RFC 6962 inclusion and consistency
proof algorithms, which assume this exact shape.

### Rebuild strategy — full rebuild per append

On every append, the tree is rebuilt **from scratch** from every leaf hash
currently in the log — O(n) work per append, not incremental. This is a
deliberate simplicity choice for this prototype: easy to reason about and
verify by hand, at the cost of redoing work on every append. A Merkle
Mountain Range (MMR) would make appends O(log n) instead by reusing
unaffected subtrees — that remains a deferred, known optimization (§10
item 1), not something this prototype implements.

### Inclusion and consistency proofs

`merkletree.py` also implements RFC 6962 inclusion proofs (prove one leaf
is in a tree of a given size/root, in O(log n) hashes, without seeing any
other leaf) and consistency proofs (prove an older, smaller tree is a
genuine append-only prefix of a newer, larger tree, without re-walking
every entry). These exist and are tested, but **are not yet wired into
`verify.py`'s actual audit flow** — see §10 item 1 and §12's footnote for
the current, simpler check `verify.py` actually performs. They're the
mechanism a future selective-disclosure workflow (e.g. "prove this one
synthesis event was logged, to this one regulator, without showing them
the rest of the log") would be built on.

---

## 7. Checkpoints

A checkpoint is a signed commitment to the entire tree's state at a given
size, written once per append (**sign every append** — no batching, no
periodic checkpoints; every append leaves the log immediately and
independently verifiable, same property the old per-entry signature used
to provide).

| field       | meaning                                                  |
|-------------|-----------------------------------------------------------|
| `tree_size` | number of leaves (entries) the root was computed over    |
| `root_hash` | `MTH(D[tree_size])` — see §6                              |
| `timestamp` | ISO 8601 UTC, same clock/caveats as an entry's timestamp  |
| `signature` | `Ed25519_sign(root_hash)` under the device-bound key      |

Checkpoints are stored separately from entries (`checkpoints.jsonl`, not
`synthlog.jsonl`) — a checkpoint is a different kind of record, not another
entry.

### What the signature covers — BE EXACT

The signature is over `root_hash` only — not the whole checkpoint dict, not
any individual entry. Because `root_hash` transitively commits to every
leaf beneath it (§6), one signature over it still commits to the entire log
at that size, the same role a chained entry's signature used to play under
the old design — but the commitment now comes from tree membership rather
than a `prev_hash` linked list. Do not sign the raw checkpoint dict; sign
the root hash.

---

## 8. Sequence commitment

```
seq_commit = SHA256(canonical_sequence)     # current baseline
```

Stores a commitment, not the sequence. This protects IP (the sequence is the
core IP of a biotech customer) and keeps storage small, while remaining
forensically useful: a regulator who later obtains a candidate sequence can
hash it and check whether this device produced it.

**KNOWN WEAKNESS (open):** a plain unsalted hash is *binding but not hiding*
over a small input space. DNA is a 4-letter alphabet; short sequences can be
brute-forced. An adversary can hash candidate sequences and match against the
log to learn what was synthesized.

Candidate fix: salted commitment `SHA256(nonce || canonical_sequence)` with
the nonce stored alongside. But then whoever holds the nonce can open the
commitment — and the operator is the adversary. Who holds the nonce is an
OPEN QUESTION (see §10). Baseline for now is unsalted; this must be revisited.

---

## 9. Detectable vs preventable

On this prototype, append-only is **assumed, not enforced**. The log is a
pair of files (`synthlog.jsonl`, `checkpoints.jsonl`) on a Raspberry Pi (or
Mac); the "append-only" property currently holds only because no deletion
code is written. This must be stated plainly in the write-up. It is not a
flaw to be hidden; it is a scoped limitation.

In production, append-only would be enforced by hardware:
- a write-once partition, or
- a TEE-protected storage area, or
- a secure element enforcing a monotonic counter.

The prototype **simulates** SE/TEE properties rather than implementing them.
The optional ATECC608 secure element (Month 2) demonstrates *real* key
non-extractability — a private key that physically cannot leave the chip —
which is the one property software alone cannot honestly show.

Detection of *tampering* (root mismatch, bad checkpoint signature) is
strong. Detection of *absence* (operator deletes the whole log, claims
device malfunction) is a different and weaker guarantee, and depends on
external anchoring / third-party witnessing. State where the design stands
on this.

---

## 10. Open questions (do not present these as settled)

1. **Log structure: hash chain vs Merkle tree / MMR — RESOLVED (Merkle
   tree).** Chosen because an operator being able to prove *one* synthesis
   event was logged, to a regulator, without revealing the other entries'
   commitments, is a real requirement (§6's inclusion proofs) — a plain
   hash chain can't do that. Root is signed on every append (§7);
   the tree is fully rebuilt on every append rather than maintained
   incrementally. **Still open:** whether to move to an incremental Merkle
   Mountain Range (MMR) as the log grows large enough that O(n)-per-append
   rebuilding becomes a real cost, and whether/when to start actually using
   the inclusion/consistency proof machinery that already exists in
   `merkletree.py` but isn't yet wired into `verify.py`'s audit flow.

2. **Salted vs unsalted sequence commitment**, and if salted, who holds the
   nonce given that the operator is the adversary (see §8).

3. **Sequence canonicalization rule** — the biological identifier problem
   (see §4). Needs input on what an investigator actually wants recorded.

4. **Which metadata fields are forensically meaningful** vs noise.

---

## 11. File plan

| file           | responsibility                                                  | who writes it |
|----------------|-------------------------------------------------------------------|---------------|
| `canonical.py` | dict → deterministic bytes (§4)                                 | **by hand**   |
| `merkletree.py`| Merkle tree construction, root computation, inclusion/consistency proofs (§6) | **by hand**   |
| `logentry.py`  | build a leaf's hash, sign a checkpoint's root; the crypto core (§5, §7) | **by hand**   |
| `log.py`       | append-only log + checkpoints; full tree rebuild per append      | agent OK      |
| `verify.py`    | auditor's tool; walk log, check root integrity + checkpoint signature | agent OK*   |
| `attack.py`    | corrupt a log/checkpoint file, run verify, report results table  | agent OK      |

\* `verify.py` must check **both**: (1) recomputing the tree from every
entry matches the last checkpoint's `root_hash` and `tree_size`, (2) that
checkpoint's signature is valid. A verifier that silently skips one is
worse than none. Read every line before trusting it.

Hand-written files (`canonical.py`, `merkletree.py`, `logentry.py`) are OFF
LIMITS to the coding agent. State this in every agent prompt.
`merkletree.py` earns this status for the same reason the other two do: a
subtle bug in tree/proof construction (e.g. missing domain separation, or
an unsound consistency-proof check — both mistakes actually made and
caught during this file's development) can silently defeat the whole
security property.

---

## 12. Outputs

- `synthlog.jsonl` — the append-only entry record (one entry per line).
- `checkpoints.jsonl` — the append-only checkpoint record (one signed
  checkpoint per line, one per append).
- verification report — verify.py output: "OK, N entries, root matches
  signed checkpoint" or "TAMPER: <reason>".
- attack results table — attack.py output; goes into the Week 7 write-up.

## 13. Acceptance demo

```
append 3 entries             -> verify: OK
delete entry 1                -> verify: tree size mismatch
modify entry 1 metadata       -> verify: root mismatch
modify + forge checkpoint     -> verify: signature invalid   <- the payoff
```

Note the shape of this changed from the original hash-chain version: delete
and modify used to be caught by two *different* checks (chain linkage vs.
hash integrity), so they had distinguishable error messages. In a Merkle
tree, any change to any entry changes the root, so both are now caught by
the *same* check — a deliberate tradeoff (§10 item 1, losing per-entry
localization in the report) in exchange for the tree's other properties.
The last line is still the core argument: the operator can recompute a
tampered tree's root correctly, but cannot forge the checkpoint's signature
over it, so cannot silently rewrite history.

---

## 14. Build order

1. `canonical.py` — then test it round-trips deterministically.
2. `merkletree.py` — leaf/node hashing, then root construction, then
   inclusion proofs, then consistency proofs. Test each stage against
   brute-force recomputation (positive cases) AND deliberately wrong
   inputs (negative cases) before moving to the next — the consistency
   proof implementation passed every positive test while still being
   unsound, twice, until adversarial testing caught it.
3. `logentry.py` — build one entry and one checkpoint, print them, eyeball
   the fields.
4. `log.py` — append 3 entries, look at both JSONL files by hand.
5. `verify.py` — run on the clean log, confirm it says OK.
6. `attack.py` — delete/modify an entry, watch verify break; then forge a
   checkpoint over the tampered tree and watch the signature check catch
   it — the "unsigned rewrite succeeds until the signature layer" moment
   that motivates the whole signing scheme.
