# DESIGN.md — Tamper-Evident Local Synthesis Log

This file is the source of truth for the design. Code must conform to it.
When a decision changes, update this file — do not just change the code.

---

## 1. Purpose

Record DNA synthesis events into an append-only log such that any later
deletion, modification, reordering, or forgery of entries is **detectable**
by a verifier who does not trust the operator of the device.

This is an integrity / non-repudiation system. It does not screen
sequences (cf. SecureDNA, which does). It proves that a record of a
synthesis event exists and has not been altered — and, since §8's
encryption design, it also lets an authorized auditor recover the actual
sequence for function screening and forensic matching, while keeping it
unreadable to anyone else who might obtain the log or the device.

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
- Has the auditor's PUBLIC encryption key (it's provisioned to the device,
  not secret — see §8) — so they can produce valid-*looking* ciphertext,
  just never decrypt anything or forge a signature.

Adversary limitations (assumptions the guarantees rest on):
- Cannot break SHA-256 (preimage / second-preimage / collision resistance).
- Cannot extract a private key held inside a secure element (SE).
- Does not have the auditor's PRIVATE decryption key — that key never
  touches the device at all (§8).

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
- **Sequence encryption:** X25519 (key exchange) + HKDF-SHA256 (key
  derivation) + AES-GCM (authenticated bulk encryption) — see §8.

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
multiple valid ways (case, line breaks, flanking regions). The sequence must
be canonicalized *before* it is encrypted, or two identical syntheses will
produce unrelated ciphertext with no way to recognize they represent the same
underlying sequence later. Resolved per §10 item 2: uppercase, strip
whitespace, validate against the IUPAC nucleotide alphabet, keep ambiguity
codes as-is, do not collapse reverse complement — see `canonical.py`'s
`canonical_sequence`.

---

## 5. Log entry structure

Each entry is a dict with exactly these fields:

| field           | meaning                                                    |
|-----------------|--------------------------------------------------------------|
| `index`         | monotonic counter, starts at 0                              |
| `timestamp`     | ISO 8601 UTC, e.g. "2026-07-13T14:22:01Z"                   |
| `seq_ciphertext`| the synthesized sequence, encrypted to the auditor's public key (see §8) |
| `metadata`      | forensically relevant synthesis params (length, etc.)       |
| `leaf_hash`     | this entry's hash as a Merkle tree leaf — see §6             |

An individual entry is **not signed on its own**. Chaining/commitment does
not live in the entry itself (there is no `prev_hash`); it comes from the
entry's position as a leaf in a Merkle tree instead (§6), and it is the
tree's *root* that gets signed, once per append, as part of a checkpoint
(§7) — not each entry individually.

Earlier versions of this design stored `seq_commit` (a hash-based
commitment to the sequence) instead of `seq_ciphertext`. That field is
retired, not kept alongside encryption — see §8 for why.

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
leaf_hash = hash_leaf(canonical({index, timestamp, seq_ciphertext, metadata}))
```

`seq_ciphertext` feeds into this exactly like every other field — routine
tamper-checking never needs to decrypt anything to catch tampering with it;
it just re-hashes whatever ciphertext bytes are already stored, same as any
other field.

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
the current, simpler check `verify.py` actually performs.

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

## 8. Sequence confidentiality

The raw sequence is **never persisted anywhere** — not in `synthlog.jsonl`,
not in any other file this project writes. It exists only transiently, in
memory, for the duration of one `logentry.build_entry` call, long enough to
derive `seq_ciphertext` — nothing assigns it anywhere that gets written to
disk.

`seq_ciphertext` is a hybrid encryption of the sequence to a **second,
separate keypair** from the device's Ed25519 signing key — X25519, held by
the **auditor**, not the device:

```
seq_ciphertext = ephemeral_public_key || nonce || AESGCM_encrypt(
    key = HKDF(X25519_exchange(ephemeral_private_key, auditor_public_key)),
    plaintext = canonical_sequence(raw_sequence),
)
```

A fresh ephemeral X25519 keypair is generated on every single call — this
is what makes the encryption non-deterministic (semantically secure):
encrypting the identical sequence twice produces completely different
ciphertext both times. This is load-bearing: the auditor's public key is
provisioned to the device and is not secret (see §2's adversary
capabilities), so if encryption were deterministic, anyone holding it could
brute-force guess candidate sequences by re-encrypting them and comparing
ciphertext — exactly the attack a salted hash commitment would need to
defend against, except here it's defeated for free by the construction,
rather than needing a manually-managed secret nonce.

**Key asymmetry, important to get right:** the device never generates or
holds this keypair. The auditor generates it, on their own system; only the
public half is ever provisioned to the device (out-of-band, analogous to
how the auditor already receives the device's public *signing* key
out-of-band for `verify.py`). The device can encrypt; it can never decrypt
anything it has logged. Full detail in `sequence_crypto.py`.

The auditor decrypts `seq_ciphertext` for every sequence-level need
uniformly — candidate confirmation, partial-sequence forensic matching, and
function screening alike — since all three require the real plaintext, and
no hash-based shortcut can ever provide that.

### History: `seq_commit`, retired

An earlier version of this design stored `seq_commit = SHA256(canonical_sequence)`
— a one-way commitment, not a decryptable ciphertext — specifically so a
party *without* decrypt access could check a known candidate sequence
against the log. That capability doesn't have a remaining beneficiary in
this design: the auditor always holds the decryption key, so every
legitimate use of sequence content already goes through decryption. Keeping
`seq_commit` alongside `seq_ciphertext` would have been redundant field
duplication with no one left to serve. Retiring it also retires the
salt/nonce-custody question that used to be open here (see §10) — there's
no hash commitment left to brute-force, so nothing needs salting.

### Open risk, stated plainly

**Auditor private-key loss is catastrophic and irreversible for historical
data.** There is deliberately no second copy of any sequence's plaintext,
and no escrow path. If the auditor's private key is lost, every previously
logged sequence becomes permanently unrecoverable — the tamper-evidence
guarantees (§6/§7) are unaffected (the log still proves *something* was
recorded and hasn't been altered), but the actual sequence content is gone
for good. This is a real operational risk worth planning key-management
practices around, not a defect to quietly work around later.

---

## 9. Detectable vs preventable

On this prototype, append-only is **assumed, not enforced**. The log is a
pair of files (`synthlog.jsonl`, `checkpoints.jsonl`) on a Raspberry Pi (or
Mac); the "append-only" property currently holds only because no deletion
code is written. This must be stated plainly in the write-up. It is not a
flaw to be hidden; it is a scoped limitation.

### TPM-backed rollback evidence

The hardware design uses a TPM NV extend index as a content-bound,
append-only accumulator. This is distinct from the entry's software `index`:
an integer counter establishes ordering, while an extend accumulator commits
to the ordered checkpoint contents.

For checkpoint `i`, compute:

```
checkpoint_commitment_i = SHA256(canonical({
    "type": "synthesis-log-checkpoint-v1",
    "tree_size": i,
    "root_hash": root_hash_i,
}))

A_i = SHA256(A_(i-1) || checkpoint_commitment_i)
```

`A_i` is the value produced by `TPM2_NV_Extend`; it is not computed and
written directly by host software. The auditor recomputes the same accumulator
from the presented checkpoints and compares it with a TPM certification of the
NV index.

Provisioning is part of the guarantee. The externally retained provisioning
record must bind the machine identity to:

- the exact TPM attestation public key, Name, and qualified Name;
- the NV index handle, Name, public attributes, and initial value `A_0`;
- an NV extend policy that permits extension but not deletion or arbitrary
  writes; and
- the device signing key and auditor encryption public key used by this log.

The NV index must be platform-created and configured for policy deletion such
that neither the device operator nor normal host software can authorize
`TPM2_NV_UndefineSpaceSpecial`. Owner, index-password, and arbitrary-write
authorization must not provide alternate deletion or write paths. Platform
hierarchy authorization must not be stored on the device. TPM clear must be
disabled where supported, and the platform-created index must survive an owner
clear. A destructive reset or TPM replacement is accepted only as a detectable
device reprovisioning event, never as continuation of the old log identity.
The deletion policy should use `PolicySigned` under an offline auditor key,
with a fresh session nonce and command-parameter hash binding authorization to
the intended `TPM2_NV_UndefineSpaceSpecial` invocation. This remains
recoverably deletable by the auditor; an unsatisfiable policy is unnecessary.

Platform authorization is a provisioning prerequisite, not an ordinary host
credential. If system firmware withholds it from the operating system, host
software cannot create the required index and the machine supports only the
mutable demonstration unless an OEM or firmware provisioning path is added.
Falling back to an owner-created index would silently remove the root-resistant
deletion guarantee and is forbidden for a production enrollment.

For an audit, the auditor sends a fresh unpredictable nonce. The device returns
`TPM2_NV_Certify` attestation data covering the accumulator's current NV value,
with the nonce included as qualifying data, plus the TPM's signature. The
auditor verifies all of the following:

1. The signature is from the attestation key in the provisioning record.
2. The returned nonce equals the challenge nonce.
3. The certified NV Name and attributes match the provisioned index.
4. Recomputing the accumulator from `A_0` and every presented checkpoint
   produces the certified current value.
5. Every checkpoint `i`'s `root_hash` equals the Merkle root of the first `i`
   presented log entries. Step 4 binds the checkpoint history to the TPM but
   never reads entries; this step binds entries to that history. Without it,
   an operator with signing-oracle access could delete an already-extended
   entry, sign and extend one new checkpoint for the altered log, and pass
   step 4 and the last-checkpoint root and signature checks, because the
   genuine earlier checkpoints remain in place.

Under these assumptions, replacing the log with an earlier prefix cannot pass
a live audit: the old prefix recomputes an old accumulator value, while the TPM
certifies its later value. Replaying an earlier certification also fails
because it does not contain the fresh nonce. Rewriting, omitting, reordering,
or forking already-extended checkpoints likewise produces an accumulator that
does not match the certified value. Once one branch has been extended, the TPM
cannot return to the predecessor value to certify a sibling branch.

This mechanism does not prove that every physical synthesis reached the
logging software. A hostile host can omit an event before extension, extend a
false checkpoint, advance the TPM to cause denial of service, or stop
responding. Closing that capture gap requires trusted hardware on the physical
synthesis path. An auditor that cannot issue a live challenge also needs an
external witness to establish currentness.

The optional TPM append path uses a durable pending journal because a file
append and an NV extend cannot be one atomic operation. Before extending, it
records the exact entry and checkpoint bytes, both files' lengths and prefix
hashes, and the expected accumulator values before and after the extend. On
recovery, the recorded before value permits the one required extend; the after
value permits completion of missing or partial file writes without a second
extend. Any other TPM value or unexpected file content fails closed. A process
lock serializes honest writers but is not considered a defense against root.

TPM mode is optional at provisioning. A software-only log retains the base
Merkle and checkpoint behavior. Once a run is TPM-enrolled, TPM failure,
missing hardware, an unexpected NV Name, or an accumulator mismatch aborts an
append; the implementation never silently falls back to software-only mode.

The mutable prototype uses an owner-created index so it can be repeatedly
tested and removed. That configuration demonstrates command integration and
crash recovery, not resistance to a root operator who can undefine the index.
The production guarantee requires the platform-created deletion policy above.
A secure element or TPM-held device signing key additionally provides real key
non-extractability. Non-extractability authenticates the hardware that signed a
value, but does not by itself prove that approved software requested the
signature or that every synthesis was logged.

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

2. **Sequence canonicalization rule — RESOLVED.** Case-fold to uppercase,
   strip all whitespace/newlines, validate against the 16-symbol IUPAC
   nucleotide alphabet (reject anything else). Ambiguity/degenerate codes
   (`N`, `K`, an `NNK` codon, etc.) are kept as-is rather than expanded or
   rejected — they're a legitimate, common synthesis order (mixed-base
   oligo pools for library construction), not sequencing uncertainty;
   realizing the actual randomness happens downstream of this log, which
   only commits to the order spec as submitted. Reverse complement is
   *not* collapsed — two RC-equivalent sequences canonicalize to two
   different strings, since RC is a biologically meaningful difference in
   what was submitted, not a cosmetic one like case/whitespace. **Still
   open:** this leaves the "resubmit in a cosmetically different form"
   laundering concern from §4 only partially closed for the RC case — a
   dedicated RC cross-check, if wanted, would live elsewhere, not in this
   function. See `canonical.py`'s `canonical_sequence`.

3. **Which metadata fields are forensically meaningful** vs noise.

4. **Auditor key management and recovery** (see §8's "open risk"). No
   backup or escrow path currently exists for the auditor's private key;
   losing it permanently forfeits every historical sequence's plaintext.
   Whether that's acceptable, or whether some form of key backup/escrow is
   needed (and who would hold it, given the same "who do you trust"
   tension salting used to raise), is unresolved.

(Formerly item 2 here: salted vs. unsalted `seq_commit`. Retired along with
`seq_commit` itself — see §8 — there is no longer a hash commitment to
salt.)

---

## 11. File plan

| file               | responsibility                                                | who writes it |
|--------------------|------------------------------------------------------------------|---------------|
| `canonical.py`     | dict → deterministic bytes (§4)                                | **by hand**   |
| `merkletree.py`    | Merkle tree construction, root computation, inclusion/consistency proofs (§6) | **by hand**   |
| `sequence_crypto.py` | auditor keypair + hybrid encrypt/decrypt of sequences (§8)   | **by hand**   |
| `logentry.py`      | build a leaf's hash, encrypt a sequence, sign a checkpoint's root; the crypto core (§5, §7, §8) | **by hand** |
| `log.py`           | append-only log + checkpoints; full tree rebuild per append      | agent OK      |
| `verify.py`        | auditor's tool; walk log, check root integrity + checkpoint signature | agent OK*  |
| `attack.py`        | corrupt a log/checkpoint file, run verify, report results table  | agent OK      |

\* `verify.py` must check **both**: (1) recomputing the tree from every
entry matches the last checkpoint's `root_hash` and `tree_size`, (2) that
checkpoint's signature is valid. A verifier that silently skips one is
worse than none. Read every line before trusting it. Note `verify.py`
never decrypts anything — routine verification only ever re-hashes
`seq_ciphertext`, the same as any other field.

Hand-written files (`canonical.py`, `merkletree.py`, `sequence_crypto.py`,
`logentry.py`) are OFF LIMITS to the coding agent. State this in every
agent prompt. `merkletree.py` and `sequence_crypto.py` earn this status for
the same reason `canonical.py`/`logentry.py` do: subtle bugs in tree/proof
construction or in the encryption assembly (missing domain separation, an
unsound consistency-proof check, reused nonces/keys — all real classes of
mistake, some actually made and caught during this project's development)
can silently defeat the whole security property.

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
append 3 entries               -> verify: OK
delete entry 1                 -> verify: tree size mismatch
modify entry 1 metadata        -> verify: root mismatch
swap entry 1 ciphertext        -> verify: root mismatch
modify + forge checkpoint      -> verify: signature invalid   <- the payoff
```

Note the shape of this changed from the original hash-chain version: delete
and modify used to be caught by two *different* checks (chain linkage vs.
hash integrity), so they had distinguishable error messages. In a Merkle
tree, any change to any entry changes the root, so all of delete/modify/
ciphertext-swap are now caught by the *same* check — a deliberate tradeoff
(§10 item 1, losing per-entry localization in the report) in exchange for
the tree's other properties.

The fourth row (swap entry 1 ciphertext) exists specifically to
demonstrate that `seq_ciphertext` being opaque doesn't make it a blind
spot: the operator has the auditor's public key (§8) and can produce
perfectly *valid* ciphertext, just not ciphertext that reproduces the
original `leaf_hash` without knowing what was actually encrypted inside
it. Caught the same way a metadata edit is.

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
3. `sequence_crypto.py` — hybrid encrypt/decrypt, tested standalone
   (round-trip correctness; confirm two encryptions of the same sequence
   produce different ciphertext; confirm tampering and wrong-key
   decryption both fail loudly) before anything else depends on it.
4. `logentry.py` — build one entry and one checkpoint, print them, eyeball
   the fields.
5. `log.py` — append 3 entries, look at both JSONL files by hand; confirm
   no plaintext sequence appears anywhere in either file.
6. `verify.py` — run on the clean log, confirm it says OK.
7. `attack.py` — delete/modify/swap-ciphertext an entry, watch verify
   break each way; then forge a checkpoint over the tampered tree and
   watch the signature check catch it — the "unsigned rewrite succeeds
   until the signature layer" moment that motivates the whole signing
   scheme.
