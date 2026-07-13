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
detectable ≠ preventable — see §7.

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
and the chain "breaks" for reasons unrelated to tampering.

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
(see §8) and is not yet fully specified.

---

## 5. Log entry structure

Each entry is a dict with exactly these fields, in this conceptual order:

| field       | meaning                                                        |
|-------------|----------------------------------------------------------------|
| `index`     | monotonic counter, starts at 0                                 |
| `timestamp` | ISO 8601 UTC, e.g. "2026-07-13T14:22:01Z"                      |
| `seq_commit`| commitment to the synthesized sequence (see §6)               |
| `metadata`  | forensically relevant synthesis params (length, etc.)          |
| `prev_hash` | `entry_hash` of the previous entry ("" or null for index 0)   |
| `entry_hash`| `SHA256(canonical({all fields above except signature}))`      |
| `signature` | `Ed25519_sign(entry_hash)` under the device-bound key         |

Two fields carry the security:
- `prev_hash` makes it a **chain** — deletion/modification/reorder breaks linkage.
- `signature` stops the operator **rewriting** the chain — they can recompute
  hashes, but cannot forge signatures without the private key.

### What the signature covers — BE EXACT

The signature is over `entry_hash`, and `entry_hash` is computed over the
canonical serialization of every field **except** `signature` itself.
Because `entry_hash` already includes `prev_hash`, the signature transitively
commits to the entire prior chain. Do not sign the raw dict; sign the hash.

---

## 6. Sequence commitment

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
OPEN QUESTION (see §8). Baseline for now is unsalted; this must be revisited.

---

## 7. Detectable vs preventable

On this prototype, append-only is **assumed, not enforced**. The log is a file
on a Raspberry Pi (or Mac); the "append-only" property currently holds only
because no deletion code is written. This must be stated plainly in the
write-up. It is not a flaw to be hidden; it is a scoped limitation.

In production, append-only would be enforced by hardware:
- a write-once partition, or
- a TEE-protected storage area, or
- a secure element enforcing a monotonic counter.

The prototype **simulates** SE/TEE properties rather than implementing them.
The optional ATECC608 secure element (Month 2) demonstrates *real* key
non-extractability — a private key that physically cannot leave the chip —
which is the one property software alone cannot honestly show.

Detection of *tampering* (broken chain, bad signature) is strong.
Detection of *absence* (operator deletes the whole log, claims device
malfunction) is a different and weaker guarantee, and depends on external
anchoring / third-party witnessing. State where the design stands on this.

---

## 8. Open questions (do not present these as settled)

1. **Log structure: hash chain vs Merkle tree / MMR.**
   Hinges on whether an operator must prove *one* synthesis event was logged,
   to a regulator, without revealing the other entries' commitments. If yes →
   inclusion proofs needed → Merkle family (O(log n) proofs, selective
   disclosure). If no → a plain hash chain is simpler and correct.
   Hash-chain verification is O(n); Merkle inclusion/consistency proofs are
   O(log n). This is currently the highest-priority structural decision.

2. **Salted vs unsalted sequence commitment**, and if salted, who holds the
   nonce given that the operator is the adversary (see §6).

3. **Sequence canonicalization rule** — the biological identifier problem
   (see §4). Needs input on what an investigator actually wants recorded.

4. **Which metadata fields are forensically meaningful** vs noise.

---

## 9. File plan

| file          | responsibility                                        | who writes it |
|---------------|-------------------------------------------------------|---------------|
| `canonical.py`| dict → deterministic bytes (§4)                       | **by hand**   |
| `logentry.py` | build/sign an entry; the crypto core (§5)             | **by hand**   |
| `log.py`      | append-only log; persist to JSONL                     | agent OK      |
| `verify.py`   | auditor's tool; walk log, check all three properties  | agent OK*     |
| `attack.py`   | corrupt a log file, run verify, report results table  | agent OK      |

\* `verify.py` must check **all three**: (1) chain linkage via `prev_hash`,
(2) `entry_hash` recomputation, (3) signature validity. A verifier that
silently skips one is worse than none. Read every line before trusting it.

Hand-written files (`canonical.py`, `logentry.py`) are OFF LIMITS to the
coding agent. State this in every agent prompt.

---

## 10. Outputs

- `synthlog.jsonl` — the append-only record (one entry per line).
- verification report — verify.py output: "OK, N entries, chain intact" or
  "TAMPER at entry K: <reason>".
- attack results table — attack.py output; goes into the Week 7 write-up.

## 11. Acceptance demo

```
append 3 entries            -> verify: OK
delete entry 2              -> verify: chain broken at 3
modify entry 1 metadata     -> verify: hash mismatch at 1
rewrite tail after modify   -> verify: signature invalid at 1   <- the payoff
```

The last line is the core argument: the operator can recompute hashes but
cannot forge signatures, so cannot silently rewrite history.

---

## 12. Build order

1. `canonical.py` — then test it round-trips deterministically.
2. `logentry.py` — build one entry, print it, eyeball the fields.
3. `log.py` — append 3 entries, look at the JSONL by hand.
4. `verify.py` — run on the clean log, confirm it says OK.
5. `attack.py` — delete an entry, watch verify break.
6. Add signatures *after* seeing an unsigned tail-rewrite succeed — the
   attack succeeding is what motivates the signature layer.