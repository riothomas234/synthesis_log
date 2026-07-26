"""
canonical.py — deterministic dict -> bytes serialization.

Spec: design.md §4.

HAND-WRITTEN FILE. Per design.md §9 this file is off limits to the
coding agent — a future "hey Claude, clean this up" should not touch it.

Why this file exists at all: everything that gets hashed or signed
anywhere in this project (logentry.py) MUST pass through canonical()
first, and only through this canonical(). If any code path serializes
the same logical entry differently — different key order, different
whitespace, different float formatting — entry_hash will differ between
write time and verify time for reasons that have nothing to do with
tampering, and the whole chain becomes useless. There must be exactly
ONE canonicalization implementation in the codebase. Do not let a
future refactor inline a second json.dumps() call somewhere else.
"""

import json


def canonical(obj: dict) -> bytes:
    """
    Deterministic byte serialization of a dict. This is given verbatim in
    design.md §4 — it's not a judgment call, so it's filled in here rather
    than left as a stub. Do not change these arguments without updating
    design.md and re-justifying the change (per the file's own header).

    sort_keys=True           -> field order can never depend on dict
                                 insertion order (which Python does NOT
                                 guarantee is stable across processes/
                                 versions in the way you'd want for a
                                 cryptographic commitment).
    separators=(",", ":")    -> no incidental whitespace. json.dumps'
                                 default separators (", ", ": ") would
                                 hash differently from a compact form
                                 written by a different json library or
                                 a different json.dumps call elsewhere.
    ensure_ascii=False       -> don't let non-ASCII metadata (e.g. a lab
                                 or operator name) get silently rewritten
                                 as \\uXXXX escapes. That rewriting is
                                 itself deterministic, so it wouldn't
                                 break correctness — but it makes the
                                 stored bytes harder to eyeball, and
                                 "harder to eyeball" is a real cost in a
                                 tamper-evidence tool whose whole job is
                                 to be inspectable.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


_IUPAC_NUCLEOTIDE_CODES = frozenset("ACGTRYSWKMBDHVN")


def canonical_sequence(raw_sequence: str) -> str:
    """
    Canonicalize a raw DNA sequence string BEFORE it is encrypted into
    seq_ciphertext (design.md §4/§8). Resolved per design.md §10 item 2:

      1. Case folding: uppercase everything.
      2. Whitespace/newline stripping: removed entirely — FASTA-style
         line wrapping, trailing newlines, etc. are export formatting,
         not content.
      3. Alphabet validation: every remaining character must be a valid
         IUPAC nucleotide code (A C G T R Y S W K M B D H V N). Anything
         else raises, rather than being silently dropped or normalized
         away — this is a synthesis order, not a sequencing read, so a
         stray non-IUPAC character is an input error to surface, not
         noise to clean up.
      4. Ambiguity codes are KEPT as-is, not expanded or rejected.
         Degenerate codes (a single N/K, or a whole NNK codon) are a
         common, legitimate synthesis order — mixed-base oligo pools for
         library construction — not sequencing uncertainty to strip out.
         Realizing the actual randomness (which base ends up in which
         physical molecule of the pool) happens downstream in the
         synthesis pipeline; this log only commits to the order
         specification as submitted, not to molecular ground truth.
      5. Reverse complement is NOT collapsed. Two sequences that are
         each other's reverse complement canonicalize to two different
         strings. This is a domain judgment call, not a technical
         default: unlike case/whitespace, RC is a biologically
         meaningful difference in what was submitted, and collapsing it
         would throw away information an investigator may need. Net
         effect: this function does not fully close the "resubmit in a
         cosmetically different form" laundering concern for the RC
         case specifically — closing that would require a separate
         cross-check elsewhere, not a lossy rule baked in here.

    Raises ValueError on an empty sequence or any non-IUPAC character.
    """
    sequence = "".join(raw_sequence.split()).upper()

    if not sequence:
        raise ValueError("canonical_sequence: empty sequence")

    invalid = sorted(set(sequence) - _IUPAC_NUCLEOTIDE_CODES)
    if invalid:
        raise ValueError(
            f"canonical_sequence: invalid symbol(s) {invalid} — "
            "not valid IUPAC nucleotide codes"
        )

    return sequence
