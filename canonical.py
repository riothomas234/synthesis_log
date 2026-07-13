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


def canonical_sequence(raw_sequence: str) -> str:
    """
    Canonicalize a raw DNA sequence string BEFORE it is hashed into a
    seq_commit (design.md §6). This is the OPEN QUESTION from §4 / §8.3
    — it is not yet specified, and it is deliberately left unimplemented
    here rather than guessed at by an agent.

    The problem: the same biological sequence can be written many
    different valid ways —
      - upper vs lower case
      - line breaks / whitespace from whatever export tool produced it
      - the reverse complement of the same physical strand
      - flanking vector/adapter sequence included or trimmed
      - ambiguity codes or modified-base notation (methylated C, etc.)

    If this function doesn't normalize all of that, two runs that
    physically synthesized the identical sequence produce two different
    seq_commit values in the log — which means the log UNDER-counts
    tampering it should be catching: an operator could "launder" a
    flagged synthesis by resubmitting it in a cosmetically different
    text form and have it read as an unrelated, first-time event.

    TODO (you): decide and implement the actual rule. At minimum decide:
      1. Case folding — almost certainly: uppercase everything.
      2. Whitespace/newline stripping.
      3. Reverse-complement equivalence — does an investigator care
         which strand was physically synthesized, or only which molecule
         resulted? If they don't care, RC-equivalent sequences should
         canonicalize to the same string; if they do, they must not.
         This is a domain judgment call, not a coding one.
      4. Non-ACGT characters — reject/flag them rather than silently
         normalizing, so ambiguity doesn't get laundered into a
         canonical form that hides it.

    Until this is implemented, seq_commit is not a trustworthy
    commitment — do not treat it as one in verify.py or the write-up.
    """
    raise NotImplementedError(
        "canonical_sequence is an open design question — see design.md §4, §8.3"
    )
