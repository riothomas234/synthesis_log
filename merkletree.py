
"""Why domain separation matters (this is the whole point of this file):
RFC 6962 (the Certificate Transparency Merkle tree spec) prefixes every
hash input with a single byte that says what KIND of thing is being
hashed — 0x00 for a leaf, 0x01 for an internal node. Without this, a
malicious party could take an internal node's hash input (left || right,
32+32=64 bytes) and try to pass it off as some leaf's raw data, or vice
versa — a "second preimage" attack that lets an attacker forge a tree
with the same root but different structure/content. The one-byte prefix
makes a leaf hash and a node hash come from disjoint input spaces, so
this confusion is impossible by construction. This is the single most
important correctness detail in the whole tree — get it wrong (e.g. hash
leaves and nodes the same way) and inclusion proofs become forgeable.
"""

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def hash_leaf(data: bytes) -> bytes:
    """
    Hash a single leaf's serialized bytes. `data` is expected to already
    be canonical()-serialized (logentry.py's job, not this file's) —
    this function's only responsibility is the domain-separated SHA-256
    on top of that.
    """
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """
    Combine two child hashes (each a 32-byte SHA-256 digest, either leaf
    hashes or other node hashes) into their parent's hash.
    """
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    """
    RFC 6962's MTH(D[n]) splits a list of n>1 leaves at k, the largest
    power of two strictly smaller than n (so k < n <= 2k). This is what
    makes the tree shape deterministic and gives every subtree of size k
    a "clean" internal structure (itself splittable the same way) —
    important later for inclusion/consistency proofs, which rely on
    being able to identify these same power-of-two subtrees again.
    """
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def compute_root(leaf_hashes: list[bytes]) -> bytes:
    """
    RFC 6962 MTH(D[n]) — the Merkle Tree Hash of a list of n leaf
    hashes (each already produced by hash_leaf, NOT raw entry data —
    this function only combines hashes, it never hashes original
    content itself).

    Base cases:
      MTH({})     = SHA-256("")         — empty tree, no leaves yet.
      MTH({d(0)}) = d(0)                — a single leaf's hash IS the
                                           root; nothing to combine.
    Recursive case (n > 1):
      Split at k = _largest_power_of_two_less_than(n), recurse on each
      half, combine with hash_node. This exact split (not a naive
      down-the-middle split) is what RFC 6962 specifies — using a
      different split rule would still produce *a* tree, but not one
      compatible with the standard inclusion/consistency proof algorithms
      that assume this specific shape.
    """
    if not leaf_hashes:
        return hashlib.sha256(b"").digest()
    return _subtree_root(leaf_hashes)


def _subtree_root(leaf_hashes: list[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 1:
        return leaf_hashes[0]
    k = _largest_power_of_two_less_than(n)
    left = _subtree_root(leaf_hashes[:k])
    right = _subtree_root(leaf_hashes[k:])
    return hash_node(left, right)





def generate_inclusion_proof(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    """
    RFC 6962 PATH(m, D[n]) — the audit path proving leaf `index` is
    included in the tree over `leaf_hashes`. Returns a list of O(log n)
    sibling hashes, ordered leaf-to-root (the sibling closest to the leaf
    comes first, the one closest to the root comes last) — this ordering
    matters, verify_inclusion_proof below assumes it.

    Each entry is the ROOT of the sibling subtree at that level, not
    necessarily a single leaf hash — e.g. for a 5-leaf tree, the proof
    for leaf 0 includes leaf 1's hash (a true sibling leaf) but also the
    combined hash of leaves 2-3 (a sibling SUBTREE), because that's the
    granularity the recursive split produces at that level.
    """
    n = len(leaf_hashes)
    if not (0 <= index < n):
        raise IndexError(f"leaf index {index} out of range for a tree of size {n}")
    return _subtree_inclusion_proof(leaf_hashes, index)


def _subtree_inclusion_proof(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    n = len(leaf_hashes)
    if n == 1:
        return []  # nothing to prove within a single-leaf subtree
    k = _largest_power_of_two_less_than(n)
    if index < k:
        # target leaf is in the left half; the right half's root is the
        # sibling needed at this level.
        path = _subtree_inclusion_proof(leaf_hashes[:k], index)
        path.append(_subtree_root(leaf_hashes[k:]))
    else:
        # target leaf is in the right half; re-index relative to that
        # half (index - k) and the left half's root is the sibling.
        path = _subtree_inclusion_proof(leaf_hashes[k:], index - k)
        path.append(_subtree_root(leaf_hashes[:k]))
    return path


def verify_inclusion_proof(
    leaf_hash: bytes,
    index: int,
    tree_size: int,
    proof: list[bytes],
    root: bytes,
) -> bool:
    """
    Recompute a root from a single leaf hash + its audit path, and check
    it matches the trusted root — WITHOUT needing any other leaf in the
    tree. This is the whole point of switching to a Merkle tree (see
    design.md §8.1): an auditor can confirm one synthesis event was
    logged using only O(log n) hashes, never seeing the rest of the log.

    The tricky part this function handles: proof entries are given
    leaf-to-root (see generate_inclusion_proof), but at each level we
    also need to know whether our current running hash was the LEFT or
    RIGHT child of that combination — combining in the wrong order
    produces a completely different hash. Rather than re-deriving that
    from the original leaf list (which would defeat the purpose — the
    auditor doesn't HAVE the other leaves), we track it using a
    left/right trick: `node_index` is our leaf's position among however
    many leaves remain "in play" at the current level, and
    `last_node_index` is the position of the last one. A node is a RIGHT
    child if its index is odd, OR if it's the last (odd-one-out) node at
    a level with no pair — RFC 6962's recursive split always produces
    exactly this shape, so this rule exactly mirrors the same left/right
    decisions generate_inclusion_proof made, one level at a time, as
    both indices are halved moving up the tree.
    """
    if not (0 <= index < tree_size):
        return False
    node = leaf_hash
    node_index = index
    last_node_index = tree_size - 1
    for sibling in proof:
        if node_index == last_node_index or node_index % 2 == 1:
            node = hash_node(sibling, node)  # we were the right child
        else:
            node = hash_node(node, sibling)  # we were the left child
        node_index //= 2
        last_node_index //= 2
    return node == root




#consistency proofs


def generate_consistency_proof(leaf_hashes: list[bytes], old_size: int) -> list[bytes]:
    """
    RFC 6962 PROOF(m, D[n]) — proves the tree used to be old_size leaves
    (root = compute_root(leaf_hashes[:old_size])) and grew, append-only,
    into the current tree over all of leaf_hashes. This is what lets an
    auditor trust a new checkpoint without re-walking the entire log:
    they already trust an old root; this proves the new root is a
    genuine extension of it, not a rewrite (design.md §8.1).

    Degenerate cases return an empty proof: an empty old tree is
    trivially a prefix of anything, and if old_size == n there's nothing
    that changed to prove.
    """
    n = len(leaf_hashes)
    if not (0 <= old_size <= n):
        raise ValueError(f"old_size {old_size} out of range for a tree of size {n}")
    if old_size == 0 or old_size == n:
        return []
    return _subproof(leaf_hashes, old_size, True)




def _subproof(leaf_hashes: list[bytes], m: int, boundary: bool) -> list[bytes]:
    """
    `boundary` tracks whether we're still walking the old tree's own
    left-aligned edge. It starts True; the FIRST time old_size doesn't
    fit evenly in the current left half (the `else` branch below), it
    flips to False for the rest of that branch's descent — from that
    point on we're reconstructing new-tree structure the old tree never
    saw, not the old tree's own boundary anymore.

    Only relevant when old_size isn't a power of two: then the old tree
    doesn't correspond to one clean subtree, but decomposes into several
    ("peaks" — same underlying idea as the MMR peaks from our earlier
    conversation, arising here from old_size's own binary representation,
    even though we never build an MMR). Each `else` branch below hands
    over exactly one such peak (`leaf_hashes[:k]`, entirely old, since
    m > k means all of it predates old_size) before continuing.
    """
    n = len(leaf_hashes)
    if m == n:
        if boundary:
            return []  # verifier already has this exact hash: old_root
        else:
            return [_subtree_root(leaf_hashes)]  # an old-tree peak
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        path = _subproof(leaf_hashes[:k], m, boundary)
        path.append(_subtree_root(leaf_hashes[k:]))
    else:
        path = _subproof(leaf_hashes[k:], m - k, False)
        path.append(_subtree_root(leaf_hashes[:k]))
    return path


def verify_consistency_proof(
    old_root: bytes,
    old_size: int,
    new_root: bytes,
    new_size: int,
    proof: list[bytes],
) -> bool:
    """
    Checks two things at once, using the same walk: (1) recombining the
    proof with old_root reconstructs new_root, and (2) old_root itself
    is genuinely the hash of old_size leaves, not an unrelated value
    that happens to combine correctly.

    (2) is the part that's easy to get wrong and worth spelling out.
    When old_size is a power of two, old_root gets used directly inside
    the reconstruction toward new_root, so (1) alone already pins it
    down. But when old_size ISN'T a power of two, old_root instead gets
    combined with sibling material and never touched again after the
    left/right split that moves past it (see _subproof's `boundary`
    note) — so (1) alone can succeed for literally any old_root, wrong
    ones included, because it was never actually load-bearing for that
    reconstruction. This was caught empirically: an early version of
    this function passed every "does the real proof verify" test but
    failed "does a WRONG old_root get rejected" for every non-power-of-
    two old_size. The fix is to separately collect every old-tree peak
    encountered along the way (_verify_subproof's `peaks` list) and
    independently recombine them into old_root — peaks must be combined
    largest-first, right-associatively (_combine_peaks_right_fold),
    mirroring how compute_root would have actually built old_root the
    first time; a naive re-split by peak COUNT (as if peaks were a
    fresh leaf list) produces a different, wrong hash whenever there
    are 3 or more peaks.
    """
    if not (0 <= old_size <= new_size):
        return False
    if old_size == 0:
        return True
    if old_size == new_size:
        return old_root == new_root and not proof
    it = iter(proof)
    peaks: list[bytes] = []
    try:
        result = _verify_subproof(old_root, old_size, new_size, True, it, peaks)
    except StopIteration:
        return False  # proof ran out of entries before the walk finished
    if list(it):
        return False  # proof had leftover entries the walk never used
    if result != new_root:
        return False
    reconstructed_old_root = _combine_peaks_right_fold(list(reversed(peaks)))
    return reconstructed_old_root == old_root


def _verify_subproof(
    old_root: bytes,
    m: int,
    n: int,
    boundary: bool,
    it,
    peaks: list[bytes],
) -> bytes | None:
    """
    Mirrors _subproof's exact recursive structure (same m/n/boundary
    decisions), but instead of building a proof list, consumes one and
    reconstructs the hash for the current subtree — while also
    collecting old-tree peaks into `peaks` as a side effect, for
    verify_consistency_proof's separate old_root check above.
    """
    if m == n:
        if boundary:
            peaks.append(old_root)
            return old_root
        else:
            v = next(it)
            peaks.append(v)
            return v
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        left = _verify_subproof(old_root, m, k, boundary, it, peaks)
        right = next(it)
        return hash_node(left, right)
    else:
        right = _verify_subproof(old_root, m - k, n - k, False, it, peaks)
        left = next(it)
        peaks.append(left)  # leaf_hashes[:k] at this level is entirely old
        return hash_node(left, right)


def _combine_peaks_right_fold(peaks_largest_first: list[bytes]) -> bytes:
    """
    Recombines old-tree peaks (ordered largest-to-smallest) the same way
    compute_root's own recursion would have combined them originally:
    the largest peak paired with the combination of everything smaller
    than it, nested — NOT a fresh power-of-two split over the peak
    list itself (that only happens to give the same answer when there
    are 1 or 2 peaks, and silently diverges with 3+, e.g. old_size=7's
    peaks of size 4, 2, 1 must combine as H(size4, H(size2, size1)),
    not H(H(size4, size2), size1)).
    """
    combined = peaks_largest_first[-1]
    for peak in reversed(peaks_largest_first[:-1]):
        combined = hash_node(peak, combined)
    return combined


