"""
logentry.py — build and sign a single log entry. The crypto core.

Spec: design.md §5 ("Log entry structure") and the "What the signature
covers — BE EXACT" subsection.

HAND-WRITTEN FILE. Per design.md §9 this file is off limits to the
coding agent. This is deliberately left as a SCAFFOLD, not a stub-only
blank file: function names, signatures, and docstrings quoting the spec
are filled in so (a) log.py and verify.py have a stable interface to
import against and (b) you're not staring at a blank page deciding what
the shape of things should be. But every function body that does actual
cryptographic work raises NotImplementedError — that part is yours to
write, because this is the file where "I understand what I built"
matters most for this project.

Depends on the `cryptography` package for Ed25519 (design.md §3):
    pip install cryptography
"""
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from sequence_crypto import encrypt_sequence
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from canonical import canonical, canonical_sequence
import os
from merkletree import hash_leaf

# The fields that get hashed into entry_hash, per design.md §5.
# Deliberately does NOT include entry_hash or signature — see
# compute_entry_hash below and the "BE EXACT" section of §5.

ENTRY_FIELDS = ("index", "timestamp", "seq_ciphertext", "metadata")




KEYS_DIR = "keys"
DEFAULT_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "device_private_key.pem")
DEFAULT_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "device_public_key.pem")




def generate_keypair(
    private_key_path: str = DEFAULT_PRIVATE_KEY_PATH,
    public_key_path: str = DEFAULT_PUBLIC_KEY_PATH,
    ) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    
    
  
    """
    Produce (or load) this device's Ed25519 keypair.

    design.md §7 is blunt about this: on the prototype, "device-bound
    key" is aspirational. A key that lives in a file on the Pi's SD card
    is extractable by exactly the adversary this project defends
    against (root-level physical access) — the ATECC608 secure element
    (Month 2) is what would make the key actually non-extractable.
    Until then, this function is simulating that property, and the
    write-up should say so plainly rather than imply otherwise.




    TODO (you): decide and implement:
      - Generate-once-and-persist vs. regenerate every run. You want
        the former — a new key each run breaks the story that every
        entry in the log is signed by "the device's" one key. Probably:
        check for an existing private key file, load it if present,
        generate + save if not.
      - Where the private key file lives, and what file permissions it
        gets (0600, not world-readable — even though on this threat
        model the adversary has root anyway, so this is a courtesy, not
        a real control).
      - What format to persist in (cryptography's Ed25519PrivateKey
        supports PEM export via `private_bytes`) and whether the public
        key gets written out separately for verify.py to load without
        needing the private key at all.
    """
    
    """
    Load this device's Ed25519 keypair if it already exists on disk;
    otherwise generate one and persist it. Load-once-and-persist, not
    regenerate-every-run, so every entry ever appended is signed under the
    same "device" key (design.md §7).

    Simulates a device-bound key, does not provide one: a PEM file on disk
    is extractable by exactly the adversary this project defends against
    (root-level physical access). The ATECC608 secure element (Month 2) is
    what would make the key actually non-extractable. Not encrypting the
    PEM at rest is deliberate, not an oversight — see module docstring.
    """
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

    if os.path.exists(private_key_path):
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(private_key_path, "wb") as f:
            f.write(private_bytes)
        os.chmod(private_key_path, 0o600)

    # Derive the public key from the private key in memory rather than
    # reading a separately stored public key file back in — the private
    # key is the one source of truth; the file below is written purely as
    # a convenience export for the auditor (see load_public_key).
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(public_key_path, "wb") as f:
        f.write(public_bytes)

    return private_key, public_key
  



def load_public_key(public_key_path: str = DEFAULT_PUBLIC_KEY_PATH) -> Ed25519PublicKey:
    """
    Auditor-facing loader: reads ONLY the public key file. Deliberately
    does not import or touch anything private-key-related, even
    transitively — verify.py should never need the private key, and
    importing this function rather than generate_keypair() keeps that
    true at the import level, not just by convention.
    """
    with open(public_key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


import hashlib


def compute_leaf_hash(
    index: int,
    timestamp: str,
    seq_ciphertext: str,
    metadata: dict,
) -> bytes:
    """
    Same shape as before this change — only the parameter name moved
    from seq_commit to seq_ciphertext. Still just canonical() + hash_leaf
    over ENTRY_FIELDS; this function doesn't know or care that the third
    field is now ciphertext instead of a hash. That's the point: routine
    tamper-checking (verify.py's check_root_integrity calls this exact
    function) never needs to decrypt anything — it just re-hashes
    whatever bytes are already stored, the same way it already does for
    every other field. Tampering with seq_ciphertext is caught here
    exactly like tampering with metadata always was.
    """
    entry_fields = {
        "index": index,
        "timestamp": timestamp,
        "seq_ciphertext": seq_ciphertext,
        "metadata": metadata,
    }
    serialized = canonical(entry_fields)
    return hash_leaf(serialized)

    
   



def sign_root(root_hash: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """
    Replaces sign_entry_hash. Signs the tree's ROOT, not a single
    entry's hash — signing moved from "once per entry" to "once per
    checkpoint" (design.md's sign-every-append choice means a
    checkpoint gets built right after every append, so in practice this
    still runs once per append, just over a different value).

    Because the root transitively commits to every leaf beneath it
    (merkletree.compute_root), one signature over it still commits to
    the entire log at that size — the same role a chained entry_hash
    signature used to play, but the commitment now comes from tree
    membership rather than a prev_hash linked list.
    """
    return private_key.sign(root_hash)






def build_entry(
    index: int,
    timestamp: str,
    raw_sequence: str,
    metadata: dict,
    auditor_public_key: X25519PublicKey,
) -> dict:
    """
    The one real behavior change from before: takes raw_sequence and
    auditor_public_key instead of a pre-made seq_commit, and actually
    performs the encryption here via sequence_crypto.encrypt_sequence.

    raw_sequence is canonicalized (canonical.canonical_sequence) before
    encryption, per design.md §4 — canonicalizing after encryption would be
    impossible (ciphertext isn't a sequence string) and canonicalizing only
    at read time wouldn't help, since two differently-spelled but
    identical sequences would already have encrypted to unrelated
    ciphertext. This is also the point where a malformed raw_sequence
    (invalid IUPAC symbol, empty string) raises and aborts the append,
    before anything is encrypted or written.

    raw_sequence exists only for the duration of this call — it gets
    consumed into seq_ciphertext below and never assigned anywhere else,
    never written to disk in its own right. This is the first (and only)
    place in the codebase a raw sequence is ever handled directly; every
    other function only ever sees seq_ciphertext.

    seq_ciphertext is raw bytes coming out of encrypt_sequence, hex-encoded
    here for storage — same inspectability convention as leaf_hash and
    signature elsewhere in this file.
    """
    sequence = canonical_sequence(raw_sequence)
    seq_ciphertext = encrypt_sequence(sequence, auditor_public_key).hex()

    leaf_hash = compute_leaf_hash(
        index=index,
        timestamp=timestamp,
        seq_ciphertext=seq_ciphertext,
        metadata=metadata,
    )
    return {
        "index": index,
        "timestamp": timestamp,
        "seq_ciphertext": seq_ciphertext,
        "metadata": metadata,
        "leaf_hash": leaf_hash.hex(),
    }




def build_checkpoint(
    tree_size: int,
    root_hash: bytes,
    timestamp: str,
    private_key: Ed25519PrivateKey,
) -> dict:
    """
    NEW. Builds one signed checkpoint — a commitment to the entire
    tree's state at tree_size leaves. log.py calls this once per
    append, right after recomputing the full tree, and appends the
    result to a new checkpoints.jsonl (separate from synthlog.jsonl,
    since a checkpoint is a different kind of record from an entry).

    Takes root_hash as a plain parameter rather than computing it
    itself — this function's job is signing, not tree construction;
    log.py owns calling merkletree.compute_root over all current leaf
    hashes and handing the result in here. Keeps this file's
    responsibility narrowly "crypto over a value it's given," same
    separation build_entry already had from log.py's storage logic.

    timestamp is also a caller-supplied parameter, not generated here,
    for the same reason build_entry never touched the system clock
    itself — see log.py's append_entry docstring on why time-source
    decisions live there, not in this file.

    root_hash is raw bytes in, hex-encoded here — same inspectability
    reasoning as leaf_hash in build_entry above.
    """
    signature = sign_root(root_hash, private_key)
    return {
        "tree_size": tree_size,
        "root_hash": root_hash.hex(),
        "timestamp": timestamp,
        "signature": signature.hex(),
    }




