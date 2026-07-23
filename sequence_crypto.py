import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Device-side: where the auditor's PUBLIC key is provisioned to, alongside
# the device's own signing keys.
DEVICE_KEYS_DIR = "keys"
DEFAULT_AUDITOR_PUBLIC_KEY_PATH = os.path.join(DEVICE_KEYS_DIR, "auditor_public_key.pem")



# Auditor-side: where the auditor keeps their OWN keypair, on their OWN
# system. Separate directory from DEVICE_KEYS_DIR on purpose — this is
# never meant to be co-located with the device's own keys in a real
# deployment; kept in the same repo here only for this prototype's
# convenience of running everything in one place.
AUDITOR_KEYS_DIR = "auditor_keys"
DEFAULT_AUDITOR_PRIVATE_KEY_PATH = os.path.join(AUDITOR_KEYS_DIR, "auditor_private_key.pem")

NONCE_SIZE = 12  # AESGCM standard nonce size
EPHEMERAL_PUBLIC_KEY_SIZE = 32  # X25519 raw public key size
HKDF_INFO = b"synthesis_log sequence encryption v1"


def generate_auditor_keypair(
    private_key_path: str = DEFAULT_AUDITOR_PRIVATE_KEY_PATH,
    public_key_path: str = DEFAULT_AUDITOR_PUBLIC_KEY_PATH,
) -> tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Load the auditor's X25519 keypair if it already exists; otherwise
    generate one and persist it. Same load-once-and-persist shape as
    logentry.generate_keypair, same reasoning (a new key every run would
    make historical ciphertext undecryptable) — but this keypair belongs
    to the AUDITOR, not the device. In a real deployment this function
    runs on the auditor's own machine, once, and public_key_path's output
    gets copied to the device out-of-band; it does not run as part of the
    device's own logging flow.

    Also unencrypted-at-rest, same deliberate choice and same caveat as
    the device's signing key (see logentry.generate_keypair's docstring)
    — protecting this file's storage is the auditor's own responsibility,
    outside this project's threat model (design.md §2 is about the device
    operator, not the auditor's own system security).
    """
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

    if os.path.exists(private_key_path):
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = X25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
        with open(private_key_path, "wb") as f:
            f.write(private_bytes)
        os.chmod(private_key_path, 0o600)

    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    os.makedirs(os.path.dirname(public_key_path), exist_ok=True)
    with open(public_key_path, "wb") as f:
        f.write(public_bytes)

    return private_key, public_key



def load_auditor_public_key(
    public_key_path: str = DEFAULT_AUDITOR_PUBLIC_KEY_PATH,
) -> X25519PublicKey:
    """
    Device-side loader: reads ONLY the auditor's public key. This is the
    ONE function from this file the device's own code (logentry.build_entry)
    actually calls — everything else here is auditor-side tooling that
    happens to live in the same file.
    """
    with open(public_key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
    


def load_auditor_private_key(
    private_key_path: str = DEFAULT_AUDITOR_PRIVATE_KEY_PATH,
) -> X25519PrivateKey:
    """
    Auditor-side loader, for the auditor's own use when decrypting. The
    device never calls this.
    """
    with open(private_key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
    


def encrypt_sequence(raw_sequence: str, auditor_public_key: X25519PublicKey) -> bytes:
    """
    Hybrid-encrypt a raw sequence to the auditor's public key. This is
    what build_entry calls; raw_sequence exists only for the duration of
    this call and the caller's own local scope — nothing in this function
    writes it anywhere.

    The hybrid construction, and why each piece is there:
      1. A FRESH, random ephemeral X25519 keypair, generated new on every
         single call — this is what makes encryption non-deterministic
         (semantically secure / IND-CPA, per the earlier design
         discussion): encrypting the identical sequence twice produces
         completely different ciphertext both times, because the
         ephemeral key differs each time. Without this, anyone holding
         the (public, widely-known) auditor public key could brute-force
         guess candidate sequences by re-encrypting them and comparing
         ciphertext — exactly the attack salting a hash would defend
         against, except encryption defeats it for free, by design,
         rather than needing a manually-managed secret.
      2. X25519 key exchange between the ephemeral private key and the
         auditor's public key produces a shared secret. The auditor can
         later reconstruct this SAME shared secret using their own
         private key plus the ephemeral PUBLIC key (which travels
         alongside the ciphertext, in the clear — it's not secret, only
         the exchange's OUTPUT is) — that's the Diffie-Hellman identity
         this relies on: (ephemeral_private × auditor_public) ==
         (auditor_private × ephemeral_public), always, regardless of
         which random ephemeral key was used.
      3. HKDF derives a proper AES key from that shared secret, rather
         than using the raw shared secret directly as a key — standard
         practice; a raw ECDH output isn't guaranteed to have the right
         statistical properties to use directly as a symmetric key.
      4. AESGCM does the actual bulk encryption, authenticated — a
         tampered ciphertext fails to decrypt outright (an auth tag
         mismatch) rather than silently producing garbage plaintext.

    Returns one bytes blob: ephemeral_public_key (32 bytes) || nonce (12
    bytes) || ciphertext-and-tag (everything else). Fixed-size prefix, no
    length-prefixing needed since the first two pieces never vary in
    size. This whole blob is what build_entry hex-encodes into
    seq_ciphertext.
    """
    ephemeral_private_key = X25519PrivateKey.generate()
    ephemeral_public_bytes = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    shared_secret = ephemeral_private_key.exchange(auditor_public_key)
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared_secret)

    nonce = os.urandom(NONCE_SIZE)
    ciphertext_and_tag = AESGCM(symmetric_key).encrypt(
        nonce, raw_sequence.encode("utf-8"), None
    )

    return ephemeral_public_bytes + nonce + ciphertext_and_tag




def decrypt_sequence(ciphertext_bundle: bytes, auditor_private_key: X25519PrivateKey) -> str:
    """
    The inverse of encrypt_sequence — auditor-side only, since it's the
    one operation that needs the private key. Unpacks the bundle,
    reconstructs the SAME shared secret via
    (auditor_private_key, ephemeral_public_key) — see encrypt_sequence's
    docstring for why this always matches regardless of which random
    ephemeral key was used — rederives the same AES key via the same
    HKDF parameters, and decrypts.

    Raises cryptography.exceptions.InvalidTag if the ciphertext was
    tampered with or doesn't correspond to this private key — AESGCM's
    authentication catches that directly, independent of anything
    merkletree.py/verify.py check.
    """
    ephemeral_public_bytes = ciphertext_bundle[:EPHEMERAL_PUBLIC_KEY_SIZE]
    nonce = ciphertext_bundle[EPHEMERAL_PUBLIC_KEY_SIZE : EPHEMERAL_PUBLIC_KEY_SIZE + NONCE_SIZE]
    ciphertext_and_tag = ciphertext_bundle[EPHEMERAL_PUBLIC_KEY_SIZE + NONCE_SIZE :]

    ephemeral_public_key = X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    shared_secret = auditor_private_key.exchange(ephemeral_public_key)
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared_secret)

    plaintext_bytes = AESGCM(symmetric_key).decrypt(nonce, ciphertext_and_tag, None)
    return plaintext_bytes.decode("utf-8")