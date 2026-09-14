"""Auditor-side verification of a TPM NV certification."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from log import read_checkpoints, read_log
from logentry import compute_leaf_hash, load_public_key
from merkletree import compute_root
from tpm_guard import TPMGuardError, replay_accumulator
from verify import verify_log


TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_NV = 0x8014
TPM_ALG_ECDSA = 0x0018
TPM_ALG_SHA256 = 0x000B


class AttestationError(TPMGuardError):
    pass


class _Reader:
    def __init__(self, value: bytes):
        self.value = value
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.value):
            raise AttestationError("truncated TPMS_ATTEST")
        result = self.value[self.offset:end]
        self.offset = end
        return result

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def tpm2b(self) -> bytes:
        return self.take(self.number(2))


def parse_nv_attestation(value: bytes) -> dict:
    reader = _Reader(value)
    result = {
        "magic": reader.number(4),
        "type": reader.number(2),
        "qualified_signer": reader.tpm2b(),
        "extra_data": reader.tpm2b(),
        "clock": reader.number(8),
        "reset_count": reader.number(4),
        "restart_count": reader.number(4),
        "safe": reader.number(1),
        "firmware_version": reader.number(8),
        "index_name": reader.tpm2b(),
        "offset": reader.number(2),
        "nv_contents": reader.tpm2b(),
    }
    if reader.offset != len(value):
        raise AttestationError(
            f"TPMS_ATTEST has {len(value) - reader.offset} trailing bytes"
        )
    return result


def parse_ecdsa_signature(value: bytes) -> bytes:
    if value.startswith(b"\x30"):
        try:
            r, s = decode_dss_signature(value)
        except ValueError as exc:
            raise AttestationError("invalid DER ECDSA signature") from exc
        return encode_dss_signature(r, s)

    reader = _Reader(value)
    algorithm = reader.number(2)
    hash_algorithm = reader.number(2)
    r = reader.tpm2b()
    s = reader.tpm2b()
    if reader.offset != len(value):
        raise AttestationError(
            f"TPMT_SIGNATURE has {len(value) - reader.offset} trailing bytes"
        )
    if algorithm != TPM_ALG_ECDSA or hash_algorithm != TPM_ALG_SHA256:
        raise AttestationError(
            "TPM signature is not ECDSA with SHA-256: "
            f"algorithm 0x{algorithm:04x}, hash 0x{hash_algorithm:04x}"
        )
    return encode_dss_signature(int.from_bytes(r, "big"), int.from_bytes(s, "big"))


def check_checkpoint_prefixes(entries: list[dict], checkpoints: list[dict]) -> None:
    """Every checkpoint's root must equal the root of the matching entry prefix.

    Replay binds the checkpoint history to the TPM, but never reads entries.
    Without this check, an operator with signing-oracle access can delete an
    already-extended entry, append a freshly signed checkpoint for the altered
    log, and extend it: replay and the last-checkpoint check both still pass,
    because the earlier genuine checkpoints are left in place.
    """
    if len(checkpoints) != len(entries):
        raise AttestationError(
            f"log has {len(entries)} entries but checkpoint history has "
            f"{len(checkpoints)} checkpoints"
        )
    leaf_hashes = [
        compute_leaf_hash(
            index=entry["index"],
            timestamp=entry["timestamp"],
            seq_ciphertext=entry["seq_ciphertext"],
            metadata=entry["metadata"],
        )
        for entry in entries
    ]
    for size, checkpoint in enumerate(checkpoints, start=1):
        if compute_root(leaf_hashes[:size]).hex() != checkpoint["root_hash"]:
            raise AttestationError(
                f"checkpoint {size} root does not match the first {size} log entries"
            )


def verify_attestation(
    entries: list[dict],
    checkpoints: list[dict],
    provisioning: dict,
    bundle: dict,
    expected_nonce: bytes,
    ak_public_key_pem: bytes,
    device_public_key_pem: bytes,
    auditor_public_key_pem: bytes,
) -> bytes:
    key_bindings = (
        ("ak_public_key_sha256", ak_public_key_pem, "AK public key"),
        (
            "device_signing_public_key_sha256",
            device_public_key_pem,
            "device signing public key",
        ),
        (
            "auditor_encryption_public_key_sha256",
            auditor_public_key_pem,
            "auditor encryption public key",
        ),
    )
    for field, public_key_bytes, label in key_bindings:
        observed = hashlib.sha256(public_key_bytes).hexdigest()
        if observed != provisioning[field].lower():
            raise AttestationError(f"{label} does not match provisioning")

    if bundle.get("version") != 1:
        raise AttestationError("unsupported attestation bundle version")
    if bytes.fromhex(bundle["nonce"]) != expected_nonce:
        raise AttestationError("bundle nonce does not match the audit challenge")
    if bundle["checkpoint_count"] != len(checkpoints):
        raise AttestationError(
            "bundle checkpoint count does not match the presented history"
        )

    attestation_bytes = bytes.fromhex(bundle["attestation"])
    signature = parse_ecdsa_signature(bytes.fromhex(bundle["signature"]))
    public_key = serialization.load_pem_public_key(ak_public_key_pem)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise AttestationError("prototype supports an ECC attestation key only")
    try:
        public_key.verify(signature, attestation_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise AttestationError("TPM attestation signature is invalid") from exc

    attested = parse_nv_attestation(attestation_bytes)
    if attested["magic"] != TPM_GENERATED_VALUE:
        raise AttestationError("attestation magic is not TPM_GENERATED_VALUE")
    if attested["type"] != TPM_ST_ATTEST_NV:
        raise AttestationError("attestation is not an NV certification")
    if attested["extra_data"] != expected_nonce:
        raise AttestationError("TPM qualifying data does not match the audit challenge")
    if (
        attested["qualified_signer"].hex()
        != provisioning["ak_qualified_name"].lower()
    ):
        raise AttestationError(
            "attestation key qualified Name does not match provisioning"
        )
    if attested["index_name"].hex() != provisioning["nv_name"].lower():
        raise AttestationError("certified NV Name does not match provisioning")
    if attested["offset"] != 0:
        raise AttestationError(f"certified NV data starts at offset {attested['offset']}")

    initial_value = bytes.fromhex(provisioning["initial_value"])
    expected_accumulator = replay_accumulator(initial_value, checkpoints)
    if bytes.fromhex(bundle["accumulator"]) != expected_accumulator:
        raise AttestationError("bundle accumulator does not match checkpoint history")
    if attested["nv_contents"] != expected_accumulator:
        raise AttestationError("certified NV value does not match checkpoint history")
    check_checkpoint_prefixes(entries, checkpoints)
    return expected_accumulator


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provisioning", required=True)
    parser.add_argument("--log", default="synthlog.jsonl")
    parser.add_argument("--checkpoints", default="checkpoints.jsonl")
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--nonce", required=True, help="expected 32-byte nonce in hex")
    parser.add_argument("--ak-public-key", required=True)
    parser.add_argument("--device-public-key", required=True)
    parser.add_argument("--auditor-public-key", required=True)
    args = parser.parse_args()

    report = verify_log(
        args.log, args.checkpoints, load_public_key(args.device_public_key)
    )
    if not report.startswith("OK"):
        raise AttestationError(report)
    provisioning = json.loads(Path(args.provisioning).read_text(encoding="utf-8"))
    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    checkpoints = read_checkpoints(args.checkpoints)
    accumulator = verify_attestation(
        read_log(args.log),
        checkpoints,
        provisioning,
        bundle,
        bytes.fromhex(args.nonce),
        Path(args.ak_public_key).read_bytes(),
        Path(args.device_public_key).read_bytes(),
        Path(args.auditor_public_key).read_bytes(),
    )
    print(
        f"OK, {len(checkpoints)} checkpoints, every checkpoint matches its "
        f"entry prefix, last checkpoint signed, fresh TPM certification, "
        f"accumulator {accumulator.hex()}"
    )


if __name__ == "__main__":
    main()
