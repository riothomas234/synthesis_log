"""Produce a fresh TPM NV certification for an auditor challenge."""

import argparse
from pathlib import Path

from canonical import canonical
from log import read_checkpoints
from tpm_guard import TPMGuard


def certify(
    config_path: str,
    checkpoints_path: str,
    signing_context: str,
    nonce: bytes,
) -> dict:
    guard = TPMGuard(config_path)
    checkpoints = read_checkpoints(checkpoints_path)
    with guard.lock():
        accumulator = guard.assert_current(checkpoints)
        attestation, signature = guard.backend.certify(signing_context, nonce)
    return {
        "version": 1,
        "nonce": nonce.hex(),
        "checkpoint_count": len(checkpoints),
        "accumulator": accumulator.hex(),
        "attestation": attestation.hex(),
        "signature": signature.hex(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--checkpoints", default="checkpoints.jsonl")
    parser.add_argument("--signing-context", required=True)
    parser.add_argument("--nonce", required=True, help="32-byte challenge in hex")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    nonce = bytes.fromhex(args.nonce)
    bundle = certify(args.config, args.checkpoints, args.signing_context, nonce)
    Path(args.output).write_bytes(canonical(bundle) + b"\n")


if __name__ == "__main__":
    main()
