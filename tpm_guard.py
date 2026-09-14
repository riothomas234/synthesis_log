"""Optional TPM-backed rollback evidence for synthesis-log checkpoints.

The TPM stores a SHA-256 NV extend accumulator.  Ordinary log operation may
extend it but cannot assign an arbitrary value.  A small durable journal makes
an append recoverable when power is lost between the TPM operation and either
JSONL write.

This module deliberately shells out to tpm2-tools.  That keeps the prototype's
TPM boundary small and makes every command directly reproducible at the bench.
No command is run through a shell.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from canonical import canonical


COMMITMENT_TYPE = "synthesis-log-checkpoint-v1"


class TPMGuardError(RuntimeError):
    pass


def checkpoint_commitment(checkpoint: dict) -> bytes:
    """Return the value supplied to TPM2_NV_Extend for one checkpoint."""
    committed = {
        "type": COMMITMENT_TYPE,
        "tree_size": checkpoint["tree_size"],
        "root_hash": checkpoint["root_hash"],
    }
    return hashlib.sha256(canonical(committed)).digest()


def extend_value(previous: bytes, commitment: bytes) -> bytes:
    if len(previous) != 32 or len(commitment) != 32:
        raise ValueError("TPM SHA-256 extend values must be 32 bytes")
    return hashlib.sha256(previous + commitment).digest()


def replay_accumulator(initial_value: bytes, checkpoints: list[dict]) -> bytes:
    value = initial_value
    for position, checkpoint in enumerate(checkpoints, start=1):
        if checkpoint["tree_size"] != position:
            raise TPMGuardError(
                "checkpoint history is not contiguous: "
                f"position {position} has tree_size {checkpoint['tree_size']}"
            )
        value = extend_value(value, checkpoint_commitment(checkpoint))
    return value


class TPM2ToolsBackend:
    """Minimal tpm2-tools adapter used by TPMGuard."""

    def __init__(self, nv_index: str, command_prefix: list[str] | None = None):
        self.nv_index = nv_index
        self.command_prefix = command_prefix or []

    def _run(self, command: list[str], **kwargs) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                [*self.command_prefix, *command],
                check=True,
                **kwargs,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise TPMGuardError(f"TPM command failed: {' '.join(command)}") from exc

    def read(self) -> bytes:
        result = self._run(
            [
                "tpm2_nvread",
                "-C",
                self.nv_index,
                "-s",
                "32",
                self.nv_index,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = result.stdout
        if len(value) != 32:
            raise TPMGuardError(f"TPM NV read returned {len(value)} bytes, expected 32")
        return value

    def extend(self, commitment: bytes) -> None:
        if len(commitment) != 32:
            raise ValueError("TPM SHA-256 commitment must be 32 bytes")
        with tempfile.TemporaryDirectory(prefix="synthlog-tpm-") as directory:
            input_path = Path(directory) / "commitment.bin"
            input_path.write_bytes(commitment)
            self._run(
                [
                    "tpm2_nvextend",
                    "-C",
                    self.nv_index,
                    "-i",
                    str(input_path),
                    self.nv_index,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

    def public(self) -> tuple[str, str]:
        result = self._run(
            ["tpm2_nvreadpublic", self.nv_index],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        name_match = re.search(r"^\s*name:\s*([0-9a-fA-F]+)\s*$", result.stdout, re.M)
        attrs_match = re.search(
            r"^\s*attributes:\s*\n\s*friendly:\s*([^\n]+)",
            result.stdout,
            re.M,
        )
        if not name_match or not attrs_match:
            raise TPMGuardError("could not parse tpm2_nvreadpublic output")
        return name_match.group(1).lower(), attrs_match.group(1).strip()

    def certify(
        self, signing_context: str, nonce: bytes
    ) -> tuple[bytes, bytes]:
        if len(nonce) != 32:
            raise ValueError("audit nonce must be 32 bytes")
        with tempfile.TemporaryDirectory(prefix="synthlog-tpm-") as directory:
            attestation_path = Path(directory) / "attestation.bin"
            signature_path = Path(directory) / "signature.bin"
            attestation_path.touch(mode=0o600)
            signature_path.touch(mode=0o600)
            self._run(
                [
                    "tpm2_nvcertify",
                    "-C",
                    signing_context,
                    "-c",
                    self.nv_index,
                    "-q",
                    nonce.hex(),
                    "-g",
                    "sha256",
                    "-s",
                    "ecdsa",
                    "--size",
                    "32",
                    "-f",
                    "plain",
                    "-o",
                    str(signature_path),
                    "--attestation",
                    str(attestation_path),
                    self.nv_index,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return attestation_path.read_bytes(), signature_path.read_bytes()

    def export_public_key(
        self, context: str, output_path: str
    ) -> tuple[str, str, str]:
        public_path = Path(output_path)
        public_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.touch(mode=0o644)
        result = self._run(
            [
                "tpm2_readpublic",
                "-c",
                context,
                "-f",
                "pem",
                "-o",
                output_path,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        name_match = re.search(r"^name:\s*([0-9a-fA-F]+)\s*$", result.stdout, re.M)
        qualified_match = re.search(
            r"^qualified name:\s*([0-9a-fA-F]+)\s*$", result.stdout, re.M
        )
        attrs_match = re.search(
            r"^attributes:\s*\n\s*value:\s*([^\n]+)", result.stdout, re.M
        )
        if not name_match or not qualified_match or not attrs_match:
            raise TPMGuardError("could not parse TPM signing key public data")
        attributes = attrs_match.group(1).strip()
        required = {"fixedtpm", "fixedparent", "restricted", "sign"}
        observed = set(attributes.split("|"))
        if not required.issubset(observed) or "decrypt" in observed:
            raise TPMGuardError(
                "attestation key is not a restricted signing key: " + attributes
            )
        return (
            name_match.group(1).lower(),
            qualified_match.group(1).lower(),
            attributes,
        )


class TPMGuard:
    """Coordinate one TPM extend with durable entry/checkpoint appends."""

    def __init__(self, config_path: str | os.PathLike, backend=None):
        self.config_path = Path(config_path)
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        if config.get("version") != 1:
            raise TPMGuardError("unsupported TPM guard configuration version")
        self.nv_index = config["nv_index"]
        self.nv_name = config["nv_name"].lower()
        self.nv_attributes = config["nv_attributes"]
        self.initial_value = bytes.fromhex(config["initial_value"])
        if len(self.initial_value) != 32:
            raise TPMGuardError("initial TPM accumulator must be 32 bytes")
        self.backend = backend or TPM2ToolsBackend(
            self.nv_index, config.get("command_prefix")
        )
        self.journal_path = Path(
            config.get("journal_path", str(self.config_path) + ".pending")
        )
        self.lock_path = Path(config.get("lock_path", str(self.config_path) + ".lock"))

    @contextlib.contextmanager
    def lock(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+b") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            yield

    def check_index(self) -> None:
        name, attributes = self.backend.public()
        if name != self.nv_name:
            raise TPMGuardError(
                f"TPM NV Name mismatch: configured {self.nv_name}, observed {name}"
            )
        if "nt=0x1" not in attributes:
            raise TPMGuardError(f"TPM NV index is not an extend index: {attributes}")

    def recover(self, log_path: str, checkpoints_path: str) -> None:
        """Finish an interrupted guarded append, or do nothing."""
        if not self.journal_path.exists():
            return
        journal = json.loads(self.journal_path.read_text(encoding="utf-8"))
        self._validate_journal_paths(journal, log_path, checkpoints_path)

        before = bytes.fromhex(journal["accumulator_before"])
        after = bytes.fromhex(journal["accumulator_after"])
        observed = self.backend.read()
        if observed == before:
            self._require_base_file(journal["log"])
            self._require_base_file(journal["checkpoints"])
            self.backend.extend(bytes.fromhex(journal["commitment"]))
            observed = self.backend.read()
        if observed != after:
            raise TPMGuardError(
                "pending append cannot be recovered: TPM accumulator is neither "
                "the recorded before nor after value"
            )

        self._complete_file(journal["log"])
        self._complete_file(journal["checkpoints"])
        self.journal_path.unlink()
        _fsync_directory(self.journal_path.parent)

    def commit(
        self,
        entry: dict,
        checkpoint: dict,
        prior_checkpoints: list[dict],
        log_path: str,
        checkpoints_path: str,
    ) -> None:
        if self.journal_path.exists():
            raise TPMGuardError("pending TPM append must be recovered before a new append")
        self.check_index()
        expected_before = replay_accumulator(self.initial_value, prior_checkpoints)
        observed = self.backend.read()
        if observed != expected_before:
            raise TPMGuardError(
                "TPM accumulator does not match the checkpoint history: "
                f"expected {expected_before.hex()}, observed {observed.hex()}"
            )

        commitment = checkpoint_commitment(checkpoint)
        expected_tree_size = len(prior_checkpoints) + 1
        if checkpoint["tree_size"] != expected_tree_size:
            raise TPMGuardError(
                "entry and checkpoint histories disagree: "
                f"new checkpoint has tree_size {checkpoint['tree_size']}, "
                f"expected {expected_tree_size}"
            )
        expected_after = extend_value(expected_before, commitment)
        journal = {
            "version": 1,
            "accumulator_before": expected_before.hex(),
            "accumulator_after": expected_after.hex(),
            "commitment": commitment.hex(),
            "log": _file_plan(log_path, canonical(entry) + b"\n"),
            "checkpoints": _file_plan(
                checkpoints_path, canonical(checkpoint) + b"\n"
            ),
        }
        self._write_journal(journal)

        self.backend.extend(commitment)
        observed = self.backend.read()
        if observed != expected_after:
            raise TPMGuardError(
                "TPM accumulator after extend is wrong: "
                f"expected {expected_after.hex()}, observed {observed.hex()}"
            )
        self._complete_file(journal["log"])
        self._complete_file(journal["checkpoints"])
        self.journal_path.unlink()
        _fsync_directory(self.journal_path.parent)

    def assert_current(self, checkpoints: list[dict]) -> bytes:
        self.check_index()
        expected = replay_accumulator(self.initial_value, checkpoints)
        observed = self.backend.read()
        if observed != expected:
            raise TPMGuardError(
                "TPM accumulator does not match the checkpoint history: "
                f"expected {expected.hex()}, observed {observed.hex()}"
            )
        return observed

    def _write_journal(self, journal: dict) -> None:
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.journal_path.with_name(self.journal_path.name + ".tmp")
        with temporary.open("wb") as output:
            output.write(canonical(journal) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.journal_path)
        _fsync_directory(self.journal_path.parent)

    @staticmethod
    def _validate_journal_paths(journal: dict, log_path: str, checkpoints_path: str):
        expected = (str(Path(log_path).resolve()), str(Path(checkpoints_path).resolve()))
        recorded = (journal["log"]["path"], journal["checkpoints"]["path"])
        if recorded != expected:
            raise TPMGuardError(
                f"pending journal is for {recorded}, not requested paths {expected}"
            )

    @staticmethod
    def _require_base_file(plan: dict) -> None:
        path = Path(plan["path"])
        current = path.read_bytes() if path.exists() else b""
        base_size = plan["base_size"]
        if len(current) != base_size:
            raise TPMGuardError(f"{path} changed before the pending TPM extend")
        if hashlib.sha256(current).hexdigest() != plan["base_sha256"]:
            raise TPMGuardError(f"{path} content changed before the pending TPM extend")

    @staticmethod
    def _complete_file(plan: dict) -> None:
        path = Path(plan["path"])
        current = path.read_bytes() if path.exists() else b""
        base_size = plan["base_size"]
        payload = bytes.fromhex(plan["payload"])
        if len(current) < base_size:
            raise TPMGuardError(f"{path} was truncated during pending append recovery")
        if hashlib.sha256(current[:base_size]).hexdigest() != plan["base_sha256"]:
            raise TPMGuardError(f"{path} prefix changed during pending append recovery")
        suffix = current[base_size:]
        if suffix == payload:
            return
        if not payload.startswith(suffix):
            raise TPMGuardError(f"{path} has unexpected data after pending append prefix")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("r+b" if path.exists() else "w+b") as output:
            output.seek(base_size)
            output.truncate()
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        _fsync_directory(path.parent)


def _file_plan(path_string: str, payload: bytes) -> dict:
    path = Path(path_string).resolve()
    current = path.read_bytes() if path.exists() else b""
    return {
        "path": str(path),
        "base_size": len(current),
        "base_sha256": hashlib.sha256(current).hexdigest(),
        "payload": payload.hex(),
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def enroll(
    config_path: str,
    nv_index: str,
    command_prefix: list[str],
    ak_context: str | None = None,
    ak_public_key_path: str | None = None,
) -> None:
    backend = TPM2ToolsBackend(nv_index, command_prefix)
    name, attributes = backend.public()
    if "nt=0x1" not in attributes:
        raise TPMGuardError(f"TPM NV index is not an extend index: {attributes}")
    config = {
        "version": 1,
        "nv_index": nv_index,
        "nv_name": name,
        "nv_attributes": attributes,
        "initial_value": backend.read().hex(),
        "command_prefix": command_prefix,
    }
    if (ak_context is None) != (ak_public_key_path is None):
        raise TPMGuardError("AK context and public-key output must be supplied together")
    if ak_context is not None:
        (
            config["ak_name"],
            config["ak_qualified_name"],
            config["ak_attributes"],
        ) = backend.export_public_key(ak_context, ak_public_key_path)
    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(config) + b"\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    enroll_parser = subparsers.add_parser("enroll", help="pin an existing NV index")
    enroll_parser.add_argument("--config", required=True)
    enroll_parser.add_argument("--index", required=True)
    enroll_parser.add_argument("--ak-context")
    enroll_parser.add_argument("--ak-public-key")
    enroll_parser.add_argument(
        "--sudo", action="store_true", help="run tpm2-tools through sudo -n"
    )
    check_parser = subparsers.add_parser("check", help="compare TPM with checkpoints")
    check_parser.add_argument("--config", required=True)
    check_parser.add_argument("--checkpoints", default="checkpoints.jsonl")
    args = parser.parse_args()

    if args.action == "enroll":
        enroll(
            args.config,
            args.index,
            ["sudo", "-n"] if args.sudo else [],
            args.ak_context,
            args.ak_public_key,
        )
        return

    from log import read_checkpoints

    guard = TPMGuard(args.config)
    checkpoints = read_checkpoints(args.checkpoints)
    with guard.lock():
        value = guard.assert_current(checkpoints)
    print(f"OK, {len(checkpoints)} checkpoints, TPM accumulator {value.hex()}")


if __name__ == "__main__":
    main()
