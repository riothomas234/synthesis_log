"""Reproducible latency and memory profiling for synthesis-log.

The benchmark uses synthetic DNA and disposable files.  Physical TPM runs
require an explicitly supplied disposable NV index.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import resource
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path

from canonical import canonical
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from log import append_entry, read_checkpoints, read_log
from logentry import build_checkpoint, build_entry, generate_keypair, load_public_key
from merkletree import hash_node
from sequence_crypto import generate_auditor_keypair, load_auditor_public_key
from tpm_guard import (
    TPM2ToolsBackend,
    TPMGuard,
    checkpoint_commitment,
    enroll,
    replay_accumulator,
)
from tpm_audit import certify
from tpm_verify import verify_attestation
from verify import verify_log

try:
    import cryptography
except ImportError:
    cryptography = None


EXPERIMENT = "mintbox-tpm-scale"
SIZES = (0, 1, 10, 100, 1_000, 10_000)
TPM_SIZES = (0, 1, 10, 100, 1_000)
PAYLOAD_SIZES = (100, 1_024, 10_240, 102_400)
BASELINE_PAYLOAD_BYTES = 1_024
TIME_LIMIT_SECONDS = 120.0
PROVISIONING_VERSION = 1


@dataclass
class Fixture:
    root: Path
    log: Path
    checkpoints: Path
    device_private: Path
    device_public: Path
    auditor_private: Path
    auditor_public: Path


class MerkleFrontier:
    """Incrementally compute the same RFC 6962 root as compute_root()."""

    def __init__(self) -> None:
        self.peaks: list[bytes | None] = []

    def append(self, leaf: bytes) -> bytes:
        node = leaf
        level = 0
        while level < len(self.peaks) and self.peaks[level] is not None:
            node = hash_node(self.peaks[level], node)
            self.peaks[level] = None
            level += 1
        if level == len(self.peaks):
            self.peaks.append(node)
        else:
            self.peaks[level] = node
        return self.root()

    def root(self) -> bytes:
        root = None
        for peak in self.peaks:
            if peak is not None:
                root = peak if root is None else hash_node(peak, root)
        if root is None:
            return hashlib.sha256(b"").digest()
        return root


def _write_jsonl(path: Path, value: dict) -> None:
    with path.open("ab") as stream:
        stream.write(canonical(value) + b"\n")


def _dna(size: int) -> str:
    pattern = "ACGT"
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def create_fixture(root: Path, count: int, payload_bytes: int) -> Fixture:
    root.mkdir(parents=True, exist_ok=True)
    keys = root / "keys"
    auditor_keys = root / "auditor_keys"
    device_private = keys / "device_private_key.pem"
    device_public = keys / "device_public_key.pem"
    auditor_private = auditor_keys / "auditor_private_key.pem"
    auditor_public = keys / "auditor_public_key.pem"
    private_key, _ = generate_keypair(str(device_private), str(device_public))
    generate_auditor_keypair(str(auditor_private), str(auditor_public))
    auditor_key = load_auditor_public_key(str(auditor_public))
    log_path = root / "synthlog.jsonl"
    checkpoints_path = root / "checkpoints.jsonl"
    log_path.write_bytes(b"")
    checkpoints_path.write_bytes(b"")
    frontier = MerkleFrontier()
    sequence = _dna(payload_bytes)
    for index in range(count):
        timestamp = f"2026-01-01T00:{index // 60 % 60:02d}:{index % 60:02d}Z"
        entry = build_entry(
            index=index,
            timestamp=timestamp,
            raw_sequence=sequence,
            metadata={
                "benchmark": EXPERIMENT,
                "length_bp": payload_bytes,
                "payload_bytes": payload_bytes,
            },
            auditor_public_key=auditor_key,
        )
        root_hash = frontier.append(bytes.fromhex(entry["leaf_hash"]))
        checkpoint = build_checkpoint(index + 1, root_hash, timestamp, private_key)
        _write_jsonl(log_path, entry)
        _write_jsonl(checkpoints_path, checkpoint)
    fixture = Fixture(
        root,
        log_path,
        checkpoints_path,
        device_private,
        device_public,
        auditor_private,
        auditor_public,
    )
    report = verify_log(str(log_path), str(checkpoints_path), load_public_key(str(device_public)))
    if not report.startswith("OK"):
        raise RuntimeError(f"generated fixture failed verification: {report}")
    return fixture


def _prefix_file(source: Path, destination: Path, count: int) -> None:
    with source.open("rb") as input_stream, destination.open("wb") as output_stream:
        for index, line in enumerate(input_stream):
            if index == count:
                break
            output_stream.write(line)


def materialize_prefix(fixture: Fixture, destination: Path, count: int) -> Fixture:
    destination.mkdir(parents=True, exist_ok=True)
    keys = destination / "keys"
    auditor_keys = destination / "auditor_keys"
    keys.mkdir()
    auditor_keys.mkdir()
    result = Fixture(
        destination,
        destination / "synthlog.jsonl",
        destination / "checkpoints.jsonl",
        keys / "device_private_key.pem",
        keys / "device_public_key.pem",
        auditor_keys / "auditor_private_key.pem",
        keys / "auditor_public_key.pem",
    )
    _prefix_file(fixture.log, result.log, count)
    _prefix_file(fixture.checkpoints, result.checkpoints, count)
    for source, target in (
        (fixture.device_private, result.device_private),
        (fixture.device_public, result.device_public),
        (fixture.auditor_private, result.auditor_private),
        (fixture.auditor_public, result.auditor_public),
    ):
        shutil.copy2(source, target)
    return result


def _cpu_seconds() -> float:
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime


def _rss_mib() -> float:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return value / (1024 * 1024)
    return value / 1024


def _tpm2b(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def _synthetic_attestation(
    entries: list[dict], checkpoints: list[dict], fixture: Fixture, nonce: bytes
) -> tuple[dict, dict, bytes, bytes, bytes]:
    ak = ec.generate_private_key(ec.SECP256R1())
    ak_public = ak.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    device_public = fixture.device_public.read_bytes()
    auditor_public = fixture.auditor_public.read_bytes()
    qualified_name = b"\x00\x0b" + b"q" * 32
    nv_name = b"\x00\x0b" + b"n" * 32
    initial = bytes(32)
    accumulator = replay_accumulator(initial, checkpoints)
    attestation = b"".join(
        (
            (0xFF544347).to_bytes(4, "big"),
            (0x8014).to_bytes(2, "big"),
            _tpm2b(qualified_name),
            _tpm2b(nonce),
            (0).to_bytes(8, "big"),
            (0).to_bytes(4, "big"),
            (0).to_bytes(4, "big"),
            b"\x01",
            (1).to_bytes(8, "big"),
            _tpm2b(nv_name),
            (0).to_bytes(2, "big"),
            _tpm2b(accumulator),
        )
    )
    signature = ak.sign(attestation, ec.ECDSA(hashes.SHA256()))
    provisioning = {
        "version": PROVISIONING_VERSION,
        "initial_value": initial.hex(),
        "nv_name": nv_name.hex(),
        "ak_qualified_name": qualified_name.hex(),
        "ak_public_key_sha256": hashlib.sha256(ak_public).hexdigest(),
        "device_signing_public_key_sha256": hashlib.sha256(device_public).hexdigest(),
        "auditor_encryption_public_key_sha256": hashlib.sha256(auditor_public).hexdigest(),
    }
    bundle = {
        "version": 1,
        "nonce": nonce.hex(),
        "checkpoint_count": len(checkpoints),
        "accumulator": accumulator.hex(),
        "attestation": attestation.hex(),
        "signature": signature.hex(),
    }
    return provisioning, bundle, ak_public, device_public, auditor_public


def _software_operation(name: str, fixture: Fixture, size: int, payload_bytes: int):
    private_key = serialization.load_pem_private_key(
        fixture.device_private.read_bytes(), password=None
    )
    public_key = load_public_key(str(fixture.device_public))
    auditor_key = load_auditor_public_key(str(fixture.auditor_public))
    nonce = bytes.fromhex("42" * 32)
    entries = read_log(str(fixture.log))
    checkpoints = read_checkpoints(str(fixture.checkpoints))
    synthetic = _synthetic_attestation(entries, checkpoints, fixture, nonce)

    if name == "restart_initialize":
        def operation():
            serialization.load_pem_private_key(
                fixture.device_private.read_bytes(), password=None
            )
            load_public_key(str(fixture.device_public))
            load_auditor_public_key(str(fixture.auditor_public))
        return operation
    if name == "verify_software":
        return lambda: verify_log(str(fixture.log), str(fixture.checkpoints), public_key)
    if name == "verify_auditor":
        provisioning, bundle, ak_public, device_public, auditor_public = synthetic

        def operation():
            report = verify_log(
                str(fixture.log), str(fixture.checkpoints), public_key
            )
            if not report.startswith("OK"):
                raise RuntimeError(report)
            verify_attestation(
                read_log(str(fixture.log)),
                read_checkpoints(str(fixture.checkpoints)),
                provisioning,
                bundle,
                nonce,
                ak_public,
                device_public,
                auditor_public,
            )
        return operation
    if name == "append_software":
        return lambda: append_entry(
            _dna(payload_bytes),
            {"benchmark": EXPERIMENT, "length_bp": payload_bytes},
            private_key,
            auditor_key,
            str(fixture.log),
            str(fixture.checkpoints),
        )
    raise ValueError(f"unknown software operation {name}")


def worker(args: argparse.Namespace) -> None:
    source = Fixture(
        Path(args.fixture),
        Path(args.fixture) / "synthlog.jsonl",
        Path(args.fixture) / "checkpoints.jsonl",
        Path(args.fixture) / "keys/device_private_key.pem",
        Path(args.fixture) / "keys/device_public_key.pem",
        Path(args.fixture) / "auditor_keys/auditor_private_key.pem",
        Path(args.fixture) / "keys/auditor_public_key.pem",
    )
    rows = []
    with tempfile.TemporaryDirectory(prefix="synthlog-benchmark-") as directory:
        temp_root = Path(directory)
        if args.cold_only:
            fixture = materialize_prefix(source, temp_root / "cold", args.size)
            operation = _software_operation(
                args.operation, fixture, args.size, args.payload_bytes
            )
            tracemalloc.start()
            cpu_before = _cpu_seconds()
            started = time.perf_counter_ns()
            result = operation()
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            cpu_ms = (_cpu_seconds() - cpu_before) * 1_000
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            if args.operation == "verify_software" and not result.startswith("OK"):
                raise RuntimeError(result)
            print(
                json.dumps(
                    {
                        "samples": [{"repetition": 0, "elapsed_ms": elapsed_ms, "cpu_ms": cpu_ms}],
                        "peak_rss_mib": _rss_mib(),
                        "peak_python_heap_mib": peak / (1024 * 1024),
                    },
                    sort_keys=True,
                )
            )
            return
        for repetition in range(args.repetitions):
            trial_root = temp_root / f"trial-{repetition}"
            if trial_root.exists():
                shutil.rmtree(trial_root)
            fixture = materialize_prefix(source, trial_root, args.size)
            operation = _software_operation(
                args.operation, fixture, args.size, args.payload_bytes
            )
            operation()
            if args.operation == "append_software":
                shutil.rmtree(trial_root)
                fixture = materialize_prefix(source, trial_root, args.size)
                operation = _software_operation(
                    args.operation, fixture, args.size, args.payload_bytes
                )
            cpu_before = _cpu_seconds()
            started = time.perf_counter_ns()
            result = operation()
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            cpu_ms = (_cpu_seconds() - cpu_before) * 1_000
            if args.operation == "verify_software" and not result.startswith("OK"):
                raise RuntimeError(result)
            rows.append(
                {
                    "repetition": repetition,
                    "elapsed_ms": elapsed_ms,
                    "cpu_ms": cpu_ms,
                }
            )
            if elapsed_ms / 1_000 > TIME_LIMIT_SECONDS:
                break

        memory_root = temp_root / "memory"
        fixture = materialize_prefix(source, memory_root, args.size)
        operation = _software_operation(
            args.operation, fixture, args.size, args.payload_bytes
        )
        tracemalloc.start()
        operation()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    print(
        json.dumps(
            {
                "samples": rows,
                "peak_rss_mib": _rss_mib(),
                "peak_python_heap_mib": peak / (1024 * 1024),
            },
            sort_keys=True,
        )
    )


def _environment() -> dict:
    git_result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    git_commit = git_result.stdout.strip() if git_result.returncode == 0 else "unknown"
    cpu_model = platform.processor() or "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    governor_path = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    governor = governor_path.read_text(encoding="ascii").strip() if governor_path.exists() else "unknown"
    ram_bytes = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    tools = subprocess.run(
        ["tpm2_getcap", "--version"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return {
        "experiment": EXPERIMENT,
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__ if cryptography else "unavailable",
        "cpu_model": cpu_model,
        "cpu_governor": governor,
        "ram_bytes": ram_bytes,
        "tpm2_tools": tools.stdout.strip().splitlines()[0] if tools.stdout.strip() else "unknown",
        "git_commit": git_commit,
    }


def _tpm_environment(prefix: list[str]) -> dict:
    result = subprocess.run(
        [*prefix, "tpm2_getcap", "properties-fixed"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    fields = {}
    wanted = {
        "TPM2_PT_MANUFACTURER": ("tpm_manufacturer", "value"),
        "TPM2_PT_VENDOR_STRING_1": ("tpm_vendor_1", "value"),
        "TPM2_PT_VENDOR_STRING_2": ("tpm_vendor_2", "value"),
        "TPM2_PT_FIRMWARE_VERSION_1": ("tpm_firmware_1", "raw"),
        "TPM2_PT_FIRMWARE_VERSION_2": ("tpm_firmware_2", "raw"),
    }
    blocks = re.split(r"(?m)^(?=TPM2_PT_[A-Z0-9_]+:)", result)
    for block in blocks:
        header = block.splitlines()[0].rstrip(":") if block.splitlines() else ""
        if header not in wanted:
            continue
        output_name, source_name = wanted[header]
        match = re.search(rf"(?m)^\s+{source_name}:\s*(.+)$", block)
        if match:
            fields[output_name] = match.group(1).strip().strip('"')
    return fields


def _append_result(path: Path, row: dict) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _read_results(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _prepare_group(
    raw_path: Path,
    backend: str,
    operation: str,
    entry_count: int,
    payload_bytes: int,
    warm_count: int,
    resume: bool,
) -> bool:
    rows = _read_results(raw_path)
    matches = [
        row for row in rows
        if row["backend"] == backend
        and row["operation"] == operation
        and row["entry_count"] == entry_count
        and row["payload_bytes"] == payload_bytes
    ]
    if resume:
        cold_count = sum(row["cache_mode"] == "cold" for row in matches)
        measured_warm = sum(row["cache_mode"] == "warm" for row in matches)
        if cold_count == 1 and measured_warm >= warm_count:
            return False
    if matches:
        retained = [row for row in rows if row not in matches]
        temporary = raw_path.with_suffix(raw_path.suffix + ".tmp")
        temporary.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in retained),
            encoding="utf-8",
        )
        os.replace(temporary, raw_path)
    return True


def _drop_backend(raw_path: Path, backend: str) -> None:
    rows = _read_results(raw_path)
    retained = [row for row in rows if row["backend"] != backend]
    temporary = raw_path.with_suffix(raw_path.suffix + ".tmp")
    temporary.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in retained),
        encoding="utf-8",
    )
    os.replace(temporary, raw_path)


def _run_worker(
    operation: str,
    fixture: Fixture,
    size: int,
    payload_bytes: int,
    repetitions: int,
) -> tuple[dict, float]:
    base_command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "worker",
        "--operation",
        operation,
        "--fixture",
        str(fixture.root),
        "--size",
        str(size),
        "--payload-bytes",
        str(payload_bytes),
        "--repetitions",
        str(repetitions),
    ]
    started = time.perf_counter_ns()
    cold = subprocess.run(
        [*base_command, "--cold-only"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
    )
    cold_ms = (time.perf_counter_ns() - started) / 1_000_000
    if not json.loads(cold.stdout)["samples"]:
        raise RuntimeError("cold benchmark worker returned no sample")
    result = subprocess.run(
        base_command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=max(300, repetitions * 150),
    )
    return json.loads(result.stdout), cold_ms


def run_software(args: argparse.Namespace, raw_path: Path, environment: dict) -> Fixture:
    fixtures_root = Path(args.output_dir) / "fixtures"
    sizes = (0, 1, 10) if args.quick else SIZES
    payload_sizes = (100, 1_024) if args.quick else PAYLOAD_SIZES
    baseline = create_fixture(fixtures_root / "baseline", max(sizes), BASELINE_PAYLOAD_BYTES)
    operations = ("restart_initialize", "append_software", "verify_software", "verify_auditor")
    skip_after: dict[str, int] = {}
    for size in sizes:
        repetitions = 2 if args.quick else (10 if size <= 1_000 else 5)
        for operation in operations:
            if operation in skip_after and size > skip_after[operation]:
                continue
            if not _prepare_group(
                raw_path,
                "software",
                operation,
                size,
                BASELINE_PAYLOAD_BYTES,
                repetitions,
                args.resume,
            ):
                continue
            result, cold_ms = _run_worker(
                operation, baseline, size, BASELINE_PAYLOAD_BYTES, repetitions
            )
            common = {
                **environment,
                "backend": "software",
                "operation": operation,
                "entry_count": size,
                "payload_bytes": BASELINE_PAYLOAD_BYTES,
                "peak_rss_mib": result["peak_rss_mib"],
                "peak_python_heap_mib": result["peak_python_heap_mib"],
            }
            _append_result(raw_path, {**common, "cache_mode": "cold", "repetition": 0, "elapsed_ms": cold_ms, "cpu_ms": None})
            for sample in result["samples"]:
                _append_result(raw_path, {**common, "cache_mode": "warm", **sample})
            if result["samples"] and result["samples"][-1]["elapsed_ms"] > TIME_LIMIT_SECONDS * 1_000:
                skip_after[operation] = size

    for payload_bytes in payload_sizes:
        payload_entry_count = min(100, max(sizes))
        repetitions = 2 if args.quick else 10
        if not _prepare_group(
            raw_path,
            "software",
            "append_payload_sweep",
            payload_entry_count,
            payload_bytes,
            repetitions,
            args.resume,
        ):
            continue
        result, cold_ms = _run_worker(
            "append_software", baseline, payload_entry_count, payload_bytes,
            repetitions,
        )
        common = {
            **environment,
            "backend": "software",
            "operation": "append_payload_sweep",
            "entry_count": payload_entry_count,
            "payload_bytes": payload_bytes,
            "peak_rss_mib": result["peak_rss_mib"],
            "peak_python_heap_mib": result["peak_python_heap_mib"],
        }
        _append_result(raw_path, {**common, "cache_mode": "cold", "repetition": 0, "elapsed_ms": cold_ms, "cpu_ms": None})
        for sample in result["samples"]:
            _append_result(raw_path, {**common, "cache_mode": "warm", **sample})
    return baseline


def _timed_call(function) -> tuple[float, float]:
    cpu_before = _cpu_seconds()
    started = time.perf_counter_ns()
    function()
    return (
        (time.perf_counter_ns() - started) / 1_000_000,
        (_cpu_seconds() - cpu_before) * 1_000,
    )


def _physical_row(environment: dict, operation: str, size: int, repetition: int, timing):
    return {
        **environment,
        "backend": "physical_tpm",
        "operation": operation,
        "entry_count": size,
        "payload_bytes": BASELINE_PAYLOAD_BYTES,
        "cache_mode": "warm",
        "repetition": repetition,
        "elapsed_ms": timing[0],
        "cpu_ms": timing[1],
        "peak_rss_mib": _rss_mib(),
        "peak_python_heap_mib": None,
    }


def run_physical(
    args: argparse.Namespace,
    raw_path: Path,
    environment: dict,
    baseline: Fixture,
) -> None:
    prefix = ["sudo", "-n"] if args.sudo else []
    environment = {**environment, **_tpm_environment(prefix)}
    raw_repetitions = 2 if args.quick else 10
    append_repetitions = 2 if args.quick else 5
    tpm_sizes = (0, 1) if args.quick else TPM_SIZES
    expected_rows = 3 + 4 * raw_repetitions + (2 + append_repetitions) * len(tpm_sizes)
    physical_rows = [
        row for row in _read_results(raw_path)
        if row["backend"] == "physical_tpm"
    ]
    if args.resume and len(physical_rows) >= expected_rows:
        return
    if physical_rows:
        _drop_backend(raw_path, "physical_tpm")
    backend = TPM2ToolsBackend(args.tpm_index, prefix)
    handles = subprocess.run(
        [*prefix, "tpm2_getcap", "handles-nv-index"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.lower()
    normalized = args.tpm_index.lower().replace("0x0", "0x")
    if normalized in handles:
        raise RuntimeError(f"refusing to overwrite existing NV index {args.tpm_index}")
    with tempfile.TemporaryDirectory(prefix="synthlog-physical-profile-") as directory:
        root = Path(directory)
        ak_public = root / "ak-public.pem"
        backend.export_public_key(args.ak_context, str(ak_public))

        def define():
            subprocess.run(
                [
                    *prefix,
                    "tpm2_nvdefine",
                    args.tpm_index,
                    "-C",
                    "o",
                    "-s",
                    "32",
                    "-g",
                    "sha256",
                    "-a",
                    "ownerwrite|authwrite|ownerread|authread|nt=extend|no_da",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        def undefine():
            subprocess.run(
                [*prefix, "tpm2_nvundefine", args.tpm_index, "-C", "o"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        created = False
        try:
            transient_ak = root / "profile-ak.ctx"
            transient_public = root / "profile-ak.pub"
            transient_name = root / "profile-ak.name"
            transient_qname = root / "profile-ak.qname"

            def create_transient_ak():
                subprocess.run(
                    [*prefix, "tpm2_createak", "-C", args.ek_context, "-G", "ecc", "-g", "sha256", "-s", "ecdsa", "-c", str(transient_ak), "-u", str(transient_public), "-n", str(transient_name), "-q", str(transient_qname)],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )

            transient_before = subprocess.run(
                [*prefix, "tpm2_getcap", "handles-transient"],
                check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout
            timing = _timed_call(create_transient_ak)
            transient_after = subprocess.run(
                [*prefix, "tpm2_getcap", "handles-transient"],
                check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout
            if transient_after != transient_before:
                raise RuntimeError("transient TPM handle set changed during AK provisioning")
            _append_result(raw_path, _physical_row(environment, "provision_ak", 0, 0, timing))

            def provision_nv():
                nonlocal created
                define()
                created = True
                backend.extend(bytes(32))

            timing = _timed_call(provision_nv)
            _append_result(raw_path, _physical_row(environment, "provision_nv", 0, 0, timing))
            for repetition in range(raw_repetitions):
                payload = os.urandom(32)
                _append_result(raw_path, _physical_row(environment, "nv_extend", 0, repetition, _timed_call(lambda p=payload: backend.extend(p))))
                _append_result(raw_path, _physical_row(environment, "nv_read", 0, repetition, _timed_call(backend.read)))
                _append_result(raw_path, _physical_row(environment, "nv_public", 0, repetition, _timed_call(backend.public)))
                nonce = os.urandom(32)
                _append_result(raw_path, _physical_row(environment, "nv_certify", 0, repetition, _timed_call(lambda n=nonce: backend.certify(args.ak_context, n))))
            undefine()
            created = False

            for size in tpm_sizes:
                define()
                created = True
                backend.extend(bytes(32))
                trial = materialize_prefix(baseline, root / f"size-{size}", size)
                config = root / f"guard-{size}.json"
                def enroll_trial():
                    enroll(
                        str(config),
                        args.tpm_index,
                        prefix,
                        args.ak_context,
                        str(ak_public),
                        str(trial.device_public),
                        str(trial.auditor_public),
                    )
                timing = _timed_call(enroll_trial)
                if size == 0:
                    _append_result(raw_path, _physical_row(environment, "provision_enroll", 0, 0, timing))
                guard = TPMGuard(str(config))
                checkpoints = read_checkpoints(str(trial.checkpoints))
                for checkpoint in checkpoints:
                    backend.extend(checkpoint_commitment(checkpoint))
                expected = replay_accumulator(guard.initial_value, checkpoints)
                if backend.read() != expected:
                    raise RuntimeError(f"TPM replay mismatch at {size} entries")

                timing = _timed_call(lambda: guard.assert_current(checkpoints))
                _append_result(raw_path, _physical_row(environment, "tpm_check", size, 0, timing))
                nonce = os.urandom(32)
                output = root / f"attestation-{size}.json"
                timing = _timed_call(lambda: certify(str(config), str(trial.checkpoints), args.ak_context, nonce))
                _append_result(raw_path, _physical_row(environment, "audit_create", size, 0, timing))

                private_key = serialization.load_pem_private_key(
                    trial.device_private.read_bytes(), password=None
                )
                auditor_key = load_auditor_public_key(str(trial.auditor_public))
                for repetition in range(append_repetitions):
                    timing = _timed_call(
                        lambda: append_entry(
                            _dna(BASELINE_PAYLOAD_BYTES),
                            {"benchmark": EXPERIMENT, "length_bp": BASELINE_PAYLOAD_BYTES},
                            private_key,
                            auditor_key,
                            str(trial.log),
                            str(trial.checkpoints),
                            guard,
                        )
                    )
                    _append_result(raw_path, _physical_row(environment, "append_tpm", size + repetition, repetition, timing))
                undefine()
                created = False
        finally:
            if created:
                undefine()


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[math.ceil(fraction * len(ordered)) - 1]


def summarize(raw_path: Path, output_dir: Path) -> None:
    rows = [json.loads(line) for line in raw_path.read_text(encoding="utf-8").splitlines() if line]
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        key = (
            row["backend"], row["operation"], row["entry_count"],
            row["payload_bytes"], row["cache_mode"],
        )
        groups.setdefault(key, []).append(row)
    summary = []
    for key, samples in sorted(groups.items()):
        values = [sample["elapsed_ms"] for sample in samples]
        summary.append(
            {
                "status": "measured",
                "backend": key[0], "operation": key[1], "entry_count": key[2],
                "payload_bytes": key[3], "cache_mode": key[4], "n": len(values),
                "mean_ms": statistics.mean(values), "median_ms": statistics.median(values),
                "p95_ms": _percentile(values, 0.95), "min_ms": min(values), "max_ms": max(values),
                "ops_per_second": 1_000 / statistics.mean(values),
                "peak_rss_mib": max(sample["peak_rss_mib"] for sample in samples if sample["peak_rss_mib"] is not None),
                "peak_python_heap_mib": max((sample["peak_python_heap_mib"] for sample in samples if sample["peak_python_heap_mib"] is not None), default=""),
            }
        )
    software_10k = next(
        (
            row for row in summary
            if row["backend"] == "software"
            and row["operation"] == "append_software"
            and row["entry_count"] == 10_000
            and row["payload_bytes"] == BASELINE_PAYLOAD_BYTES
            and row["cache_mode"] == "warm"
        ),
        None,
    )
    fixed_parts = {}
    for operation in ("nv_public", "nv_read", "nv_extend"):
        candidate = next(
            (
                row for row in summary
                if row["backend"] == "physical_tpm"
                and row["operation"] == operation
                and row["cache_mode"] == "warm"
            ),
            None,
        )
        if candidate:
            fixed_parts[operation] = candidate
    if software_10k and len(fixed_parts) == 3:
        projected_ms = (
            software_10k["median_ms"]
            + fixed_parts["nv_public"]["median_ms"]
            + 2 * fixed_parts["nv_read"]["median_ms"]
            + fixed_parts["nv_extend"]["median_ms"]
        )
        summary.append(
            {
                **software_10k,
                "status": "projected",
                "backend": "physical_tpm_projected",
                "operation": "append_tpm",
                "n": 0,
                "mean_ms": projected_ms,
                "median_ms": projected_ms,
                "p95_ms": projected_ms,
                "min_ms": projected_ms,
                "max_ms": projected_ms,
                "ops_per_second": 1_000 / projected_ms,
                "peak_rss_mib": max(
                    software_10k["peak_rss_mib"],
                    *(part["peak_rss_mib"] for part in fixed_parts.values()),
                ),
            }
        )
    fields = list(summary[0])
    with (output_dir / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(summary)
    warm = [row for row in summary if row["cache_mode"] == "warm"]
    measured_warm = [row for row in summary if row["cache_mode"] == "warm" and row["status"] == "measured"]
    environment = rows[0]

    def lookup(backend, operation, entry_count):
        return next(
            (
                row for row in summary
                if row["backend"] == backend
                and row["operation"] == operation
                and row["entry_count"] == entry_count
                and row["payload_bytes"] == BASELINE_PAYLOAD_BYTES
                and row["cache_mode"] == "warm"
            ),
            None,
        )

    software_append_10k = lookup("software", "append_software", 10_000)
    tpm_append_1k = lookup("physical_tpm", "append_tpm", 1_000)
    auditor_10k = lookup("software", "verify_auditor", 10_000)
    software_verify_10k = lookup("software", "verify_software", 10_000)
    projected = lookup("physical_tpm_projected", "append_tpm", 10_000)
    peak_rss = max(row["peak_rss_mib"] for row in measured_warm)
    findings = ["## Key findings", ""]
    if tpm_append_1k:
        findings.append(f"- Physical TPM append at 1,000 prior entries: {tpm_append_1k['median_ms']:.2f} ms median wall time.")
    if projected:
        findings.append(f"- Projected physical TPM append at 10,000 prior entries: {projected['median_ms']:.2f} ms, combining measured software scaling with measured TPM command costs.")
    if software_append_10k:
        findings.append(f"- Software-only append at 10,000 prior entries: {software_append_10k['median_ms']:.2f} ms median.")
    if software_verify_10k and auditor_10k:
        findings.append(f"- Latest-checkpoint verification at 10,000 entries: {software_verify_10k['median_ms']:.2f} ms; full historical-prefix auditor verification: {auditor_10k['median_ms']:.2f} ms.")
    findings.append(f"- Maximum measured process RSS across warm operations: {peak_rss:.2f} MiB.")

    lines = [
        f"# {EXPERIMENT}", "",
        "## Method", "",
        "Latency is wall-clock time on mintbox-c. Warm results exclude one warmup. Cold results include process startup. Peak RSS is total process memory; Python heap is measured with tracemalloc. Synthetic payload generation and fixture copying are outside timed intervals.", "",
        f"Host: {environment['cpu_model']}; {environment['ram_bytes'] / (1024 ** 3):.2f} GiB RAM; CPU governor {environment['cpu_governor']}; Python {environment['python']}; cryptography {environment['cryptography']}; tpm2-tools {environment['tpm2_tools']}.", "",
        f"Core source commit: `{environment['git_commit']}`.", "",
        "The physical TPM is a Nuvoton NPCT75x. Physical measurements use a disposable NV index and the established persistent AK. The 10,000-entry TPM append is projected; all other rows are measured.", "",
        *findings, "",
        "## Warm measurements", "",
        "| Status | Backend | Operation | Entries | Payload (B) | n | Median (ms) | p95 (ms) | Peak RSS (MiB) | Python heap (MiB) |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in warm:
        heap = row["peak_python_heap_mib"]
        heap_text = "" if heap == "" else f"{heap:.2f}"
        lines.append(
            f"| {row['status']} | {row['backend']} | {row['operation']} | {row['entry_count']} | {row['payload_bytes']} | {row['n']} | {row['median_ms']:.2f} | {row['p95_ms']:.2f} | {row['peak_rss_mib']:.2f} | {heap_text} |"
        )
    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    _write_svg(output_dir / "latency.svg", warm, "median_ms", "Median latency (ms)")
    _write_svg(output_dir / "memory.svg", warm, "peak_rss_mib", "Peak RSS (MiB)")


def _write_svg(path: Path, rows: list[dict], field: str, title: str) -> None:
    plotted = [
        row for row in rows
        if row["payload_bytes"] == BASELINE_PAYLOAD_BYTES
        and row[field] != ""
        and row["operation"] != "append_payload_sweep"
    ]
    width, height = 960, 540
    maximum = max((math.log10(float(row[field]) + 1) for row in plotted), default=1.0)
    max_entries = max((row["entry_count"] for row in plotted), default=1)
    colors = ("#3568a8", "#b64236", "#39834b", "#8a52a3", "#b07820", "#4f6d7a")
    series: dict[tuple[str, str], list[dict]] = {}
    for row in plotted:
        series.setdefault((row["backend"], row["operation"]), []).append(row)
    elements = []
    for series_index, (name, values) in enumerate(sorted(series.items())):
        color = colors[series_index % len(colors)]
        points = []
        for row in sorted(values, key=lambda item: item["entry_count"]):
            x = 100 + 800 * math.log10(row["entry_count"] + 1) / math.log10(max_entries + 1)
            y = 460 - 380 * math.log10(float(row[field]) + 1) / maximum
            points.append(f"{x:.1f},{y:.1f}")
            elements.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{color}"><title>{name[0]} {name[1]} n={row["entry_count"]} {float(row[field]):.2f}</title></circle>')
        if len(points) > 1:
            elements.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="{color}" stroke-width="2"/>')
        legend_y = 62 + 16 * series_index
        elements.append(f'<text x="620" y="{legend_y}" font-family="sans-serif" font-size="11" fill="{color}">{name[0]}: {name[1]}</text>')
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<rect width="100%" height="100%" fill="white"/><text x="40" y="35" font-family="sans-serif" font-size="22">{title}</text>'
        f'<line x1="100" y1="60" x2="100" y2="460" stroke="black"/><line x1="100" y1="460" x2="930" y2="460" stroke="black"/>'
        + "".join(elements) + "</svg>"
    )
    path.write_text(svg, encoding="ascii")


def run(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = output_dir / "raw.jsonl"
    if raw_path.exists() and not args.resume:
        raise SystemExit(f"{raw_path} exists; use --resume or a new output directory")
    environment = _environment()
    if args.source_commit:
        environment["git_commit"] = args.source_commit
    baseline = run_software(args, raw_path, environment)
    if args.tpm_index:
        run_physical(args, raw_path, environment, baseline)
    summarize(raw_path, output_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--output-dir", default=f"profiling/{EXPERIMENT}")
    run_parser.add_argument("--tpm-index")
    run_parser.add_argument("--ak-context", default="0x81010010")
    run_parser.add_argument("--ek-context", default="0x81010001")
    run_parser.add_argument("--sudo", action="store_true")
    run_parser.add_argument("--resume", action="store_true")
    run_parser.add_argument("--quick", action="store_true")
    run_parser.add_argument("--source-commit")
    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--output-dir", default=f"profiling/{EXPERIMENT}")
    worker_parser = subparsers.add_parser("worker", help=argparse.SUPPRESS)
    worker_parser.add_argument("--operation", required=True)
    worker_parser.add_argument("--fixture", required=True)
    worker_parser.add_argument("--size", type=int, required=True)
    worker_parser.add_argument("--payload-bytes", type=int, required=True)
    worker_parser.add_argument("--repetitions", type=int, required=True)
    worker_parser.add_argument("--cold-only", action="store_true")
    args = parser.parse_args()
    if args.command == "run":
        run(args)
    elif args.command == "report":
        output_dir = Path(args.output_dir)
        summarize(output_dir / "raw.jsonl", output_dir)
    else:
        worker(args)


if __name__ == "__main__":
    main()
