import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from log import append_entry, read_checkpoints, read_log
from logentry import generate_keypair
from sequence_crypto import generate_auditor_keypair
from tpm_guard import (
    TPMGuard,
    TPMGuardError,
    checkpoint_commitment,
    extend_value,
    replay_accumulator,
)
from tpm_verify import AttestationError, parse_nv_attestation, verify_attestation
from verify import verify_log


class FakeTPM:
    def __init__(self, value=b"\0" * 32, fail_after_extend=False):
        self.value = value
        self.fail_after_extend = fail_after_extend
        self.name = "000b" + "11" * 32
        self.attributes = "authwrite|nt=0x1|authread|no_da"

    def read(self):
        return self.value

    def extend(self, commitment):
        self.value = extend_value(self.value, commitment)
        if self.fail_after_extend:
            self.fail_after_extend = False
            raise TPMGuardError("simulated power loss after TPM extend")

    def public(self):
        return self.name, self.attributes


class TPMGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.log_path = root / "log.jsonl"
        self.checkpoints_path = root / "checkpoints.jsonl"
        self.config_path = root / "tpm.json"
        self.device_public_key_path = root / "keys" / "device-public.pem"
        self.auditor_public_key_path = root / "keys" / "auditor-public.pem"
        self.private_key, self.public_key = generate_keypair(
            str(root / "keys" / "device-private.pem"),
            str(self.device_public_key_path),
        )
        _, self.auditor_public_key = generate_auditor_keypair(
            str(root / "keys" / "auditor-private.pem"),
            str(self.auditor_public_key_path),
        )
        self.backend = FakeTPM()
        self.config_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "nv_index": "0x01534c47",
                    "nv_name": self.backend.name,
                    "nv_attributes": self.backend.attributes,
                    "initial_value": self.backend.value.hex(),
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def guard(self):
        return TPMGuard(self.config_path, backend=self.backend)

    def append(self, guard):
        return append_entry(
            "ACGT",
            {"length_bp": 4},
            self.private_key,
            self.auditor_public_key,
            str(self.log_path),
            str(self.checkpoints_path),
            rollback_guard=guard,
        )

    def test_guarded_append_extends_and_writes(self):
        initial = self.backend.value
        self.append(self.guard())
        checkpoints = read_checkpoints(str(self.checkpoints_path))
        self.assertEqual(len(read_log(str(self.log_path))), 1)
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(
            self.backend.value,
            extend_value(initial, checkpoint_commitment(checkpoints[0])),
        )

    def test_recovery_does_not_extend_twice(self):
        self.backend.fail_after_extend = True
        with self.assertRaises(TPMGuardError):
            self.append(self.guard())
        value_after_extend = self.backend.value
        guard = self.guard()
        with guard.lock():
            guard.recover(str(self.log_path), str(self.checkpoints_path))
        self.assertEqual(self.backend.value, value_after_extend)
        self.assertEqual(len(read_log(str(self.log_path))), 1)
        self.assertEqual(len(read_checkpoints(str(self.checkpoints_path))), 1)

    def test_recovery_repairs_partial_file_write(self):
        self.backend.fail_after_extend = True
        with self.assertRaises(TPMGuardError):
            self.append(self.guard())
        journal_path = Path(str(self.config_path) + ".pending")
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        log_payload = bytes.fromhex(journal["log"]["payload"])
        self.log_path.write_bytes(log_payload[: len(log_payload) // 2])

        guard = self.guard()
        with guard.lock():
            guard.recover(str(self.log_path), str(self.checkpoints_path))

        self.assertEqual(len(read_log(str(self.log_path))), 1)
        self.assertEqual(len(read_checkpoints(str(self.checkpoints_path))), 1)

    def test_truncated_history_cannot_continue(self):
        self.append(self.guard())
        self.log_path.write_bytes(b"")
        self.checkpoints_path.write_bytes(b"")
        with self.assertRaisesRegex(TPMGuardError, "does not match"):
            self.append(self.guard())
        self.assertEqual(self.log_path.read_bytes(), b"")
        self.assertEqual(self.checkpoints_path.read_bytes(), b"")

    def test_mismatch_fails_before_writing(self):
        self.backend.value = hashlib.sha256(b"unexpected").digest()
        with self.assertRaisesRegex(TPMGuardError, "does not match"):
            self.append(self.guard())
        self.assertFalse(self.log_path.exists())
        self.assertFalse(self.checkpoints_path.exists())

    def test_software_only_path_is_unchanged(self):
        self.append(None)
        self.assertEqual(len(read_log(str(self.log_path))), 1)
        self.assertEqual(len(read_checkpoints(str(self.checkpoints_path))), 1)

    def test_nv_certification_is_bound_to_nonce_identity_and_history(self):
        self.append(self.guard())
        entries = read_log(str(self.log_path))
        checkpoints = read_checkpoints(str(self.checkpoints_path))
        nonce = hashlib.sha256(b"auditor challenge").digest()
        provisioning, bundle, public_pem = self.certify(nonce, len(checkpoints))
        self.assertEqual(
            verify_attestation(
                entries,
                checkpoints,
                provisioning,
                bundle,
                nonce,
                public_pem,
                self.device_public_key_path.read_bytes(),
                self.auditor_public_key_path.read_bytes(),
            ),
            self.backend.value,
        )
        with self.assertRaisesRegex(AttestationError, "bundle nonce"):
            verify_attestation(
                entries,
                checkpoints,
                provisioning,
                bundle,
                b"x" * 32,
                public_pem,
                self.device_public_key_path.read_bytes(),
                self.auditor_public_key_path.read_bytes(),
            )
        with self.assertRaisesRegex(
            AttestationError, "auditor encryption public key"
        ):
            verify_attestation(
                entries,
                checkpoints,
                provisioning,
                bundle,
                nonce,
                public_pem,
                self.device_public_key_path.read_bytes(),
                b"different auditor key",
            )

    def test_oracle_deletion_passes_replay_but_fails_prefix_check(self):
        initial = self.backend.value
        guard = self.guard()
        for _ in range(3):
            self.append(guard)
        # Operator deletes entry 1 and duplicates entry 2 as filler, then uses
        # the signing oracle for one new checkpoint and extends it.
        lines = self.log_path.read_bytes().splitlines(keepends=True)
        self.log_path.write_bytes(lines[0] + lines[2] + lines[2])
        self.append(None)
        checkpoints = read_checkpoints(str(self.checkpoints_path))
        self.backend.extend(checkpoint_commitment(checkpoints[-1]))
        entries = read_log(str(self.log_path))
        assert len(entries) == len(checkpoints) == 4, (len(entries), len(checkpoints))

        self.assertEqual(replay_accumulator(initial, checkpoints), self.backend.value)
        self.assertTrue(
            verify_log(
                str(self.log_path), str(self.checkpoints_path), self.public_key
            ).startswith("OK")
        )
        nonce = hashlib.sha256(b"auditor challenge").digest()
        provisioning, bundle, public_pem = self.certify(nonce, len(checkpoints))
        with self.assertRaisesRegex(AttestationError, "checkpoint 2 root"):
            verify_attestation(
                entries,
                checkpoints,
                provisioning,
                bundle,
                nonce,
                public_pem,
                self.device_public_key_path.read_bytes(),
                self.auditor_public_key_path.read_bytes(),
            )

    def certify(self, nonce, checkpoint_count):
        ak_private = ec.generate_private_key(ec.SECP256R1())
        ak_name = bytes.fromhex("000b" + "22" * 32)
        attestation = _nv_attestation(
            ak_name,
            nonce,
            bytes.fromhex(self.backend.name),
            self.backend.value,
        )
        signature = ak_private.sign(attestation, ec.ECDSA(hashes.SHA256()))
        signature = _marshal_ecdsa_signature(signature)
        provisioning = json.loads(self.config_path.read_text(encoding="utf-8"))
        provisioning["ak_name"] = (bytes.fromhex("000b" + "33" * 32)).hex()
        provisioning["ak_qualified_name"] = ak_name.hex()
        bundle = {
            "version": 1,
            "nonce": nonce.hex(),
            "checkpoint_count": checkpoint_count,
            "accumulator": self.backend.value.hex(),
            "attestation": attestation.hex(),
            "signature": signature.hex(),
        }
        public_pem = ak_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        provisioning["ak_public_key_sha256"] = hashlib.sha256(public_pem).hexdigest()
        provisioning["device_signing_public_key_sha256"] = hashlib.sha256(
            self.device_public_key_path.read_bytes()
        ).hexdigest()
        provisioning["auditor_encryption_public_key_sha256"] = hashlib.sha256(
            self.auditor_public_key_path.read_bytes()
        ).hexdigest()
        return provisioning, bundle, public_pem


def _tpm2b(value):
    return len(value).to_bytes(2, "big") + value


def _nv_attestation(ak_name, nonce, nv_name, nv_contents):
    return b"".join(
        [
            (0xFF544347).to_bytes(4, "big"),
            (0x8014).to_bytes(2, "big"),
            _tpm2b(ak_name),
            _tpm2b(nonce),
            (123).to_bytes(8, "big"),
            (1).to_bytes(4, "big"),
            (2).to_bytes(4, "big"),
            b"\x01",
            (3).to_bytes(8, "big"),
            _tpm2b(nv_name),
            (0).to_bytes(2, "big"),
            _tpm2b(nv_contents),
        ]
    )


def _marshal_ecdsa_signature(der_signature):
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der_signature)
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")
    return b"\x00\x18\x00\x0b" + _tpm2b(r_bytes) + _tpm2b(s_bytes)


if __name__ == "__main__":
    unittest.main()
