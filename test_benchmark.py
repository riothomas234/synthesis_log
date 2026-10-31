import tempfile
import unittest
from pathlib import Path

from benchmark import (
    MerkleFrontier,
    _synthetic_attestation,
    create_fixture,
    materialize_prefix,
)
from log import read_checkpoints, read_log
from logentry import load_public_key
from merkletree import compute_root
from verify import verify_log
from tpm_verify import verify_attestation


class BenchmarkTests(unittest.TestCase):
    def test_frontier_matches_production_tree(self):
        frontier = MerkleFrontier()
        leaves = []
        for index in range(1, 65):
            leaf = bytes([index]) * 32
            leaves.append(leaf)
            self.assertEqual(frontier.append(leaf), compute_root(leaves))

    def test_fixture_prefix_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = create_fixture(root / "source", 12, 100)
            prefix = materialize_prefix(fixture, root / "prefix", 10)
            report = verify_log(
                str(prefix.log),
                str(prefix.checkpoints),
                load_public_key(str(prefix.device_public)),
            )
            self.assertEqual(report, "OK, 10 entries, root matches signed checkpoint")

    def test_synthetic_auditor_bundle_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = create_fixture(Path(directory) / "fixture", 4, 100)
            entries = read_log(str(fixture.log))
            checkpoints = read_checkpoints(str(fixture.checkpoints))
            nonce = bytes.fromhex("42" * 32)
            provisioning, bundle, ak_public, device_public, auditor_public = (
                _synthetic_attestation(entries, checkpoints, fixture, nonce)
            )
            verify_attestation(
                entries,
                checkpoints,
                provisioning,
                bundle,
                nonce,
                ak_public,
                device_public,
                auditor_public,
            )


if __name__ == "__main__":
    unittest.main()
