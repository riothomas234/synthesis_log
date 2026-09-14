# TPM prototype

The optional hardware mode uses a TPM 2.0 SHA-256 NV extend index. It is not
tied to a Raspberry Pi or a particular TPM module. The prototype invokes
`tpm2-tools` directly and has been exercised with a discrete Nuvoton NPCT75x.

Hardware mode adds rollback and fork evidence to the existing Merkle tree. It
does not replace the tree: the tree commits to every log entry, while the TPM
accumulator prevents an operator from presenting an earlier signed tree state
as current during a live audit.

## Mutable test setup

Use a disposable owner-created index while testing. This index is deliberately
deletable and therefore does not provide a root-resistant production
guarantee.

```sh
sudo tpm2_nvdefine 0x01534c47 -C o -s 32 -g sha256 \
  -a 'ownerwrite|authwrite|ownerread|authread|nt=extend|no_da'
```

Create or load a restricted ECC signing key and retain its public key, Name,
qualified Name, and attributes as auditor provisioning material. Enrollment
rejects an unrestricted signing key because root could use one as an oracle to
sign fabricated attestation bytes. The `--ak-context` argument may be a context
file for a bench session or a persistent TPM handle for a durable deployment.
Enroll only against a fresh pair of log and checkpoint files: the observed NV
value becomes `A_0` for that log.

```sh
python3 tpm_guard.py enroll \
  --config tpm-guard.json \
  --index 0x01534c47 \
  --ak-context signing.ctx \
  --ak-public-key signing.pem \
  --sudo
```

Pass the enrolled guard explicitly when appending:

```python
from tpm_guard import TPMGuard

guard = TPMGuard("tpm-guard.json")
append_entry(..., rollback_guard=guard)
```

If no guard is passed, behavior and file formats are unchanged. Once a guard is
passed, an unavailable or mismatched TPM aborts the append; there is no silent
software fallback.

## Crash recovery

The guarded append holds a process lock and performs these operations:

1. Verify that replaying every checkpoint from `A_0` equals the live NV value.
2. Durably write a pending journal containing both exact JSONL records.
3. Extend the checkpoint commitment into the TPM.
4. Read the NV value back and compare it with the expected extension result.
5. Durably append the entry and checkpoint, then remove the journal.

On restart, the pending journal distinguishes the two recoverable states. If
the TPM still contains the recorded prior value, recovery performs the extend.
If it contains the recorded result, recovery writes any missing or partial
JSONL record without extending again. Any other value or unexpected file
content fails closed.

## Live audit

The auditor generates a fresh random 32-byte nonce. On the device:

```sh
python3 tpm_audit.py \
  --config tpm-guard.json \
  --checkpoints checkpoints.jsonl \
  --signing-context signing.ctx \
  --nonce "$NONCE_HEX" \
  --output attestation.json
```

The auditor retains the enrollment JSON, AK public key, and device public key
independently, then verifies the returned bundle against the log:

```sh
python3 tpm_verify.py \
  --provisioning tpm-guard.json \
  --log synthlog.jsonl \
  --checkpoints checkpoints.jsonl \
  --bundle attestation.json \
  --nonce "$NONCE_HEX" \
  --ak-public-key signing.pem \
  --device-public-key keys/device_public_key.pem
```

Verification first runs `verify.py`'s checks (last checkpoint root and device
signature), then checks the ECDSA signature, fresh nonce, attestation type, AK
Name, NV Name, offset, checkpoint count, the accumulator recomputed from the
complete checkpoint history, and that every checkpoint's root equals the root
of the corresponding prefix of log entries. The prefix check is what ties the
TPM-bound checkpoint history to the entries: without it, an operator with
signing-oracle access could delete an extended entry, sign and extend one new
checkpoint for the altered log, and still pass replay.

## Immutable deployment

After the mutable workflow passes, replace the disposable index with a
platform-created `policydelete` extend index. Its deletion branch must require
an offline auditor authorization and `TPM2_CC_NV_UndefineSpaceSpecial`.
Neither platform authorization nor an auditor deletion private key belongs on
the device. Test that policy using a deletable auditor-controlled policy before
creating an intentionally undeletable index.

Root can still stop logging, extend garbage, destroy the TPM, or replace the
machine. Those actions cause denial of service or detectable reprovisioning;
this mechanism cannot prove that logging software observed every physical
synthesis event.
