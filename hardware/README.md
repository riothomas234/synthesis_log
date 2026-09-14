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
  --ak-context 0x81010010 \
  --ak-public-key signing.pem \
  --device-public-key keys/device_public_key.pem \
  --auditor-public-key keys/auditor_public_key.pem \
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
  --signing-context 0x81010010 \
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
  --device-public-key keys/device_public_key.pem \
  --auditor-public-key keys/auditor_public_key.pem
```

Verification first runs `verify.py`'s checks (last checkpoint root and device
signature), then checks the ECDSA signature, fresh nonce, attestation type, AK
Name, NV Name, offset, checkpoint count, all three provisioned public-key
bindings, the accumulator recomputed from the complete checkpoint history, and
that every checkpoint's root equals the root of the corresponding prefix of
log entries. The prefix check is what ties the TPM-bound checkpoint history to
the entries: without it, an operator with signing-oracle access could delete an
extended entry, sign and extend one new checkpoint for the altered log, and
still pass replay.

## Immutable deployment

After the mutable workflow passes, replace the disposable index with a
platform-created `policydelete` extend index. Its deletion branch must require
an offline auditor signature and `TPM2_CC_NV_UndefineSpaceSpecial`. Use
`PolicySigned` with a session nonce and command-parameter hash so an
authorization is fresh and bound to the intended index deletion. Neither
platform authorization nor the auditor deletion private key belongs on the
device.

Creating a `policydelete` index requires platform-hierarchy authorization. PC
firmware commonly keeps that authorization from the operating system. Such a
machine can run the complete mutable integration and audit workflow but cannot
be provisioned with the production index from host software; it needs a
firmware/OEM provisioning path or a TPM platform whose owner controls platform
authorization. An authorization failure from `tpm2_nvdefine -C p` must not be
worked around by falling back to an owner-created index.

Test the deletion policy on a disposable software TPM or development platform:

1. Normal owner-authorized extension succeeds.
2. Ordinary platform or owner deletion fails.
3. A policy session missing the auditor signature fails inside the TPM.
4. The auditor-signed `TPM2_NV_UndefineSpaceSpecial` succeeds and frees the
   handle.

An auditor-deletable index provides the required resistance to device root
without permanently consuming the handle. An empty or otherwise unsatisfiable
deletion policy makes the allocation intentionally undeletable and is not
needed for the normal deployment.

Root can still stop logging, extend garbage, destroy the TPM, or replace the
machine. Those actions cause denial of service or detectable reprovisioning;
this mechanism cannot prove that logging software observed every physical
synthesis event.
