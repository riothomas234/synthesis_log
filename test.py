from logentry import generate_keypair
from sequence_crypto import generate_auditor_keypair, decrypt_sequence
from log import append_entry, read_log, read_checkpoints

private_key, public_key = generate_keypair()
auditor_private_key, auditor_public_key = generate_auditor_keypair()

append_entry(raw_sequence="ACGTACGTGGCCTTAACCGGATCG", metadata={"length_bp": 500}, private_key=private_key, auditor_public_key=auditor_public_key)
append_entry(raw_sequence="TTTTAAAACCCCGGGGACGTACGT", metadata={"length_bp": 620}, private_key=private_key, auditor_public_key=auditor_public_key)

print("entries:")
for e in read_log():
    print(" ", e)

print("checkpoints:")
for c in read_checkpoints():
    print(" ", c)

print("decrypted sequences (auditor-only):")
for e in read_log():
    print(" ", decrypt_sequence(bytes.fromhex(e["seq_ciphertext"]), auditor_private_key))
