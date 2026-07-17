


from logentry import generate_keypair
from log import append_entry, read_log, read_checkpoints

private_key, public_key = generate_keypair()
append_entry(seq_commit="deadbeef", metadata={"length_bp": 500}, private_key=private_key)
append_entry(seq_commit="cafef00d", metadata={"length_bp": 620}, private_key=private_key)

print("entries:")
for e in read_log():
    print(" ", e)

print("checkpoints:")
for c in read_checkpoints():
    print(" ", c)