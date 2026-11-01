# Performance profiling

`benchmark.py` measures the public synthesis-log lifecycle with synthetic DNA
payloads. It keeps fixture construction and file copying outside measured
intervals and records both warm steady-state and cold-process observations.

Run the complete software profile and physical TPM validation on the TPM host:

```sh
python3 benchmark.py run \
  --output-dir profiling/mintbox-tpm-scale \
  --tpm-index 0x01534c49 \
  --ak-context 0x81010010 \
  --ek-context 0x81010001 \
  --sudo
```

The TPM index must be unused and owner-deletable. The runner refuses to
overwrite an existing index and removes only the supplied disposable index.
Use `--quick` for the small smoke workload and `--resume` to retain complete
sample groups while rerunning incomplete groups. When profiling from a copied
source tree, pass `--source-commit COMMIT` to preserve repository provenance.

Regenerate summaries and dependency-free SVG plots from existing raw data:

```sh
python3 benchmark.py report --output-dir profiling/mintbox-tpm-scale
```

Run the lifetime-capacity profile with one representative 45-base sequence
length and direct measurements through one million log entries:

```sh
python3 benchmark.py run \
  --lifetime \
  --output-dir profiling/mintbox-lifetime-scale \
  --tpm-reference profiling/mintbox-tpm-scale/raw.jsonl
```

The lifetime profile measures linear append and verification paths directly,
but stops the quadratic historical-prefix auditor check at 10,000 entries. It
projects physical-TPM append latency from the measured physical command costs
in the reference result set rather than performing a million NV writes.

The output directory contains:

- `raw.jsonl`: one durable record per observation, with milliseconds and MiB.
- `summary.csv`: grouped latency, throughput, and memory statistics.
- `report.md`: methodology and key findings.
- `latency.svg` and `memory.svg`: log-scaled entry-count plots.

The named `mintbox-tpm-scale` result set was measured on a Lenovo ThinkCentre. Its
10,000-entry physical TPM append is explicitly labeled as a projection from
measured software scaling and measured TPM command costs.
