# mintbox-lifetime-scale

## Method

Latency is wall-clock time on a Lenovo ThinkCentre. Warm results exclude one warmup. Cold results include process startup. Peak RSS is total process memory; Python heap is measured with tracemalloc. Synthetic payload generation and fixture copying are outside timed intervals.

Host: AMD Ryzen 5 8500GE w/ Radeon 740M Graphics; 14.22 GiB RAM; CPU governor powersave; Python 3.14.4; cryptography 46.0.5; tpm2-tools tool="tpm2_getcap" version="5.7" tctis="libtss2-tctildr" tcti-default=tcti-device.

Core source commit: `3e6cebd2cba0d06896d163eac7c66e5e19076d58`.

The physical TPM is a Nuvoton NPCT75x. Physical measurements use a disposable NV index and the established persistent AK. The 1,000,000-entry TPM append is projected from measured software scaling and physical TPM command costs.

## Key findings

- Projected physical TPM append at 1,000,000 prior entries: 13258.29 ms, combining measured software scaling with measured TPM command costs.
- Software-only append at 1,000,000 prior entries: 6506.09 ms median.
- Latest-checkpoint verification at 10,000 entries: 76.43 ms; full historical-prefix auditor verification: 22246.54 ms.
- Maximum measured process RSS across warm operations: 5380.24 MiB.

## Warm measurements

| Status | Backend | Operation | Entries | Payload (B) | n | Median (ms) | p95 (ms) | Peak RSS (MiB) | Python heap (MiB) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| measured | software | append_guard_simulated | 0 | 45 | 10 | 0.36 | 0.42 | 32.99 | 0.26 |
| measured | software | append_guard_simulated | 1 | 45 | 10 | 0.39 | 0.44 | 32.91 | 0.26 |
| measured | software | append_guard_simulated | 10 | 45 | 10 | 0.47 | 0.51 | 33.01 | 0.28 |
| measured | software | append_guard_simulated | 100 | 45 | 10 | 1.25 | 1.30 | 33.46 | 0.50 |
| measured | software | append_guard_simulated | 1000 | 45 | 10 | 8.63 | 9.06 | 39.12 | 2.69 |
| measured | software | append_guard_simulated | 10000 | 45 | 5 | 96.79 | 98.05 | 91.92 | 24.73 |
| measured | software | append_guard_simulated | 100000 | 45 | 3 | 1157.48 | 1175.64 | 580.12 | 245.14 |
| measured | software | append_guard_simulated | 1000000 | 45 | 1 | 12381.31 | 12381.31 | 5380.24 | 2450.98 |
| measured | software | append_software | 0 | 45 | 10 | 0.17 | 0.19 | 32.95 | 0.13 |
| measured | software | append_software | 1 | 45 | 10 | 0.19 | 0.21 | 32.91 | 0.14 |
| measured | software | append_software | 10 | 45 | 10 | 0.22 | 0.25 | 32.89 | 0.14 |
| measured | software | append_software | 100 | 45 | 10 | 0.57 | 0.60 | 33.11 | 0.26 |
| measured | software | append_software | 1000 | 45 | 10 | 3.94 | 4.27 | 36.88 | 1.42 |
| measured | software | append_software | 10000 | 45 | 5 | 46.10 | 51.77 | 64.96 | 13.14 |
| measured | software | append_software | 100000 | 45 | 3 | 616.96 | 618.07 | 349.03 | 131.17 |
| measured | software | append_software | 1000000 | 45 | 1 | 6506.09 | 6506.09 | 3533.07 | 1310.19 |
| measured | software | restart_initialize | 0 | 45 | 10 | 0.05 | 0.05 | 31.92 | 0.13 |
| measured | software | verify_auditor | 0 | 45 | 10 | 0.11 | 0.13 | 32.68 | 0.13 |
| measured | software | verify_auditor | 1 | 45 | 10 | 0.24 | 0.27 | 32.73 | 0.14 |
| measured | software | verify_auditor | 10 | 45 | 10 | 0.40 | 0.44 | 32.75 | 0.15 |
| measured | software | verify_auditor | 100 | 45 | 10 | 3.99 | 4.00 | 33.25 | 0.32 |
| measured | software | verify_auditor | 1000 | 45 | 10 | 234.87 | 236.57 | 38.39 | 2.08 |
| measured | software | verify_auditor | 10000 | 45 | 5 | 22246.54 | 22703.14 | 87.32 | 20.46 |
| measured | software | verify_software | 0 | 45 | 10 | 0.02 | 0.02 | 31.88 | 0.13 |
| measured | software | verify_software | 1 | 45 | 10 | 0.11 | 0.14 | 32.18 | 0.14 |
| measured | software | verify_software | 10 | 45 | 10 | 0.17 | 0.19 | 31.91 | 0.15 |
| measured | software | verify_software | 100 | 45 | 10 | 0.77 | 0.80 | 32.40 | 0.31 |
| measured | software | verify_software | 1000 | 45 | 10 | 6.62 | 7.67 | 36.71 | 2.06 |
| measured | software | verify_software | 10000 | 45 | 5 | 76.43 | 79.20 | 85.16 | 19.67 |
| measured | software | verify_software | 100000 | 45 | 3 | 830.49 | 849.46 | 520.72 | 195.70 |
| measured | software | verify_software | 1000000 | 45 | 1 | 8921.79 | 8921.79 | 4794.02 | 1956.95 |
| projected | physical_tpm_projected | append_tpm | 1000000 | 45 | 0 | 13258.29 | 13258.29 | 5380.24 | 2450.98 |
