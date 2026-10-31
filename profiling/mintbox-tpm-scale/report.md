# mintbox-tpm-scale

## Method

Latency is wall-clock time on mintbox-c. Warm results exclude one warmup. Cold results include process startup. Peak RSS is total process memory; Python heap is measured with tracemalloc. Synthetic payload generation and fixture copying are outside timed intervals.

Host: AMD Ryzen 5 8500GE w/ Radeon 740M Graphics; 14.22 GiB RAM; CPU governor powersave; Python 3.14.4; cryptography 46.0.5; tpm2-tools tool="tpm2_getcap" version="5.7" tctis="libtss2-tctildr" tcti-default=tcti-device.

Core source commit: `1849e15695c5ad387c5b1d51b33f966d8347f63d`.

The physical TPM is a Nuvoton NPCT75x. Physical measurements use a disposable NV index and the established persistent AK. The 10,000-entry TPM append is projected; all other rows are measured.

## Key findings

- Physical TPM append at 1,000 prior entries: 891.62 ms median wall time.
- Projected physical TPM append at 10,000 prior entries: 964.78 ms, combining measured software scaling with measured TPM command costs.
- Software-only append at 10,000 prior entries: 87.81 ms median.
- Latest-checkpoint verification at 10,000 entries: 153.50 ms; full historical-prefix auditor verification: 22587.70 ms.
- Maximum measured process RSS across warm operations: 105.94 MiB.

## Warm measurements

| Status | Backend | Operation | Entries | Payload (B) | n | Median (ms) | p95 (ms) | Peak RSS (MiB) | Python heap (MiB) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| measured | physical_tpm | append_tpm | 0 | 1024 | 1 | 870.95 | 870.95 | 73.77 |  |
| measured | physical_tpm | append_tpm | 1 | 1024 | 2 | 874.13 | 878.59 | 73.77 |  |
| measured | physical_tpm | append_tpm | 2 | 1024 | 2 | 877.38 | 878.82 | 73.77 |  |
| measured | physical_tpm | append_tpm | 3 | 1024 | 2 | 874.03 | 874.16 | 73.77 |  |
| measured | physical_tpm | append_tpm | 4 | 1024 | 2 | 877.33 | 877.69 | 73.77 |  |
| measured | physical_tpm | append_tpm | 5 | 1024 | 1 | 872.15 | 872.15 | 73.77 |  |
| measured | physical_tpm | append_tpm | 10 | 1024 | 1 | 874.69 | 874.69 | 73.77 |  |
| measured | physical_tpm | append_tpm | 11 | 1024 | 1 | 873.94 | 873.94 | 73.77 |  |
| measured | physical_tpm | append_tpm | 12 | 1024 | 1 | 874.89 | 874.89 | 73.77 |  |
| measured | physical_tpm | append_tpm | 13 | 1024 | 1 | 868.09 | 868.09 | 73.77 |  |
| measured | physical_tpm | append_tpm | 14 | 1024 | 1 | 870.77 | 870.77 | 73.77 |  |
| measured | physical_tpm | append_tpm | 100 | 1024 | 1 | 873.21 | 873.21 | 73.77 |  |
| measured | physical_tpm | append_tpm | 101 | 1024 | 1 | 947.09 | 947.09 | 73.77 |  |
| measured | physical_tpm | append_tpm | 102 | 1024 | 1 | 875.67 | 875.67 | 73.77 |  |
| measured | physical_tpm | append_tpm | 103 | 1024 | 1 | 877.87 | 877.87 | 73.77 |  |
| measured | physical_tpm | append_tpm | 104 | 1024 | 1 | 874.07 | 874.07 | 73.77 |  |
| measured | physical_tpm | append_tpm | 1000 | 1024 | 1 | 891.62 | 891.62 | 73.77 |  |
| measured | physical_tpm | append_tpm | 1001 | 1024 | 1 | 968.15 | 968.15 | 73.77 |  |
| measured | physical_tpm | append_tpm | 1002 | 1024 | 1 | 894.95 | 894.95 | 73.77 |  |
| measured | physical_tpm | append_tpm | 1003 | 1024 | 1 | 898.93 | 898.93 | 73.77 |  |
| measured | physical_tpm | append_tpm | 1004 | 1024 | 1 | 894.97 | 894.97 | 73.77 |  |
| measured | physical_tpm | audit_create | 0 | 1024 | 1 | 984.96 | 984.96 | 73.77 |  |
| measured | physical_tpm | audit_create | 1 | 1024 | 1 | 982.35 | 982.35 | 73.77 |  |
| measured | physical_tpm | audit_create | 10 | 1024 | 1 | 984.03 | 984.03 | 73.77 |  |
| measured | physical_tpm | audit_create | 100 | 1024 | 1 | 980.86 | 980.86 | 73.77 |  |
| measured | physical_tpm | audit_create | 1000 | 1024 | 1 | 990.18 | 990.18 | 73.77 |  |
| measured | physical_tpm | nv_certify | 0 | 1024 | 10 | 648.42 | 651.96 | 73.77 |  |
| measured | physical_tpm | nv_extend | 0 | 1024 | 10 | 227.35 | 229.95 | 73.77 |  |
| measured | physical_tpm | nv_public | 0 | 1024 | 10 | 25.89 | 26.97 | 73.77 |  |
| measured | physical_tpm | nv_read | 0 | 1024 | 10 | 311.87 | 314.86 | 73.77 |  |
| measured | physical_tpm | provision_ak | 0 | 1024 | 1 | 535.78 | 535.78 | 73.77 |  |
| measured | physical_tpm | provision_enroll | 0 | 1024 | 1 | 357.39 | 357.39 | 73.77 |  |
| measured | physical_tpm | provision_nv | 0 | 1024 | 1 | 377.03 | 377.03 | 73.77 |  |
| measured | physical_tpm | tpm_check | 0 | 1024 | 1 | 332.95 | 332.95 | 73.77 |  |
| measured | physical_tpm | tpm_check | 1 | 1024 | 1 | 338.52 | 338.52 | 73.77 |  |
| measured | physical_tpm | tpm_check | 10 | 1024 | 1 | 336.02 | 336.02 | 73.77 |  |
| measured | physical_tpm | tpm_check | 100 | 1024 | 1 | 329.86 | 329.86 | 73.77 |  |
| measured | physical_tpm | tpm_check | 1000 | 1024 | 1 | 337.15 | 337.15 | 73.77 |  |
| measured | software | append_payload_sweep | 100 | 100 | 10 | 0.95 | 0.97 | 73.77 | 0.45 |
| measured | software | append_payload_sweep | 100 | 1024 | 10 | 0.96 | 1.00 | 73.77 | 0.46 |
| measured | software | append_payload_sweep | 100 | 10240 | 10 | 1.10 | 1.15 | 73.77 | 0.52 |
| measured | software | append_payload_sweep | 100 | 102400 | 10 | 2.82 | 2.88 | 73.77 | 1.18 |
| measured | software | append_software | 0 | 1024 | 10 | 0.19 | 0.22 | 73.77 | 0.14 |
| measured | software | append_software | 1 | 1024 | 10 | 0.21 | 0.23 | 73.77 | 0.15 |
| measured | software | append_software | 10 | 1024 | 10 | 0.28 | 0.31 | 73.77 | 0.17 |
| measured | software | append_software | 100 | 1024 | 10 | 0.97 | 0.98 | 73.77 | 0.46 |
| measured | software | append_software | 1000 | 1024 | 10 | 7.83 | 8.22 | 73.77 | 3.35 |
| measured | software | append_software | 10000 | 1024 | 5 | 87.81 | 91.67 | 87.27 | 32.35 |
| measured | software | restart_initialize | 0 | 1024 | 10 | 0.05 | 0.05 | 73.77 | 0.13 |
| measured | software | restart_initialize | 1 | 1024 | 10 | 0.05 | 0.06 | 73.77 | 0.13 |
| measured | software | restart_initialize | 10 | 1024 | 10 | 0.05 | 0.06 | 73.77 | 0.13 |
| measured | software | restart_initialize | 100 | 1024 | 10 | 0.05 | 0.05 | 73.77 | 0.13 |
| measured | software | restart_initialize | 1000 | 1024 | 10 | 0.05 | 0.05 | 73.77 | 0.13 |
| measured | software | restart_initialize | 10000 | 1024 | 5 | 0.05 | 0.06 | 74.02 | 0.13 |
| measured | software | verify_auditor | 0 | 1024 | 10 | 0.11 | 0.13 | 73.77 | 0.13 |
| measured | software | verify_auditor | 1 | 1024 | 10 | 0.25 | 0.28 | 73.77 | 0.14 |
| measured | software | verify_auditor | 10 | 1024 | 10 | 0.56 | 0.59 | 73.77 | 0.17 |
| measured | software | verify_auditor | 100 | 1024 | 10 | 5.51 | 5.60 | 73.77 | 0.52 |
| measured | software | verify_auditor | 1000 | 1024 | 10 | 249.78 | 251.65 | 73.77 | 4.00 |
| measured | software | verify_auditor | 10000 | 1024 | 5 | 22587.70 | 22779.17 | 105.94 | 39.66 |
| measured | software | verify_software | 0 | 1024 | 10 | 0.02 | 0.02 | 73.77 | 0.13 |
| measured | software | verify_software | 1 | 1024 | 10 | 0.12 | 0.14 | 73.77 | 0.14 |
| measured | software | verify_software | 10 | 1024 | 10 | 0.26 | 0.26 | 73.77 | 0.17 |
| measured | software | verify_software | 100 | 1024 | 10 | 1.53 | 1.58 | 73.77 | 0.50 |
| measured | software | verify_software | 1000 | 1024 | 10 | 14.09 | 14.42 | 73.77 | 3.98 |
| measured | software | verify_software | 10000 | 1024 | 5 | 153.50 | 154.40 | 103.16 | 38.87 |
| projected | physical_tpm_projected | append_tpm | 10000 | 1024 | 0 | 964.78 | 964.78 | 87.27 | 32.35 |
