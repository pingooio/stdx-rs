# LZ4 benchmark results

- Date (UTC): 2026-05-23 15:42:12
- Command: `cargo bench -p lz4@0.1.0 --bench comparison -- --sample-size 30`
- Tool: Criterion

## Compression (lower time is better)

| Dataset | Ours (µs) | Reference (µs) | Ours MiB/s | Ref MiB/s | Speed ratio (ref/ours) |
|---|---:|---:|---:|---:|---:|
| compressible-1024 | 7.440 | 0.286 | 131.26 | 3418.88 | 26.0x |
| random-1024 | 6.933 | 0.527 | 140.85 | 1853.47 | 13.2x |
| compressible-16384 | 41.336 | 1.495 | 378.00 | 10450.14 | 27.6x |
| random-16384 | 35.383 | 2.107 | 441.60 | 7416.97 | 16.8x |
| compressible-131072 | 294.291 | 10.335 | 424.75 | 12095.15 | 28.5x |
| random-131072 | 749.473 | 8.694 | 166.78 | 14377.41 | 86.2x |

## Decompression of reference-compressed blocks (lower time is better)

| Dataset | Ours (µs) | Reference (µs) | Ours MiB/s | Ref MiB/s | Speed ratio (ref/ours) |
|---|---:|---:|---:|---:|---:|
| compressible-1024 | 0.607 | 0.117 | 1608.77 | 8379.34 | 5.2x |
| random-1024 | 0.073 | 0.073 | 13342.27 | 13414.03 | 1.0x |
| compressible-16384 | 9.170 | 0.963 | 1703.87 | 16232.91 | 9.5x |
| random-16384 | 0.619 | 0.622 | 25262.18 | 25130.42 | 1.0x |
| compressible-131072 | 72.984 | 7.271 | 1712.71 | 17191.75 | 10.0x |
| random-131072 | 4.734 | 4.716 | 26404.84 | 26503.27 | 1.0x |

### Notes
- These numbers are from the current CI/container environment and are mainly for relative comparison between implementations.
- The benchmark includes both compressible and random inputs at 1KiB, 16KiB, and 128KiB.
