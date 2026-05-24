# LZ4 benchmark results

- Date (UTC): 2026-05-24 07:32:45
- Command: `cargo bench -p lz4@0.1.0 --bench comparison -- --sample-size 30`
- Tool: Criterion

## Compression (lower time is better)

| Dataset | Ours (µs) | Reference (µs) | Ours MiB/s | Ref MiB/s | Speed ratio (ref/ours) |
|---|---:|---:|---:|---:|---:|
| compressible-1024 | 6.963 | 0.355 | 140.26 | 2754.47 | 19.6x |
| random-1024 | 7.232 | 0.687 | 135.04 | 1420.50 | 10.5x |
| compressible-16384 | 9.023 | 1.766 | 1731.66 | 8849.46 | 5.1x |
| random-16384 | 9.793 | 2.649 | 1595.56 | 5898.84 | 3.7x |
| compressible-131072 | 24.556 | 11.993 | 5090.47 | 10422.69 | 2.0x |
| random-131072 | 19.927 | 10.699 | 6273.01 | 11683.64 | 1.9x |

## Decompression of reference-compressed blocks (lower time is better)

| Dataset | Ours (µs) | Reference (µs) | Ours MiB/s | Ref MiB/s | Speed ratio (ref/ours) |
|---|---:|---:|---:|---:|---:|
| compressible-1024 | 0.708 | 0.225 | 1378.66 | 4337.09 | 3.1x |
| random-1024 | 0.079 | 0.084 | 12397.35 | 11622.41 | 0.9x |
| compressible-16384 | 10.477 | 1.259 | 1491.34 | 12414.92 | 8.3x |
| random-16384 | 5.855 | 5.857 | 2668.53 | 2667.68 | 1.0x |
| compressible-131072 | 83.373 | 10.153 | 1499.29 | 12311.15 | 8.2x |
| random-131072 | 4.762 | 4.616 | 26251.04 | 27079.98 | 1.0x |

### Notes
- These numbers are from the current CI/container environment and are mainly for relative comparison between implementations.
- The benchmark includes both compressible and random inputs at 1KiB, 16KiB, and 128KiB.
