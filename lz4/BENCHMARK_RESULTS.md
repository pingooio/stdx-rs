# LZ4 benchmark results

- Date (UTC): 2026-05-24 10:23:56
- Command: `cargo bench -p lz4@0.1.0 --bench comparison -- --sample-size 30`
- Tool: Criterion

## Compression (lower time is better)

| Dataset | Ours (µs) | Reference (µs) | Ours MiB/s | Ref MiB/s | Speed ratio (ref/ours) |
|---|---:|---:|---:|---:|---:|
| compressible-1024 | 7.620 | 0.346 | 128.16 | 2821.69 | 22.0x |
| random-1024 | 8.674 | 0.692 | 112.58 | 1410.34 | 12.5x |
| compressible-16384 | 10.279 | 1.763 | 1520.13 | 8861.72 | 5.8x |
| random-16384 | 10.947 | 2.638 | 1427.36 | 5923.47 | 4.1x |
| compressible-131072 | 24.107 | 12.001 | 5185.17 | 10415.49 | 2.0x |
| random-131072 | 21.178 | 10.607 | 5902.26 | 11784.38 | 2.0x |

## Decompression of reference-compressed blocks (lower time is better)

| Dataset | Ours (µs) | Reference (µs) | Ours MiB/s | Ref MiB/s | Speed ratio (ref/ours) |
|---|---:|---:|---:|---:|---:|
| compressible-1024 | 0.142 | 0.145 | 6899.09 | 6736.06 | 1.0x |
| random-1024 | 0.081 | 0.082 | 12098.81 | 11841.67 | 1.0x |
| compressible-16384 | 0.522 | 1.254 | 29951.32 | 12456.97 | 0.4x |
| random-16384 | 0.550 | 0.554 | 28411.12 | 28208.45 | 1.0x |
| compressible-131072 | 4.227 | 10.205 | 29572.05 | 12249.39 | 0.4x |
| random-131072 | 52.826 | 52.786 | 2366.28 | 2368.05 | 1.0x |

### Notes
- These numbers are from the current CI/container environment and are mainly for relative comparison between implementations.
- The benchmark includes both compressible and random inputs at 1KiB, 16KiB, and 128KiB.
