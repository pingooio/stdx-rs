use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use lz4::{compress, decompress};
use lz4_reference::block as reference;

fn deterministic_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    let mut out = vec![0u8; len];
    for byte in &mut out {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = (state & 0xFF) as u8;
    }
    out
}

fn compressible_bytes(len: usize) -> Vec<u8> {
    let pattern = b"abcdabcdabcdabcd";
    pattern.iter().copied().cycle().take(len).collect()
}

fn benchmark_compress(c: &mut Criterion) {
    let mut group = c.benchmark_group("compress");
    for &size in &[1024usize, 16 * 1024, 128 * 1024] {
        let compressible = compressible_bytes(size);
        let random = deterministic_bytes(size, size as u32 + 17);

        for (kind, input) in [("compressible", &compressible), ("random", &random)] {
            group.throughput(Throughput::Bytes(input.len() as u64));
            group.bench_with_input(BenchmarkId::new("ours", format!("{kind}-{size}")), input, |b, data| {
                b.iter(|| compress(black_box(data)).expect("ours compress failed"))
            });
            group.bench_with_input(BenchmarkId::new("reference", format!("{kind}-{size}")), input, |b, data| {
                b.iter(|| reference::compress(black_box(data), None, false).expect("reference compress failed"))
            });
        }
    }
    group.finish();
}

fn benchmark_decompress(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompress");
    for &size in &[1024usize, 16 * 1024, 128 * 1024] {
        let compressible = compressible_bytes(size);
        let random = deterministic_bytes(size, size as u32 + 31);

        for (kind, input) in [("compressible", &compressible), ("random", &random)] {
            let ours_compressed = compress(input).expect("ours compress setup failed");
            let reference_compressed =
                reference::compress(input, None, false).expect("reference compress setup failed");

            group.throughput(Throughput::Bytes(input.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("ours-from-ours", format!("{kind}-{size}")),
                &ours_compressed,
                |b, data| b.iter(|| decompress(black_box(data), size).expect("ours decompress failed")),
            );
            group.bench_with_input(
                BenchmarkId::new("reference-from-ours", format!("{kind}-{size}")),
                &ours_compressed,
                |b, data| {
                    b.iter(|| {
                        reference::decompress(black_box(data), Some(size as i32)).expect("reference decompress failed")
                    })
                },
            );
            group.bench_with_input(
                BenchmarkId::new("ours-from-reference", format!("{kind}-{size}")),
                &reference_compressed,
                |b, data| b.iter(|| decompress(black_box(data), size).expect("ours decompress failed")),
            );
            group.bench_with_input(
                BenchmarkId::new("reference-from-reference", format!("{kind}-{size}")),
                &reference_compressed,
                |b, data| {
                    b.iter(|| {
                        reference::decompress(black_box(data), Some(size as i32)).expect("reference decompress failed")
                    })
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, benchmark_compress, benchmark_decompress);
criterion_main!(benches);
