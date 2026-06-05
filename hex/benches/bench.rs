use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use hex::{Alphabet, decode_into, encode_into};

const DATA_SIZES: &[usize] = &[32, 256, 4096, 64 * 1024];

fn bench_encode_decode(c: &mut Criterion) {
    for &size in DATA_SIZES {
        let mut group = c.benchmark_group(size.to_string());
        group.throughput(Throughput::Bytes(size as u64));

        let mut raw_data = vec![0xABu8; size];
        let mut hex = vec![0u8; size * 2];

        group.bench_with_input(BenchmarkId::from_parameter("encode"), &raw_data, |b, data| {
            b.iter(|| encode_into(black_box(&mut hex), black_box(data), Alphabet::Lower));
        });
        group.bench_with_input(BenchmarkId::from_parameter("decode"), &hex, |b, hex| {
            b.iter(|| decode_into(black_box(&mut raw_data), black_box(hex)).unwrap());
        });

        group.finish();
    }
}

#[cfg(target_arch = "aarch64")]
fn bench_scalar_vs_neon(c: &mut Criterion) {
    use hex::encode_into_scalar;

    for &size in DATA_SIZES {
        let mut group = c.benchmark_group(size.to_string());
        group.throughput(Throughput::Bytes(size as u64));

        let data = vec![0xABu8; size];
        let mut output = vec![0u8; size * 2];

        group.bench_with_input(BenchmarkId::new("encode", "scalar"), &data, |b, data| {
            b.iter(|| encode_into_scalar(black_box(&mut output), black_box(data), Alphabet::Lower));
        });
        group.bench_with_input(BenchmarkId::new("encode", "neon"), &data, |b, data| {
            b.iter(|| encode_into(black_box(&mut output), black_box(data), Alphabet::Lower));
        });

        group.finish();
    }
}

// #[cfg(target_arch = "aarch64")]
// fn bench_decode_scalar_vs_simd(c: &mut Criterion) {
//     use hex::decode_into_scalar;

//     let sizes = [32, 256, 4096, 65536];

//     for &size in &sizes {
//         let mut group = c.benchmark_group(size.to_string());
//         group.throughput(Throughput::Bytes(size as u64));

//         let data = vec![0xABu8; size];
//         let hex_input = hex::encode(&data);
//         let mut output = vec![0u8; size];

//         group.bench_with_input(BenchmarkId::new("scalar", size), hex_input.as_bytes(), |b, hex_input| {
//             b.iter(|| decode_into_scalar(black_box(&mut output), black_box(hex_input)).unwrap());
//         });
//         group.bench_with_input(BenchmarkId::new("neon", size), hex_input.as_bytes(), |b, hex_input| {
//             b.iter(|| decode_into(black_box(&mut output), black_box(hex_input)).unwrap());
//         });

//         group.finish();
//     }
// }

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn bench_encode_scalar_vs_simd(c: &mut Criterion) {
    use hex::encode_into_scalar;

    let sizes = [32, 256, 4096, 65536];
    let mut group = c.benchmark_group("encode_scalar_vs_avx2");

    for &size in &sizes {
        group.throughput(Throughput::Bytes(size as u64));

        let data = vec![0xABu8; size];
        let mut output = vec![0u8; size * 2];

        group.bench_with_input(BenchmarkId::new("scalar", size), &data, |b, data| {
            b.iter(|| encode_into_scalar(black_box(&mut output), black_box(data), Alphabet::Lower));
        });
        group.bench_with_input(BenchmarkId::new("avx2", size), &data, |b, data| {
            b.iter(|| encode_into(black_box(&mut output), black_box(data), Alphabet::Lower));
        });

        group.finish();
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn bench_decode_scalar_vs_simd(c: &mut Criterion) {
    use hex::decode_into_scalar;

    let sizes = [32, 256, 4096, 65536];
    let mut group = c.benchmark_group("decode_scalar_vs_avx2");

    for &size in &sizes {
        group.throughput(Throughput::Bytes(size as u64));

        let data = vec![0xABu8; size];
        let hex_input = hex::encode(&data);
        let mut output = vec![0u8; size];

        group.bench_with_input(BenchmarkId::new("scalar", size), hex_input.as_bytes(), |b, hex_input| {
            b.iter(|| decode_into_scalar(black_box(&mut output), black_box(hex_input)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("avx2", size), hex_input.as_bytes(), |b, hex_input| {
            b.iter(|| decode_into(black_box(&mut output), black_box(hex_input)).unwrap());
        });

        group.finish();
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
criterion_group!(
    benches,
    bench_encode_decode,
    bench_encode_scalar_vs_simd,
    bench_decode_scalar_vs_simd
);

#[cfg(target_arch = "aarch64")]
criterion_group!(benches, bench_encode_decode, bench_scalar_vs_neon,);

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
criterion_group!(benches, bench_encode_decode);

criterion_main!(benches);
