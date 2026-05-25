use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crypto::{Hasher, Sha256, Sha512};

const DATA_SIZES: [usize; 7] = [
    64,
    256,
    1024,
    16 * 1024,
    64 * 1024,
    1024 * 1024,
    10 * 1024 * 1024,
];

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for &size in &DATA_SIZES {
        let data = vec![0xA5_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let _ = Sha256::hash(black_box(data.as_slice()));
            });
        });
    }

    group.finish();
}

fn bench_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512");

    for &size in &DATA_SIZES {
        let data = vec![0x5A_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let _ = Sha512::hash(black_box(data.as_slice()));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_sha256, bench_sha512);
criterion_main!(benches);
