use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crypto::{
    Hasher,
    sha2::{Sha256, Sha512},
    sha3::{Sha3_256, Sha3_512},
};

const DATA_SIZES: [usize; 7] = [64, 256, 1024, 16 * 1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024];

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

fn bench_sha3_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3-256");

    for &size in &DATA_SIZES {
        let data = vec![0xC3_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let _ = Sha3_256::hash(black_box(data.as_slice()));
            });
        });
    }

    group.finish();
}

fn bench_sha3_512(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3-512");

    for &size in &DATA_SIZES {
        let data = vec![0x3C_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let _ = Sha3_512::hash(black_box(data.as_slice()));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_sha256, bench_sha512, bench_sha3_256, bench_sha3_512);
criterion_main!(benches);
