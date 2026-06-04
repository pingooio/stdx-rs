use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crypto::{
    Hasher,
    sha2::{Sha256, Sha512},
    sha3::{Sha3_256, Sha3_512},
};

const DATA_SIZES: [usize; 7] = [64, 256, 1024, 16 * 1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024];

fn bench_hashes(c: &mut Criterion) {
    for &size in &DATA_SIZES {
        let mut group = c.benchmark_group(size.to_string());
        group.throughput(Throughput::Bytes(size as u64));

        let data = vec![0xA5_u8; size];

        group.bench_with_input(BenchmarkId::from_parameter("SHA-256"), &data, |b, data| {
            b.iter(|| {
                let _ = Sha256::hash(black_box(data.as_slice()));
            });
        });

        group.bench_with_input(BenchmarkId::from_parameter("SHA-512"), &data, |b, data| {
            b.iter(|| {
                let _ = Sha512::hash(black_box(data.as_slice()));
            });
        });

        group.bench_with_input(BenchmarkId::from_parameter("SHA3-256"), &data, |b, data| {
            b.iter(|| {
                let _ = Sha3_256::hash(black_box(data.as_slice()));
            });
        });

        group.bench_with_input(BenchmarkId::from_parameter("SHA3-512"), &data, |b, data| {
            b.iter(|| {
                let _ = Sha3_512::hash(black_box(data.as_slice()));
            });
        });

        group.finish();
    }
}

criterion_group!(benches, bench_hashes);
criterion_main!(benches);
