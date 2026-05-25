use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crypto::{
    Hmac,
    sha2::{Sha256, Sha512},
};

const DATA_SIZES: [usize; 7] = [64, 256, 1024, 16 * 1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024];

fn bench_hmac_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac-sha256");
    let key = b"stdx-rs-crypto-bench-key";

    for &size in &DATA_SIZES {
        let data = vec![0x36_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut hmac = Hmac::<Sha256>::new(black_box(key));
                hmac.update(black_box(data.as_slice()));
                let _ = hmac.finalize();
            });
        });
    }

    group.finish();
}

fn bench_hmac_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac-sha512");
    let key = b"stdx-rs-crypto-bench-key";

    for &size in &DATA_SIZES {
        let data = vec![0x5c_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut hmac = Hmac::<Sha512>::new(black_box(key));
                hmac.update(black_box(data.as_slice()));
                let _ = hmac.finalize();
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_hmac_sha256, bench_hmac_sha512);
criterion_main!(benches);
