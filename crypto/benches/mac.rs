use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crypto::{
    Hmac,
    poly1305::poly1305_mac,
    sha2::{Sha256, Sha512},
    sha3::Kmac256,
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

fn bench_kmac256(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac256");
    let key: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
        0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    ];
    let customization = b"stdx-rs";

    for &size in &DATA_SIZES {
        let data = vec![0xA3_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut kmac = Kmac256::new(black_box(&key), black_box(customization));
                kmac.update(black_box(data.as_slice()));
                let mut out = [0u8; 32];
                kmac.finalize_into(&mut out);
                black_box(out);
            });
        });
    }

    group.finish();
}

fn bench_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly1305");
    let key: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
        0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    ];

    for &size in &DATA_SIZES {
        let data = vec![0xA3_u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let out = poly1305_mac(&key, &data);
                black_box(out);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_hmac_sha256, bench_hmac_sha512, bench_kmac256, bench_poly1305);
criterion_main!(benches);
