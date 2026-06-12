use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use crypto::aes::Aes256Gcm;

const DATA_SIZES: [usize; 7] = [64, 256, 1024, 16 * 1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024];

const KEY: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
    0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
];

const NONCE_96: [u8; 12] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];

fn bench_encrypt(c: &mut Criterion) {
    let cipher = Aes256Gcm::new(&KEY);

    for &size in &DATA_SIZES {
        let mut group = c.benchmark_group(size.to_string());
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::from_parameter("AES-256-GCM-encrypt"), |b| {
            b.iter_batched(
                || vec![0xA5_u8; size],
                |mut data| {
                    let _tag = cipher.encrypt_in_place(&mut data, &NONCE_96, &[]);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.finish();
    }
}

fn bench_decrypt(c: &mut Criterion) {
    let cipher = Aes256Gcm::new(&KEY);

    for &size in &DATA_SIZES {
        let mut group = c.benchmark_group(size.to_string());
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::from_parameter("AES-256-GCM-decrypt"), |b| {
            b.iter_batched(
                || {
                    let mut data = vec![0xA5_u8; size];
                    let tag = cipher.encrypt_in_place(&mut data, &NONCE_96, &[]);
                    (data, tag)
                },
                |(mut data, tag)| {
                    let _result = cipher.decrypt_in_place(&mut data, &tag, &NONCE_96, &[]);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.finish();
    }
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
