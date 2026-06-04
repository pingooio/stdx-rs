use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use crypto::curve25519::ed25519::SecretKey;

const DATA_SIZES: [usize; 5] = [64, 256, 1024, 16 * 1024, 64 * 1024];

fn bench_ed25519(c: &mut Criterion) {
    let sk = black_box(SecretKey::generate());
    let pk = black_box(sk.public_key());

    for &size in &DATA_SIZES {
        let mut group = c.benchmark_group(format!("ed25519 {size}B msg"));
        group.throughput(Throughput::Bytes(size as u64));

        let msg = vec![0xA5_u8; size];

        group.bench_with_input(BenchmarkId::from_parameter("sign"), &msg, |b, msg| {
            b.iter(|| {
                let sig = sk.sign(black_box(msg.as_slice()));
                black_box(sig);
            });
        });

        group.bench_with_input(BenchmarkId::from_parameter("verify"), &msg, |b, msg| {
            let sig = sk.sign(msg.as_slice());
            b.iter(|| {
                black_box(pk.verify(black_box(msg.as_slice()), black_box(&sig)).is_ok());
            });
        });

        group.finish();
    }
}

criterion_group!(benches, bench_ed25519);
criterion_main!(benches);
