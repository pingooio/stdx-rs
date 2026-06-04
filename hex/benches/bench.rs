use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use hex::{Alphabet, decode_into, encode_into};

fn bench_encode(c: &mut Criterion) {
    let sizes = [16, 256, 4096, 65536, 1048576];
    let mut group = c.benchmark_group("encode");

    for &size in &sizes {
        let data = vec![0xABu8; size];
        let mut output = vec![0u8; size * 2];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("lower", size), &data, |b, data| {
            b.iter(|| encode_into(black_box(&mut output), black_box(data), Alphabet::Lower));
        });
        group.bench_with_input(BenchmarkId::new("upper", size), &data, |b, data| {
            b.iter(|| encode_into(black_box(&mut output), black_box(data), Alphabet::Upper));
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let sizes = [16, 256, 4096, 65536, 1048576];
    let mut group = c.benchmark_group("decode");

    for &size in &sizes {
        let raw = vec![0xABu8; size];
        let hex = raw
            .iter()
            .flat_map(|b| {
                let hi = b"0123456789abcdef"[(b >> 4) as usize];
                let lo = b"0123456789abcdef"[(b & 0x0F) as usize];
                [hi, lo]
            })
            .collect::<Vec<_>>();
        let mut output = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("lower", size), &hex, |b, hex| {
            b.iter(|| decode_into(black_box(&mut output), black_box(hex)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
