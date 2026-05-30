use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tgcryptors_core::{
    cbc256_decrypt, cbc256_encrypt, ctr256_encrypt, ige256_decrypt, ige256_encrypt,
};

fn bench_ige256(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let iv = [0x24u8; 32];

    let mut group = c.benchmark_group("ige256");

    for size in [1048576, 16777216, 67108864, 268435456].iter() {
        let data: Vec<u8> = (0..*size).map(|i| (i & 0xFF) as u8).collect();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| ige256_encrypt(data, &key, &iv))
        });

        let encrypted = ige256_encrypt(&data, &key, &iv);
        group.bench_with_input(BenchmarkId::new("decrypt", size), &encrypted, |b, data| {
            b.iter(|| ige256_decrypt(data, &key, &iv))
        });
    }

    group.finish();
}

fn bench_ctr256(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let iv_orig = [0x24u8; 16];

    let mut group = c.benchmark_group("ctr256");

    for size in [1048576, 16777216, 67108864, 268435456].iter() {
        let data: Vec<u8> = (0..*size).map(|i| (i & 0xFF) as u8).collect();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| {
                let mut iv = iv_orig;
                let mut state = 0u8;
                ctr256_encrypt(data, &key, &mut iv, &mut state)
            })
        });
    }

    group.finish();
}

fn bench_cbc256(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let iv_orig = [0x24u8; 16];

    let mut group = c.benchmark_group("cbc256");

    for size in [1048576, 16777216, 67108864, 268435456].iter() {
        let data: Vec<u8> = (0..*size).map(|i| (i & 0xFF) as u8).collect();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| {
                let mut iv = iv_orig;
                cbc256_encrypt(data, &key, &mut iv)
            })
        });

        let mut enc_iv = iv_orig;
        let encrypted = cbc256_encrypt(&data, &key, &mut enc_iv);
        group.bench_with_input(BenchmarkId::new("decrypt", size), &encrypted, |b, data| {
            b.iter(|| {
                let mut iv = iv_orig;
                cbc256_decrypt(data, &key, &mut iv)
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_ige256, bench_ctr256, bench_cbc256);
criterion_main!(benches);
