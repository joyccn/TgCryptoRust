use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use tgcryptors_core::{
    cbc256_decrypt, cbc256_encrypt, ctr256_encrypt, ctr256_encrypt_into_ek, ige256_decrypt,
    ige256_encrypt, ige256_encrypt_into_ek, ExpandedKey,
};

fn bench_ige256(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let iv = [0x24u8; 32];

    let mut group = c.benchmark_group("ige256");

    for size in [64, 1024, 16384, 262144, 1048576, 16777216].iter() {
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

    for size in [64, 1024, 16384, 262144, 1048576, 16777216].iter() {
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

    for size in [64, 1024, 16384, 262144, 1048576, 16777216].iter() {
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

// Separate key expansion and output allocation from cipher throughput, matching
// the streaming Python API and Rust callers that retain ExpandedKey instances.
fn bench_preexpanded(c: &mut Criterion) {
    let key = ExpandedKey::new_encrypt(&[0x42; 32]);
    let mut group = c.benchmark_group("preexpanded");
    for size in [64, 1024, 16384, 262144, 1048576] {
        let data = vec![0x24; size];
        let mut dest = vec![0; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new("ctr", size), |b| {
            b.iter(|| {
                let mut iv = [0x24; 16];
                let mut state = 0;
                ctr256_encrypt_into_ek(black_box(&data), &key, &mut iv, &mut state, &mut dest);
                black_box(&dest);
            });
        });
        group.bench_function(BenchmarkId::new("ige", size), |b| {
            b.iter(|| {
                let mut iv = [0x24; 32];
                ige256_encrypt_into_ek(black_box(&data), &key, &mut iv, &mut dest);
                black_box(&dest);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_ige256,
    bench_ctr256,
    bench_cbc256,
    bench_preexpanded
);
criterion_main!(benches);
