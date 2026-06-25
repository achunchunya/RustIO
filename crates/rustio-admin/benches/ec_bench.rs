use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::time::Duration;

fn encode_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ec_encode");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for (data, parity) in [(4, 1), (8, 2)] {
        for size_kb in [64u64, 256, 1024, 16384] {
            let size = (size_kb * 1024) as usize;
            let label = format!("d{data}p{parity}_{size_kb}kb");
            group.throughput(Throughput::Bytes(size as u64));

            group.bench_function(BenchmarkId::new("encode", &label), |b| {
                let rs = ReedSolomon::new(data, parity).unwrap();
                let shard_size = size.div_ceil(data).max(1);
                let mut shards: Vec<Vec<u8>> = (0..data)
                    .map(|i| vec![(i as u8).wrapping_add(b'x'); shard_size])
                    .collect();
                for _ in 0..parity {
                    shards.push(vec![0u8; shard_size]);
                }

                b.iter(|| {
                    rs.encode(black_box(&mut shards)).unwrap();
                });
            });

            group.bench_function(BenchmarkId::new("encode_streaming_1mb_blocks", &label), |b| {
                let rs = ReedSolomon::new(data, parity).unwrap();
                let shard_size = size.div_ceil(data).max(1);
                let src_shards: Vec<Vec<u8>> = (0..data)
                    .map(|i| vec![(i as u8).wrapping_add(b'x'); shard_size])
                    .collect();
                const BLOCK: usize = 1024 * 1024;

                b.iter(|| {
                    let mut blocks: Vec<Vec<u8>> = vec![Vec::<u8>::new(); data + parity];
                    let mut produced = 0usize;
                    while produced < shard_size {
                        let this_block = BLOCK.min(shard_size - produced);
                        for block in blocks.iter_mut() {
                            block.resize(this_block, 0u8);
                        }
                        for (idx, src) in src_shards.iter().enumerate() {
                            blocks[idx].copy_from_slice(&src[produced..produced + this_block]);
                        }
                        rs.encode(black_box(&mut blocks)).unwrap();
                        produced += this_block;
                    }
                });
            });
        }
    }
    group.finish();
}

fn reconstruct_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ec_reconstruct");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for (data, parity) in [(4, 1), (8, 2)] {
        for size_kb in [64u64, 256, 1024, 16384] {
            let size = (size_kb * 1024) as usize;
            let label = format!("d{data}p{parity}_{size_kb}kb");
            group.throughput(Throughput::Bytes(size as u64));

            group.bench_function(BenchmarkId::new("reconstruct_lose_1", &label), |b| {
                let rs = ReedSolomon::new(data, parity).unwrap();
                let shard_size = size.div_ceil(data).max(1);
                let mut shards: Vec<Vec<u8>> = (0..data)
                    .map(|i| vec![(i as u8).wrapping_add(b'x'); shard_size])
                    .collect();
                for _ in 0..parity {
                    shards.push(vec![0u8; shard_size]);
                }
                rs.encode(&mut shards).unwrap();

                // 模拟丢失 shard 0，用 parity 重建
                b.iter(|| {
                    let mut loaded: Vec<Option<Vec<u8>>> = shards
                        .clone()
                        .into_iter()
                        .enumerate()
                        .map(|(idx, shard)| if idx == 0 { None } else { Some(shard) })
                        .collect();
                    rs.reconstruct(black_box(&mut loaded)).unwrap();
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, encode_bench, reconstruct_bench);
criterion_main!(benches);
