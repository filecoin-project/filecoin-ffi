use filecrypto::proofs::{api, types};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::Value

pub fn agg_verify_benchmark(c: &mut Criterion) {
    let agg_str = std::include_str!("agg1.json");
    let v Value = serde_json::from_str(agg_str)?;



    c.bench_function("agg 1.6k", |b| b.iter(|| {
        //api::fil_verify_aggregate_seal_proof(inputs from agg1.json)

    }));
}

criterion_group!(benches, agg_verify_benchmark);
criterion_main!(benches);
