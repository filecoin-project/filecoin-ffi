use criterion::{criterion_group, criterion_main, Criterion};
use serde::Deserialize;
use serde_json::Value;

use filcrypto::proofs::api::fil_verify_aggregate_seal_proof;
use filcrypto::proofs::types::{
    fil_32ByteArray, fil_AggregationInputs, fil_RegisteredAggregationProof, fil_RegisteredSealProof,
};

#[derive(Deserialize, Debug)]
struct Info {
    Number: usize,
    Randomness: String,
    InteractiveRandomness: String,
    SealedCID: Value,
    UnsealedCID: Value,
}

#[derive(Deserialize, Debug)]
struct AggregateEntry {
    Miner: usize,
    SealProof: usize,
    AggregateProof: usize,
    Proof: String,
    Infos: Vec<Info>,
}

pub fn agg_verify_benchmark(c: &mut Criterion) {
    let agg_str = std::include_str!("agg1.json");
    let values: Value = serde_json::from_str(agg_str).expect("failed to convert json");
    let entry = AggregateEntry::deserialize(&values).expect("failed to convert entries");

    c.bench_function("agg 1.6k", |b| {
        b.iter(|| {
            let sector_id = 0;
            let comm_r = fil_32ByteArray { inner: [0u8; 32] };
            let comm_d = fil_32ByteArray { inner: [0u8; 32] };
            let prover_id = fil_32ByteArray { inner: [0u8; 32] };

            let proof: Vec<u8> =
                base64::decode(&entry.Proof).expect("failed to decode base64 proof");
            let mut commit_inputs: Vec<fil_AggregationInputs> =
                Vec::with_capacity(entry.Infos.len());
            for info in entry.Infos.iter() {
                let mut ticket_decoded: [u8; 32] = [0u8; 32];
                let ticket_slice =
                    base64::decode(&info.Randomness).expect("failed to convert randomness");
                ticket_decoded.copy_from_slice(&ticket_slice);
                let ticket: fil_32ByteArray = fil_32ByteArray {
                    inner: ticket_decoded,
                };

                let mut seed_decoded: [u8; 32] = [0u8; 32];
                let seed_slice = base64::decode(&info.InteractiveRandomness)
                    .expect("failed to convert interactive randomness");
                seed_decoded.copy_from_slice(&seed_slice);
                let seed = fil_32ByteArray {
                    inner: seed_decoded,
                };

                commit_inputs.push(fil_AggregationInputs {
                    comm_r,
                    comm_d,
                    sector_id,
                    ticket,
                    seed,
                });
            }

            unsafe {
                fil_verify_aggregate_seal_proof(
                    fil_RegisteredSealProof::StackedDrg32GiBV1_1,
                    fil_RegisteredAggregationProof::SnarkPackV1,
                    prover_id,
                    proof.as_ptr(),
                    proof.len(),
                    commit_inputs.as_mut_ptr(),
                    commit_inputs.len(),
                )
            }
        })
    });
}

criterion_group!(benches, agg_verify_benchmark);
criterion_main!(benches);
