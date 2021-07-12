use anyhow::{Context, Result};
use criterion::{criterion_group, criterion_main, Criterion};
use serde::Deserialize;
use serde_json::Value;
use std::convert::TryInto;

use ffi_toolkit::{c_str_to_rust_str, FCPResponseStatus};
use filcrypto::proofs::api::fil_verify_aggregate_seal_proof;
use filcrypto::proofs::types::{
    fil_32ByteArray, fil_AggregationInputs, fil_RegisteredAggregationProof,
    fil_RegisteredSealProof, fil_VerifyAggregateSealProofResponse,
};

#[derive(Deserialize, Debug)]
struct Info {
    #[serde(rename = "Number")]
    number: u64,
    #[serde(rename = "Randomness")]
    randomness: String,
    #[serde(rename = "InteractiveRandomness")]
    interactive_randomness: String,
    #[serde(rename = "SealedCID")]
    sealed_cid: Value,
    #[serde(rename = "UnsealedCID")]
    unsealed_cid: Value,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct AggregateEntry {
    miner: u64,
    seal_proof: usize,
    aggregate_proof: usize,
    proof: String,
    infos: Vec<Info>,
}

/* JSON input format:
  {
    "Miner": 117118,
    "SealProof": 8,
    "AggregateProof": 0,
    "Proof": "[...] long proof here",
    "Infos": [
      {
        "Number": 1668,
        "Randomness": "91jwr9yMPrJf5uAyQL/gTI7YW2LH09Ic7j1ZvtFX/yc=",
        "InteractiveRandomness": "E+W1ADEBRkXuErTEnNezvbhZMIkgK49Xi3d31XfEDbc=",
        "SealedCID": {
          "/": "bagboea4b5abcaron4bcfdt2z5akuv3fy6bqaqunnv7gsfl57a6n7gybsdaxcguzd"
        },
        "UnsealedCID": {
          "/": "baga6ea4seaqao7s73y24kcutaosvacpdjgfe5pw76ooefnyqw4ynr3d2y6x2mpq"
        }
      }
    ]
  }
*/

fn agg_verify_benchmark(c: &mut Criterion, num_threads_per_iteration: usize) -> Result<()> {
    let agg_file = std::fs::File::open("./benches/agg1.json")?;
    let values: Value = serde_json::from_reader(agg_file)?;
    let entry = AggregateEntry::deserialize(&values).context("deserialize aggregate")?;

    let mut prover_id_raw = [0u8; 32];
    prover_id_raw[..4].copy_from_slice(&[0x00u8, 0xE5u8, 0xAEu8, 0x01u8]);
    let prover_id = fil_32ByteArray {
        inner: prover_id_raw,
    };

    let proof: Vec<u8> = base64::decode(&entry.proof).context("decode proof")?;
    let mut commit_inputs: Vec<fil_AggregationInputs> = Vec::with_capacity(entry.infos.len());

    for info in entry.infos.iter() {
        let ticket_slice = base64::decode(&info.randomness).context("decode ticket")?;
        let ticket: fil_32ByteArray = fil_32ByteArray {
            inner: ticket_slice.try_into().unwrap(),
        };

        let seed_slice = base64::decode(&info.interactive_randomness)?;
        let seed = fil_32ByteArray {
            inner: seed_slice.try_into().unwrap(),
        };

        let sealed_cid = info.sealed_cid["/"].as_str().unwrap();
        let unsealed_cid = info.unsealed_cid["/"].as_str().unwrap();
        let (_, comm_r_cid) = multibase::decode(sealed_cid)?;
        let (_, comm_d_cid) = multibase::decode(unsealed_cid)?;

        let comm_r_raw = comm_r_cid[comm_r_cid.len() - 32..].try_into().unwrap();
        let comm_d_raw = comm_d_cid[comm_d_cid.len() - 32..].try_into().unwrap();

        let comm_r = fil_32ByteArray { inner: comm_r_raw };
        let comm_d = fil_32ByteArray { inner: comm_d_raw };

        commit_inputs.push(fil_AggregationInputs {
            comm_r,
            comm_d,
            sector_id: info.number,
            ticket,
            seed,
        });
    }

    // prewarm using direct call
    unsafe {
        fil_verify_aggregate_seal_proof(
            fil_RegisteredSealProof::StackedDrg32GiBV1_1,
            fil_RegisteredAggregationProof::SnarkPackV1,
            prover_id,
            proof.as_ptr(),
            proof.len(),
            commit_inputs.as_mut_ptr(),
            commit_inputs.len(),
        );
    }
    c.bench_function("agg 1.6k", |b| {
        b.iter(|| unsafe {
            rayon::scope(|s| {
                for _ in 0..num_threads_per_iteration {
                    let mut inputs = commit_inputs.clone();
                    let proof = proof.clone();
                    s.spawn(move |_| {
                        let response = bench_verify_agg(
                            fil_RegisteredSealProof::StackedDrg32GiBV1_1,
                            fil_RegisteredAggregationProof::SnarkPackV1,
                            prover_id,
                            proof.as_ptr(),
                            proof.len(),
                            inputs.as_mut_ptr(),
                            inputs.len(),
                        );
                        if (*response).status_code != FCPResponseStatus::FCPNoError {
                            let msg = c_str_to_rust_str((*response).error_msg);
                            panic!("verify_aggregate_seal_proof failed: {:?}", msg);
                        }
                        //if !(*response).is_valid {
                        //    println!("VERIFY FAILED");
                        //}
                    });
                }
            });
        })
    });

    Ok(())
}

/// It is here so it shows up in stack traces.
#[inline(never)]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn bench_verify_agg(
    registered_proof: fil_RegisteredSealProof,
    registered_aggregation: fil_RegisteredAggregationProof,
    prover_id: fil_32ByteArray,
    proof_ptr: *const u8,
    proof_len: libc::size_t,
    commit_inputs_ptr: *mut fil_AggregationInputs,
    commit_inputs_len: libc::size_t,
) -> *mut fil_VerifyAggregateSealProofResponse {
    fil_verify_aggregate_seal_proof(
        registered_proof,
        registered_aggregation,
        prover_id,
        proof_ptr,
        proof_len,
        commit_inputs_ptr,
        commit_inputs_len,
    )
}

fn aggregate_verify(c: &mut Criterion) {
    let num_threads_per_iteration = 4;
    agg_verify_benchmark(c, num_threads_per_iteration).unwrap();
}

criterion_group!(benches, aggregate_verify);
criterion_main!(benches);
