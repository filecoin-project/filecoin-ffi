use cid::{Cid};
use criterion::{criterion_group, criterion_main, Criterion};
use multihash::Sha2_256;
use serde::Deserialize;
use serde_json::Value;
use std::convert::TryFrom;

use ffi_toolkit::{c_str_to_rust_str, FCPResponseStatus};
use filcrypto::proofs::api::fil_verify_aggregate_seal_proof;
use filcrypto::proofs::types::{
    fil_32ByteArray, fil_AggregationInputs, fil_RegisteredAggregationProof, fil_RegisteredSealProof,
    fil_VerifyAggregateSealProofResponse,
};

#[derive(Deserialize, Debug)]
struct Info {
    Number: u64,
    Randomness: String,
    InteractiveRandomness: String,
    SealedCID: Value,
    UnsealedCID: Value,
}

#[derive(Deserialize, Debug)]
struct AggregateEntry {
    Miner: u64,
    SealProof: usize,
    AggregateProof: usize,
    Proof: String,
    Infos: Vec<Info>,
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

pub fn agg_verify_benchmark(c: &mut Criterion) {
    let agg_str = std::include_str!("agg1.json");
    let values: Value = serde_json::from_str(agg_str).expect("failed to convert json");
    let entry = AggregateEntry::deserialize(&values).expect("failed to convert entries");

    let mut prover_id_raw: [u8; 32] = [0u8; 32];
    prover_id_raw[..4].copy_from_slice(&[0x00u8, 0xE5u8, 0xAEu8, 0x01u8]);
    let prover_id = fil_32ByteArray { inner: prover_id_raw };


    let proof: Vec<u8> = base64::decode(&entry.Proof).expect("failed to decode base64 proof");
    let mut commit_inputs: Vec<fil_AggregationInputs> = Vec::with_capacity(entry.Infos.len());

    for info in entry.Infos.iter() {
        let mut ticket_decoded: [u8; 32] = [0u8; 32];
        let ticket_slice = base64::decode(&info.Randomness).expect("failed to convert randomness");
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

        println!("Sealed CID: {:?}", info.SealedCID["/"]);
        let comm_r_cid = Cid::from(info.SealedCID["/"].to_string()).expect("failed to decode commr");
        let comm_d_cid = Cid::from(info.UnsealedCID["/"].to_string()).expect("failed to decode commd");

        let mut comm_r_raw: [u8; 32] = [0u8; 32];
        let mut comm_d_raw: [u8; 32] = [0u8; 32];

        comm_r_raw.copy_from_slice(&comm_r_cid.hash);
        comm_d_raw.copy_from_slice(&comm_d_cid.hash);

        let comm_r = fil_32ByteArray { inner: comm_r_raw };
        let comm_d = fil_32ByteArray { inner: comm_d_raw };

        commit_inputs.push(fil_AggregationInputs {
            comm_r,
            comm_d,
            sector_id: info.Number,
            ticket,
            seed,
        });
    }

    c.bench_function("agg 1.6k", |b| {
        b.iter(|| unsafe {
            let response = bench_verify_agg(
                fil_RegisteredSealProof::StackedDrg32GiBV1_1,
                fil_RegisteredAggregationProof::SnarkPackV1,
                prover_id,
                proof.as_ptr(),
                proof.len(),
                commit_inputs.as_mut_ptr(),
                commit_inputs.len(),
            );
            if (*response).status_code != FCPResponseStatus::FCPNoError {
                let msg = c_str_to_rust_str((*response).error_msg);
                panic!("verify_aggregate_seal_proof failed: {:?}", msg);
            }
            if !(*response).is_valid {
                println!("VERIFY FAILED");
            }
        })
    });
}

// it is here so it shows up in stack traces
#[inline(never)]
pub unsafe fn bench_verify_agg(
    registered_proof: fil_RegisteredSealProof,
    registered_aggregation: fil_RegisteredAggregationProof,
    prover_id: fil_32ByteArray,
    proof_ptr: *const u8,
    proof_len: libc::size_t,
    commit_inputs_ptr: *mut fil_AggregationInputs,
    commit_inputs_len: libc::size_t,
) -> *mut fil_VerifyAggregateSealProofResponse {
    return fil_verify_aggregate_seal_proof(
        registered_proof,
        registered_aggregation,
        prover_id,
        proof_ptr,
        proof_len,
        commit_inputs_ptr,
        commit_inputs_len,
    );
}

criterion_group!(benches, agg_verify_benchmark);
criterion_main!(benches);
