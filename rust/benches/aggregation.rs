use cid::{Cid, Codec, Version};
use criterion::{criterion_group, criterion_main, Criterion};
use multihash::Sha2_256;
use serde::Deserialize;
use serde_json::Value;
use std::convert::TryFrom;

use ffi_toolkit::{c_str_to_rust_str, FCPResponseStatus};
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

    let sealed: Cid = Cid::new(Codec::DagProtobuf, Version::V1, &Sha2_256::digest(values["Infos"]["SealedCID"].to_string().as_bytes()));
    let unsealed: Cid = Cid::new(Codec::DagProtobuf, Version::V1, &Sha2_256::digest(values["Infos"]["SealedCID"].to_string().as_bytes()));
    let sector_id = 0;

    let sealed_decoded = sealed.to_bytes();
    let unsealed_decoded = sealed.to_bytes();
    let mut comm_r_raw: [u8; 32] = [0u8; 32];
    let mut comm_d_raw: [u8; 32] = [0u8; 32];
    comm_r_raw.copy_from_slice(&sealed_decoded[4..36]);
    comm_d_raw.copy_from_slice(&unsealed_decoded[4..36]);
    let comm_r = fil_32ByteArray { inner: comm_r_raw };
    let comm_d = fil_32ByteArray { inner: comm_d_raw };
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

    c.bench_function("agg 1.6k", |b| {
        b.iter(|| {
            unsafe {
                let response = fil_verify_aggregate_seal_proof(
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
            }
        })
    });
}

criterion_group!(benches, agg_verify_benchmark);
criterion_main!(benches);
