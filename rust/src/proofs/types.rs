use std::io::SeekFrom;

use filecoin_proofs_api as api;
use safer_ffi::prelude::*;

use crate::util::types::Result;

/// FileDescriptorRef does not drop its file descriptor when it is dropped. Its
/// owner must manage the lifecycle of the file descriptor.
pub struct FileDescriptorRef(std::mem::ManuallyDrop<std::fs::File>);

impl FileDescriptorRef {
    #[cfg(not(target_os = "windows"))]
    pub unsafe fn new(raw: std::os::unix::io::RawFd) -> Self {
        use std::os::unix::io::FromRawFd;
        FileDescriptorRef(std::mem::ManuallyDrop::new(std::fs::File::from_raw_fd(raw)))
    }
}

impl std::io::Read for FileDescriptorRef {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for FileDescriptorRef {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl std::io::Seek for FileDescriptorRef {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

#[derive_ReprC]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum RegisteredSealProof {
    StackedDrg2KiBV1,
    StackedDrg8MiBV1,
    StackedDrg512MiBV1,
    StackedDrg32GiBV1,
    StackedDrg64GiBV1,
    StackedDrg2KiBV1_1,
    StackedDrg8MiBV1_1,
    StackedDrg512MiBV1_1,
    StackedDrg32GiBV1_1,
    StackedDrg64GiBV1_1,
    StackedDrg2KiBV1_1_Feat_SyntheticPoRep,
    StackedDrg8MiBV1_1_Feat_SyntheticPoRep,
    StackedDrg512MiBV1_1_Feat_SyntheticPoRep,
    StackedDrg32GiBV1_1_Feat_SyntheticPoRep,
    StackedDrg64GiBV1_1_Feat_SyntheticPoRep,
    StackedDrg2KiBV1_2_Feat_NonInteractivePoRep,
    StackedDrg8MiBV1_2_Feat_NonInteractivePoRep,
    StackedDrg512MiBV1_2_Feat_NonInteractivePoRep,
    StackedDrg32GiBV1_2_Feat_NonInteractivePoRep,
    StackedDrg64GiBV1_2_Feat_NonInteractivePoRep,
}

impl From<api::RegisteredSealProof> for RegisteredSealProof {
    fn from(other: api::RegisteredSealProof) -> Self {
        use api::RegisteredSealProof::*;
        match other {
            StackedDrg2KiBV1 => RegisteredSealProof::StackedDrg2KiBV1,
            StackedDrg8MiBV1 => RegisteredSealProof::StackedDrg8MiBV1,
            StackedDrg512MiBV1 => RegisteredSealProof::StackedDrg512MiBV1,
            StackedDrg32GiBV1 => RegisteredSealProof::StackedDrg32GiBV1,
            StackedDrg64GiBV1 => RegisteredSealProof::StackedDrg64GiBV1,
            StackedDrg2KiBV1_1 => RegisteredSealProof::StackedDrg2KiBV1_1,
            StackedDrg8MiBV1_1 => RegisteredSealProof::StackedDrg8MiBV1_1,
            StackedDrg512MiBV1_1 => RegisteredSealProof::StackedDrg512MiBV1_1,
            StackedDrg32GiBV1_1 => RegisteredSealProof::StackedDrg32GiBV1_1,
            StackedDrg64GiBV1_1 => RegisteredSealProof::StackedDrg64GiBV1_1,
            StackedDrg2KiBV1_1_Feat_SyntheticPoRep => {
                RegisteredSealProof::StackedDrg2KiBV1_1_Feat_SyntheticPoRep
            }
            StackedDrg8MiBV1_1_Feat_SyntheticPoRep => {
                RegisteredSealProof::StackedDrg8MiBV1_1_Feat_SyntheticPoRep
            }
            StackedDrg512MiBV1_1_Feat_SyntheticPoRep => {
                RegisteredSealProof::StackedDrg512MiBV1_1_Feat_SyntheticPoRep
            }
            StackedDrg32GiBV1_1_Feat_SyntheticPoRep => {
                RegisteredSealProof::StackedDrg32GiBV1_1_Feat_SyntheticPoRep
            }
            StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                RegisteredSealProof::StackedDrg64GiBV1_1_Feat_SyntheticPoRep
            }
            StackedDrg2KiBV1_2_Feat_NonInteractivePoRep => {
                RegisteredSealProof::StackedDrg2KiBV1_2_Feat_NonInteractivePoRep
            }
            StackedDrg8MiBV1_2_Feat_NonInteractivePoRep => {
                RegisteredSealProof::StackedDrg8MiBV1_2_Feat_NonInteractivePoRep
            }
            StackedDrg512MiBV1_2_Feat_NonInteractivePoRep => {
                RegisteredSealProof::StackedDrg512MiBV1_2_Feat_NonInteractivePoRep
            }
            StackedDrg32GiBV1_2_Feat_NonInteractivePoRep => {
                RegisteredSealProof::StackedDrg32GiBV1_2_Feat_NonInteractivePoRep
            }
            StackedDrg64GiBV1_2_Feat_NonInteractivePoRep => {
                RegisteredSealProof::StackedDrg64GiBV1_2_Feat_NonInteractivePoRep
            }
        }
    }
}

impl From<RegisteredSealProof> for api::RegisteredSealProof {
    fn from(other: RegisteredSealProof) -> Self {
        use api::RegisteredSealProof::*;
        match other {
            RegisteredSealProof::StackedDrg2KiBV1 => StackedDrg2KiBV1,
            RegisteredSealProof::StackedDrg8MiBV1 => StackedDrg8MiBV1,
            RegisteredSealProof::StackedDrg512MiBV1 => StackedDrg512MiBV1,
            RegisteredSealProof::StackedDrg32GiBV1 => StackedDrg32GiBV1,
            RegisteredSealProof::StackedDrg64GiBV1 => StackedDrg64GiBV1,

            RegisteredSealProof::StackedDrg2KiBV1_1 => StackedDrg2KiBV1_1,
            RegisteredSealProof::StackedDrg8MiBV1_1 => StackedDrg8MiBV1_1,
            RegisteredSealProof::StackedDrg512MiBV1_1 => StackedDrg512MiBV1_1,
            RegisteredSealProof::StackedDrg32GiBV1_1 => StackedDrg32GiBV1_1,
            RegisteredSealProof::StackedDrg64GiBV1_1 => StackedDrg64GiBV1_1,

            RegisteredSealProof::StackedDrg2KiBV1_1_Feat_SyntheticPoRep => {
                StackedDrg2KiBV1_1_Feat_SyntheticPoRep
            }
            RegisteredSealProof::StackedDrg8MiBV1_1_Feat_SyntheticPoRep => {
                StackedDrg8MiBV1_1_Feat_SyntheticPoRep
            }
            RegisteredSealProof::StackedDrg512MiBV1_1_Feat_SyntheticPoRep => {
                StackedDrg512MiBV1_1_Feat_SyntheticPoRep
            }
            RegisteredSealProof::StackedDrg32GiBV1_1_Feat_SyntheticPoRep => {
                StackedDrg32GiBV1_1_Feat_SyntheticPoRep
            }
            RegisteredSealProof::StackedDrg64GiBV1_1_Feat_SyntheticPoRep => {
                StackedDrg64GiBV1_1_Feat_SyntheticPoRep
            }

            RegisteredSealProof::StackedDrg2KiBV1_2_Feat_NonInteractivePoRep => {
                StackedDrg2KiBV1_2_Feat_NonInteractivePoRep
            }
            RegisteredSealProof::StackedDrg8MiBV1_2_Feat_NonInteractivePoRep => {
                StackedDrg8MiBV1_2_Feat_NonInteractivePoRep
            }
            RegisteredSealProof::StackedDrg512MiBV1_2_Feat_NonInteractivePoRep => {
                StackedDrg512MiBV1_2_Feat_NonInteractivePoRep
            }
            RegisteredSealProof::StackedDrg32GiBV1_2_Feat_NonInteractivePoRep => {
                StackedDrg32GiBV1_2_Feat_NonInteractivePoRep
            }
            RegisteredSealProof::StackedDrg64GiBV1_2_Feat_NonInteractivePoRep => {
                StackedDrg64GiBV1_2_Feat_NonInteractivePoRep
            }
        }
    }
}

#[derive_ReprC]
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum RegisteredPoStProof {
    StackedDrgWinning2KiBV1,
    StackedDrgWinning8MiBV1,
    StackedDrgWinning512MiBV1,
    StackedDrgWinning32GiBV1,
    StackedDrgWinning64GiBV1,

    StackedDrgWindow2KiBV1,
    StackedDrgWindow8MiBV1,
    StackedDrgWindow512MiBV1,
    StackedDrgWindow32GiBV1,
    StackedDrgWindow64GiBV1,

    StackedDrgWindow2KiBV1_1,
    StackedDrgWindow8MiBV1_1,
    StackedDrgWindow512MiBV1_1,
    StackedDrgWindow32GiBV1_1,
    StackedDrgWindow64GiBV1_1,
}

impl From<api::RegisteredPoStProof> for RegisteredPoStProof {
    fn from(other: api::RegisteredPoStProof) -> Self {
        use api::RegisteredPoStProof::*;

        match other {
            StackedDrgWinning2KiBV1 => RegisteredPoStProof::StackedDrgWinning2KiBV1,
            StackedDrgWinning8MiBV1 => RegisteredPoStProof::StackedDrgWinning8MiBV1,
            StackedDrgWinning512MiBV1 => RegisteredPoStProof::StackedDrgWinning512MiBV1,
            StackedDrgWinning32GiBV1 => RegisteredPoStProof::StackedDrgWinning32GiBV1,
            StackedDrgWinning64GiBV1 => RegisteredPoStProof::StackedDrgWinning64GiBV1,
            StackedDrgWindow2KiBV1 => RegisteredPoStProof::StackedDrgWindow2KiBV1,
            StackedDrgWindow8MiBV1 => RegisteredPoStProof::StackedDrgWindow8MiBV1,
            StackedDrgWindow512MiBV1 => RegisteredPoStProof::StackedDrgWindow512MiBV1,
            StackedDrgWindow32GiBV1 => RegisteredPoStProof::StackedDrgWindow32GiBV1,
            StackedDrgWindow64GiBV1 => RegisteredPoStProof::StackedDrgWindow64GiBV1,

            // rust-filecoin-proofs-api WindowPoSt uses api_version
            // V1_2 to fix the grindability issue, which we map here
            // as V1_1 for Lotus/actors compat reasons.
            //
            // Translation: Proofs api_version WindowPoStV1_2 -> WindowPoStV1_1 here
            StackedDrgWindow2KiBV1_2 => RegisteredPoStProof::StackedDrgWindow2KiBV1_1,
            StackedDrgWindow8MiBV1_2 => RegisteredPoStProof::StackedDrgWindow8MiBV1_1,
            StackedDrgWindow512MiBV1_2 => RegisteredPoStProof::StackedDrgWindow512MiBV1_1,
            StackedDrgWindow32GiBV1_2 => RegisteredPoStProof::StackedDrgWindow32GiBV1_1,
            StackedDrgWindow64GiBV1_2 => RegisteredPoStProof::StackedDrgWindow64GiBV1_1,
        }
    }
}

impl From<RegisteredPoStProof> for api::RegisteredPoStProof {
    fn from(other: RegisteredPoStProof) -> Self {
        use api::RegisteredPoStProof::*;

        match other {
            RegisteredPoStProof::StackedDrgWinning2KiBV1 => StackedDrgWinning2KiBV1,
            RegisteredPoStProof::StackedDrgWinning8MiBV1 => StackedDrgWinning8MiBV1,
            RegisteredPoStProof::StackedDrgWinning512MiBV1 => StackedDrgWinning512MiBV1,
            RegisteredPoStProof::StackedDrgWinning32GiBV1 => StackedDrgWinning32GiBV1,
            RegisteredPoStProof::StackedDrgWinning64GiBV1 => StackedDrgWinning64GiBV1,
            RegisteredPoStProof::StackedDrgWindow2KiBV1 => StackedDrgWindow2KiBV1,
            RegisteredPoStProof::StackedDrgWindow8MiBV1 => StackedDrgWindow8MiBV1,
            RegisteredPoStProof::StackedDrgWindow512MiBV1 => StackedDrgWindow512MiBV1,
            RegisteredPoStProof::StackedDrgWindow32GiBV1 => StackedDrgWindow32GiBV1,
            RegisteredPoStProof::StackedDrgWindow64GiBV1 => StackedDrgWindow64GiBV1,

            // rust-filecoin-proofs-api WindowPoSt uses api_version
            // V1_2 to fix the grindability issue, which we map here
            // as V1_1 for Lotus/actors compat reasons.
            //
            // Translation: WindowPoStV1_1 here -> Proofs api_version WindowPoStV1_2
            RegisteredPoStProof::StackedDrgWindow2KiBV1_1 => StackedDrgWindow2KiBV1_2,
            RegisteredPoStProof::StackedDrgWindow8MiBV1_1 => StackedDrgWindow8MiBV1_2,
            RegisteredPoStProof::StackedDrgWindow512MiBV1_1 => StackedDrgWindow512MiBV1_2,
            RegisteredPoStProof::StackedDrgWindow32GiBV1_1 => StackedDrgWindow32GiBV1_2,
            RegisteredPoStProof::StackedDrgWindow64GiBV1_1 => StackedDrgWindow64GiBV1_2,
        }
    }
}

#[derive_ReprC]
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum RegisteredAggregationProof {
    SnarkPackV1,
    SnarkPackV2,
}

impl From<api::RegisteredAggregationProof> for RegisteredAggregationProof {
    fn from(other: api::RegisteredAggregationProof) -> Self {
        match other {
            api::RegisteredAggregationProof::SnarkPackV1 => RegisteredAggregationProof::SnarkPackV1,
            api::RegisteredAggregationProof::SnarkPackV2 => RegisteredAggregationProof::SnarkPackV2,
        }
    }
}

impl From<RegisteredAggregationProof> for api::RegisteredAggregationProof {
    fn from(other: RegisteredAggregationProof) -> Self {
        match other {
            RegisteredAggregationProof::SnarkPackV1 => api::RegisteredAggregationProof::SnarkPackV1,
            RegisteredAggregationProof::SnarkPackV2 => api::RegisteredAggregationProof::SnarkPackV2,
        }
    }
}

#[derive_ReprC]
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum RegisteredUpdateProof {
    StackedDrg2KiBV1,
    StackedDrg8MiBV1,
    StackedDrg512MiBV1,
    StackedDrg32GiBV1,
    StackedDrg64GiBV1,
}

impl From<api::RegisteredUpdateProof> for RegisteredUpdateProof {
    fn from(other: api::RegisteredUpdateProof) -> Self {
        use api::RegisteredUpdateProof::*;
        match other {
            StackedDrg2KiBV1 => RegisteredUpdateProof::StackedDrg2KiBV1,
            StackedDrg8MiBV1 => RegisteredUpdateProof::StackedDrg8MiBV1,
            StackedDrg512MiBV1 => RegisteredUpdateProof::StackedDrg512MiBV1,
            StackedDrg32GiBV1 => RegisteredUpdateProof::StackedDrg32GiBV1,
            StackedDrg64GiBV1 => RegisteredUpdateProof::StackedDrg64GiBV1,
        }
    }
}

impl From<RegisteredUpdateProof> for api::RegisteredUpdateProof {
    fn from(other: RegisteredUpdateProof) -> Self {
        use api::RegisteredUpdateProof::*;
        match other {
            RegisteredUpdateProof::StackedDrg2KiBV1 => StackedDrg2KiBV1,
            RegisteredUpdateProof::StackedDrg8MiBV1 => StackedDrg8MiBV1,
            RegisteredUpdateProof::StackedDrg512MiBV1 => StackedDrg512MiBV1,
            RegisteredUpdateProof::StackedDrg32GiBV1 => StackedDrg32GiBV1,
            RegisteredUpdateProof::StackedDrg64GiBV1 => StackedDrg64GiBV1,
        }
    }
}

#[derive_ReprC]
#[repr(C)]
#[derive(Clone)]
pub struct PublicPieceInfo {
    pub num_bytes: u64,
    pub comm_p: [u8; 32],
}

impl From<&PublicPieceInfo> for api::PieceInfo {
    fn from(x: &PublicPieceInfo) -> Self {
        let PublicPieceInfo { num_bytes, comm_p } = x;
        api::PieceInfo {
            commitment: *comm_p,
            size: api::UnpaddedBytesAmount(*num_bytes),
        }
    }
}

pub type VanillaProof = c_slice::Box<u8>;

pub type AggregateProof = Result<VanillaProof>;

#[derive(Clone, Debug)]
pub struct ApiPoStProof {
    pub registered_proof: api::RegisteredPoStProof,
    pub proof: Vec<u8>,
}

#[derive_ReprC]
#[repr(C)]
#[derive(Clone)]
pub struct PoStProof {
    pub registered_proof: RegisteredPoStProof,
    pub proof: c_slice::Box<u8>,
}

impl Default for PoStProof {
    fn default() -> Self {
        Self {
            registered_proof: RegisteredPoStProof::StackedDrgWindow32GiBV1, // dummy value
            proof: Default::default(),
        }
    }
}

impl From<PoStProof> for ApiPoStProof {
    fn from(other: PoStProof) -> Self {
        ApiPoStProof {
            registered_proof: other.registered_proof.into(),
            proof: other.proof.to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct ApiPartitionSnarkProof {
    pub registered_proof: api::RegisteredPoStProof,
    pub proof: Vec<u8>,
}

#[derive_ReprC]
#[repr(C)]
#[derive(Clone)]
pub struct PartitionSnarkProof {
    pub registered_proof: RegisteredPoStProof,
    pub proof: c_slice::Box<u8>,
}

impl Default for PartitionSnarkProof {
    fn default() -> Self {
        Self {
            registered_proof: RegisteredPoStProof::StackedDrgWindow32GiBV1, // dummy value
            proof: Default::default(),
        }
    }
}

impl From<PartitionSnarkProof> for ApiPartitionSnarkProof {
    fn from(other: PartitionSnarkProof) -> Self {
        ApiPartitionSnarkProof {
            registered_proof: other.registered_proof.into(),
            proof: other.proof.to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct PartitionProof {
    pub proof: Vec<u8>,
}

pub type ApiPartitionProof = c_slice::Box<u8>;

#[derive_ReprC]
#[repr(C)]
#[derive(Clone)]
pub struct PrivateReplicaInfo {
    pub registered_proof: RegisteredPoStProof,
    pub cache_dir_path: c_slice::Box<u8>,
    pub comm_r: [u8; 32],
    pub replica_path: c_slice::Box<u8>,
    pub sector_id: u64,
}

#[derive_ReprC]
#[repr(C)]
#[derive(Clone)]
pub struct PublicReplicaInfo {
    pub registered_proof: RegisteredPoStProof,
    pub comm_r: [u8; 32],
    pub sector_id: u64,
}

pub type GenerateWinningPoStSectorChallenge = Result<c_slice::Box<u64>>;

pub type GenerateFallbackSectorChallengesResponse = Result<GenerateFallbackSectorChallenges>;

#[derive_ReprC]
#[repr(C)]
#[derive(Default)]
pub struct GenerateFallbackSectorChallenges {
    pub ids: c_slice::Box<u64>,
    pub challenges: c_slice::Box<c_slice::Box<u64>>,
}

pub type GenerateSingleVanillaProofResponse = Result<VanillaProof>;

pub type GenerateWinningPoStResponse = Result<c_slice::Box<PoStProof>>;

pub type GenerateWindowPoStResponse = Result<GenerateWindowPoSt>;

#[derive_ReprC]
#[repr(C)]
#[derive(Default)]
pub struct GenerateWindowPoSt {
    pub proofs: c_slice::Box<PoStProof>,
    pub faulty_sectors: c_slice::Box<u64>,
}

pub type GenerateSingleWindowPoStWithVanillaResponse = Result<GenerateSingleWindowPoStWithVanilla>;

#[derive_ReprC]
#[repr(C)]
#[derive(Default)]
pub struct GenerateSingleWindowPoStWithVanilla {
    pub partition_proof: PartitionSnarkProof,
    pub faulty_sectors: c_slice::Box<u64>,
}

pub type GetNumPartitionForFallbackPoStResponse = Result<libc::size_t>;

pub type MergeWindowPoStPartitionProofsResponse = Result<PoStProof>;

pub type WriteWithAlignmentResponse = Result<WriteWithAlignment>;

#[derive_ReprC]
#[repr(C)]
#[derive(Default)]
pub struct WriteWithAlignment {
    pub comm_p: [u8; 32],
    pub left_alignment_unpadded: u64,
    pub total_write_unpadded: u64,
}

pub type WriteWithoutAlignmentResponse = Result<WriteWithoutAlignment>;

#[derive_ReprC]
#[repr(C)]
#[derive(Default)]
pub struct WriteWithoutAlignment {
    pub comm_p: [u8; 32],
    pub total_write_unpadded: u64,
}

pub type SealPreCommitPhase1Response = Result<c_slice::Box<u8>>;

pub type FauxRepResponse = Result<[u8; 32]>;

pub type GenerateSdrResponse = Result<()>;

pub type SealPreCommitPhase2Response = Result<SealPreCommitPhase2>;

pub type GenerateTreeRLastResponse = Result<[u8; 32]>;

pub type GenerateTreeCResponse = Result<[u8; 32]>;

#[derive_ReprC]
#[repr(C)]
pub struct SealPreCommitPhase2 {
    pub registered_proof: RegisteredSealProof,
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
}

impl Default for SealPreCommitPhase2 {
    fn default() -> Self {
        Self {
            registered_proof: RegisteredSealProof::StackedDrg2KiBV1_1, // dummy value
            comm_d: Default::default(),
            comm_r: Default::default(),
        }
    }
}

pub type SealCommitPhase1Response = Result<c_slice::Box<u8>>;

pub type SealCommitPhase2Response = Result<c_slice::Box<u8>>;

#[derive_ReprC]
#[repr(C)]
#[derive(Clone, Default)]
pub struct AggregationInputs {
    pub comm_r: [u8; 32],
    pub comm_d: [u8; 32],
    pub sector_id: u64,
    pub ticket: [u8; 32],
    pub seed: [u8; 32],
}

pub type UnsealRangeResponse = Result<()>;

pub type VerifySealResponse = Result<bool>;

pub type VerifyAggregateSealProofResponse = Result<bool>;

pub type VerifyWinningPoStResponse = Result<bool>;

pub type VerifyWindowPoStResponse = Result<bool>;

pub type FinalizeTicketResponse = Result<[u8; 32]>;

pub type GeneratePieceCommitmentResponse = Result<GeneratePieceCommitment>;

#[derive_ReprC]
#[repr(C)]
#[derive(Default)]
pub struct GeneratePieceCommitment {
    pub comm_p: [u8; 32],
    /// The number of unpadded bytes in the original piece plus any (unpadded)
    /// alignment bytes added to create a whole merkle tree.
    pub num_bytes_aligned: u64,
}

pub type GenerateDataCommitmentResponse = Result<[u8; 32]>;

pub type StringResponse = Result<c_slice::Box<u8>>;

pub type GenerateSynthProofsResponse = Result<()>;
pub type ClearCacheResponse = Result<()>;

pub type EmptySectorUpdateEncodeIntoResponse = Result<EmptySectorUpdateEncodeInto>;

#[derive_ReprC]
#[repr(C)]
#[derive(Default)]
pub struct EmptySectorUpdateEncodeInto {
    pub comm_r_new: [u8; 32],
    pub comm_r_last_new: [u8; 32],
    pub comm_d_new: [u8; 32],
}

pub type EmptySectorUpdateDecodeFromResponse = Result<()>;

pub type EmptySectorUpdateDecodeFromRangeResponse = Result<()>;

pub type EmptySectorUpdateRemoveEncodedDataResponse = Result<()>;

pub type EmptySectorUpdateProofResponse = Result<c_slice::Box<u8>>;

pub type PartitionProofResponse = Result<c_slice::Box<ApiPartitionProof>>;

pub type VerifyPartitionProofResponse = Result<bool>;

pub type VerifyEmptySectorUpdateProofResponse = Result<bool>;
