use std::io::{Error, SeekFrom};
use std::ops::Deref;

use anyhow::Result;
use filecoin_proofs_api::seal::SealCommitPhase2Output;
use filecoin_proofs_api::{
    PieceInfo, RegisteredAggregationProof, RegisteredPoStProof, RegisteredSealProof,
    RegisteredUpdateProof, UnpaddedBytesAmount,
};

use crate::util::types::{fil_Array, fil_Bytes, fil_Result};

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct fil_32ByteArray {
    pub inner: [u8; 32],
}

impl Deref for fil_32ByteArray {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<[u8; 32]> for fil_32ByteArray {
    fn from(val: [u8; 32]) -> Self {
        Self { inner: val }
    }
}

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
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.0.flush()
    }
}

impl std::io::Seek for FileDescriptorRef {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Error> {
        self.0.seek(pos)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum fil_RegisteredSealProof {
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
}

impl From<RegisteredSealProof> for fil_RegisteredSealProof {
    fn from(other: RegisteredSealProof) -> Self {
        match other {
            RegisteredSealProof::StackedDrg2KiBV1 => fil_RegisteredSealProof::StackedDrg2KiBV1,
            RegisteredSealProof::StackedDrg8MiBV1 => fil_RegisteredSealProof::StackedDrg8MiBV1,
            RegisteredSealProof::StackedDrg512MiBV1 => fil_RegisteredSealProof::StackedDrg512MiBV1,
            RegisteredSealProof::StackedDrg32GiBV1 => fil_RegisteredSealProof::StackedDrg32GiBV1,
            RegisteredSealProof::StackedDrg64GiBV1 => fil_RegisteredSealProof::StackedDrg64GiBV1,

            RegisteredSealProof::StackedDrg2KiBV1_1 => fil_RegisteredSealProof::StackedDrg2KiBV1_1,
            RegisteredSealProof::StackedDrg8MiBV1_1 => fil_RegisteredSealProof::StackedDrg8MiBV1_1,
            RegisteredSealProof::StackedDrg512MiBV1_1 => {
                fil_RegisteredSealProof::StackedDrg512MiBV1_1
            }
            RegisteredSealProof::StackedDrg32GiBV1_1 => {
                fil_RegisteredSealProof::StackedDrg32GiBV1_1
            }
            RegisteredSealProof::StackedDrg64GiBV1_1 => {
                fil_RegisteredSealProof::StackedDrg64GiBV1_1
            }
        }
    }
}

impl From<fil_RegisteredSealProof> for RegisteredSealProof {
    fn from(other: fil_RegisteredSealProof) -> Self {
        match other {
            fil_RegisteredSealProof::StackedDrg2KiBV1 => RegisteredSealProof::StackedDrg2KiBV1,
            fil_RegisteredSealProof::StackedDrg8MiBV1 => RegisteredSealProof::StackedDrg8MiBV1,
            fil_RegisteredSealProof::StackedDrg512MiBV1 => RegisteredSealProof::StackedDrg512MiBV1,
            fil_RegisteredSealProof::StackedDrg32GiBV1 => RegisteredSealProof::StackedDrg32GiBV1,
            fil_RegisteredSealProof::StackedDrg64GiBV1 => RegisteredSealProof::StackedDrg64GiBV1,

            fil_RegisteredSealProof::StackedDrg2KiBV1_1 => RegisteredSealProof::StackedDrg2KiBV1_1,
            fil_RegisteredSealProof::StackedDrg8MiBV1_1 => RegisteredSealProof::StackedDrg8MiBV1_1,
            fil_RegisteredSealProof::StackedDrg512MiBV1_1 => {
                RegisteredSealProof::StackedDrg512MiBV1_1
            }
            fil_RegisteredSealProof::StackedDrg32GiBV1_1 => {
                RegisteredSealProof::StackedDrg32GiBV1_1
            }
            fil_RegisteredSealProof::StackedDrg64GiBV1_1 => {
                RegisteredSealProof::StackedDrg64GiBV1_1
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum fil_RegisteredPoStProof {
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
}

impl From<RegisteredPoStProof> for fil_RegisteredPoStProof {
    fn from(other: RegisteredPoStProof) -> Self {
        use RegisteredPoStProof::*;

        match other {
            StackedDrgWinning2KiBV1 => fil_RegisteredPoStProof::StackedDrgWinning2KiBV1,
            StackedDrgWinning8MiBV1 => fil_RegisteredPoStProof::StackedDrgWinning8MiBV1,
            StackedDrgWinning512MiBV1 => fil_RegisteredPoStProof::StackedDrgWinning512MiBV1,
            StackedDrgWinning32GiBV1 => fil_RegisteredPoStProof::StackedDrgWinning32GiBV1,
            StackedDrgWinning64GiBV1 => fil_RegisteredPoStProof::StackedDrgWinning64GiBV1,
            StackedDrgWindow2KiBV1 => fil_RegisteredPoStProof::StackedDrgWindow2KiBV1,
            StackedDrgWindow8MiBV1 => fil_RegisteredPoStProof::StackedDrgWindow8MiBV1,
            StackedDrgWindow512MiBV1 => fil_RegisteredPoStProof::StackedDrgWindow512MiBV1,
            StackedDrgWindow32GiBV1 => fil_RegisteredPoStProof::StackedDrgWindow32GiBV1,
            StackedDrgWindow64GiBV1 => fil_RegisteredPoStProof::StackedDrgWindow64GiBV1,
        }
    }
}

impl From<fil_RegisteredPoStProof> for RegisteredPoStProof {
    fn from(other: fil_RegisteredPoStProof) -> Self {
        use RegisteredPoStProof::*;

        match other {
            fil_RegisteredPoStProof::StackedDrgWinning2KiBV1 => StackedDrgWinning2KiBV1,
            fil_RegisteredPoStProof::StackedDrgWinning8MiBV1 => StackedDrgWinning8MiBV1,
            fil_RegisteredPoStProof::StackedDrgWinning512MiBV1 => StackedDrgWinning512MiBV1,
            fil_RegisteredPoStProof::StackedDrgWinning32GiBV1 => StackedDrgWinning32GiBV1,
            fil_RegisteredPoStProof::StackedDrgWinning64GiBV1 => StackedDrgWinning64GiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow2KiBV1 => StackedDrgWindow2KiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow8MiBV1 => StackedDrgWindow8MiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow512MiBV1 => StackedDrgWindow512MiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow32GiBV1 => StackedDrgWindow32GiBV1,
            fil_RegisteredPoStProof::StackedDrgWindow64GiBV1 => StackedDrgWindow64GiBV1,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum fil_RegisteredAggregationProof {
    SnarkPackV1,
}

impl From<RegisteredAggregationProof> for fil_RegisteredAggregationProof {
    fn from(other: RegisteredAggregationProof) -> Self {
        match other {
            RegisteredAggregationProof::SnarkPackV1 => fil_RegisteredAggregationProof::SnarkPackV1,
        }
    }
}

impl From<fil_RegisteredAggregationProof> for RegisteredAggregationProof {
    fn from(other: fil_RegisteredAggregationProof) -> Self {
        match other {
            fil_RegisteredAggregationProof::SnarkPackV1 => RegisteredAggregationProof::SnarkPackV1,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum fil_RegisteredUpdateProof {
    StackedDrg2KiBV1,
    StackedDrg8MiBV1,
    StackedDrg512MiBV1,
    StackedDrg32GiBV1,
    StackedDrg64GiBV1,
}

impl From<RegisteredUpdateProof> for fil_RegisteredUpdateProof {
    fn from(other: RegisteredUpdateProof) -> Self {
        match other {
            RegisteredUpdateProof::StackedDrg2KiBV1 => fil_RegisteredUpdateProof::StackedDrg2KiBV1,
            RegisteredUpdateProof::StackedDrg8MiBV1 => fil_RegisteredUpdateProof::StackedDrg8MiBV1,
            RegisteredUpdateProof::StackedDrg512MiBV1 => {
                fil_RegisteredUpdateProof::StackedDrg512MiBV1
            }
            RegisteredUpdateProof::StackedDrg32GiBV1 => {
                fil_RegisteredUpdateProof::StackedDrg32GiBV1
            }
            RegisteredUpdateProof::StackedDrg64GiBV1 => {
                fil_RegisteredUpdateProof::StackedDrg64GiBV1
            }
        }
    }
}

impl From<fil_RegisteredUpdateProof> for RegisteredUpdateProof {
    fn from(other: fil_RegisteredUpdateProof) -> Self {
        match other {
            fil_RegisteredUpdateProof::StackedDrg2KiBV1 => RegisteredUpdateProof::StackedDrg2KiBV1,
            fil_RegisteredUpdateProof::StackedDrg8MiBV1 => RegisteredUpdateProof::StackedDrg8MiBV1,
            fil_RegisteredUpdateProof::StackedDrg512MiBV1 => {
                RegisteredUpdateProof::StackedDrg512MiBV1
            }
            fil_RegisteredUpdateProof::StackedDrg32GiBV1 => {
                RegisteredUpdateProof::StackedDrg32GiBV1
            }
            fil_RegisteredUpdateProof::StackedDrg64GiBV1 => {
                RegisteredUpdateProof::StackedDrg64GiBV1
            }
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct fil_PublicPieceInfo {
    pub num_bytes: u64,
    pub comm_p: [u8; 32],
}

impl From<fil_PublicPieceInfo> for PieceInfo {
    fn from(x: fil_PublicPieceInfo) -> Self {
        let fil_PublicPieceInfo { num_bytes, comm_p } = x;
        PieceInfo {
            commitment: comm_p,
            size: UnpaddedBytesAmount(num_bytes),
        }
    }
}

#[allow(non_camel_case_types)]
pub type fil_VanillaProof = fil_Bytes;

#[allow(non_camel_case_types)]
pub type fil_AggregateProof = fil_Result<fil_VanillaProof>;

#[derive(Clone, Debug)]
pub struct PoStProof {
    pub registered_proof: RegisteredPoStProof,
    pub proof: Vec<u8>,
}

#[repr(C)]
#[derive(Clone)]
pub struct fil_PoStProof {
    pub registered_proof: fil_RegisteredPoStProof,
    pub proof: fil_Bytes,
}

impl Default for fil_PoStProof {
    fn default() -> Self {
        Self {
            registered_proof: fil_RegisteredPoStProof::StackedDrgWindow32GiBV1, // dummy value
            proof: Default::default(),
        }
    }
}

impl From<fil_PoStProof> for PoStProof {
    fn from(other: fil_PoStProof) -> Self {
        PoStProof {
            registered_proof: other.registered_proof.into(),
            proof: other.proof.to_vec(),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct PartitionSnarkProof {
    pub registered_proof: RegisteredPoStProof,
    pub proof: Vec<u8>,
}

#[repr(C)]
#[derive(Clone)]
pub struct fil_PartitionSnarkProof {
    pub registered_proof: fil_RegisteredPoStProof,
    pub proof: fil_Bytes,
}

impl Default for fil_PartitionSnarkProof {
    fn default() -> Self {
        Self {
            registered_proof: fil_RegisteredPoStProof::StackedDrgWindow32GiBV1, // dummy value
            proof: Default::default(),
        }
    }
}

impl From<fil_PartitionSnarkProof> for PartitionSnarkProof {
    fn from(other: fil_PartitionSnarkProof) -> Self {
        PartitionSnarkProof {
            registered_proof: other.registered_proof.into(),
            proof: other.proof.to_vec(),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct PartitionProof {
    pub proof: Vec<u8>,
}

#[allow(non_camel_case_types)]
pub type fil_PartitionProof = fil_Bytes;

#[repr(C)]
#[derive(Clone)]
pub struct fil_PrivateReplicaInfo {
    pub registered_proof: fil_RegisteredPoStProof,
    pub cache_dir_path: fil_Bytes,
    pub comm_r: [u8; 32],
    pub replica_path: fil_Bytes,
    pub sector_id: u64,
}

#[repr(C)]
#[derive(Clone)]
pub struct fil_PublicReplicaInfo {
    pub registered_proof: fil_RegisteredPoStProof,
    pub comm_r: [u8; 32],
    pub sector_id: u64,
}

#[allow(non_camel_case_types)]
pub type fil_GenerateWinningPoStSectorChallenge = fil_Result<fil_Array<u64>>;

#[allow(non_camel_case_types)]
pub type fil_GenerateFallbackSectorChallengesResponse =
    fil_Result<fil_GenerateFallbackSectorChallenges>;

#[repr(C)]
#[derive(Default)]
pub struct fil_GenerateFallbackSectorChallenges {
    pub ids: fil_Array<u64>,
    pub challenges: fil_Array<u64>,
    pub challenges_stride: libc::size_t,
}

#[allow(non_camel_case_types)]
pub type fil_GenerateSingleVanillaProofResponse = fil_Result<fil_VanillaProof>;

#[allow(non_camel_case_types)]
pub type fil_GenerateWinningPoStResponse = fil_Result<fil_Array<fil_PoStProof>>;

#[allow(non_camel_case_types)]
pub type fil_GenerateWindowPoStResponse = fil_Result<fil_GenerateWindowPoSt>;

#[repr(C)]
#[derive(Default)]
pub struct fil_GenerateWindowPoSt {
    pub proofs: fil_Array<fil_PoStProof>,
    pub faulty_sectors: fil_Array<u64>,
}

#[allow(non_camel_case_types)]
pub type fil_GenerateSingleWindowPoStWithVanillaResponse =
    fil_Result<fil_GenerateSingleWindowPoStWithVanilla>;

#[repr(C)]
#[derive(Default)]
pub struct fil_GenerateSingleWindowPoStWithVanilla {
    pub partition_proof: fil_PartitionSnarkProof,
    pub faulty_sectors: fil_Array<u64>,
}

#[allow(non_camel_case_types)]
pub type fil_GetNumPartitionForFallbackPoStResponse = fil_Result<libc::size_t>;

#[allow(non_camel_case_types)]
pub type fil_MergeWindowPoStPartitionProofsResponse = fil_Result<fil_PoStProof>;

#[allow(non_camel_case_types)]
pub type fil_WriteWithAlignmentResponse = fil_Result<fil_WriteWithAlignment>;

#[repr(C)]
#[derive(Default)]
pub struct fil_WriteWithAlignment {
    pub comm_p: [u8; 32],
    pub left_alignment_unpadded: u64,
    pub total_write_unpadded: u64,
}

#[allow(non_camel_case_types)]
pub type fil_WriteWithoutAlignmentResponse = fil_Result<fil_WriteWithoutAlignment>;

#[repr(C)]
#[derive(Default)]
pub struct fil_WriteWithoutAlignment {
    pub comm_p: [u8; 32],
    pub total_write_unpadded: u64,
}

#[allow(non_camel_case_types)]
pub type fil_SealPreCommitPhase1Response = fil_Result<fil_Bytes>;

#[allow(non_camel_case_types)]
pub type fil_FauxRepResponse = fil_Result<fil_32ByteArray>;

#[allow(non_camel_case_types)]
pub type fil_SealPreCommitPhase2Response = fil_Result<fil_SealPreCommitPhase2>;

#[repr(C)]
pub struct fil_SealPreCommitPhase2 {
    pub registered_proof: fil_RegisteredSealProof,
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
}

impl Default for fil_SealPreCommitPhase2 {
    fn default() -> Self {
        Self {
            registered_proof: fil_RegisteredSealProof::StackedDrg2KiBV1_1, // dummy value
            comm_d: Default::default(),
            comm_r: Default::default(),
        }
    }
}

#[allow(non_camel_case_types)]
pub type fil_SealCommitPhase1Response = fil_Result<fil_Bytes>;

#[allow(non_camel_case_types)]
pub type fil_SealCommitPhase2Response = fil_Result<fil_SealCommitPhase2>;

impl From<&fil_SealCommitPhase2> for SealCommitPhase2Output {
    fn from(other: &fil_SealCommitPhase2) -> Self {
        SealCommitPhase2Output {
            proof: other.proof.to_vec(),
        }
    }
}

#[repr(C)]
#[derive(Default, Clone)]
pub struct fil_SealCommitPhase2 {
    pub proof: fil_Bytes,
    // TODO: this is not actualy used?
    // pub commit_inputs: fil_Array<fil_AggregationInputs>,
}

#[repr(C)]
#[derive(Clone, Default)]
pub struct fil_AggregationInputs {
    pub comm_r: fil_32ByteArray,
    pub comm_d: fil_32ByteArray,
    pub sector_id: u64,
    pub ticket: fil_32ByteArray,
    pub seed: fil_32ByteArray,
}

#[allow(non_camel_case_types)]
pub type fil_UnsealRangeResponse = fil_Result<()>;

#[allow(non_camel_case_types)]
pub type fil_VerifySealResponse = fil_Result<bool>;

#[allow(non_camel_case_types)]
pub type fil_VerifyAggregateSealProofResponse = fil_Result<bool>;

#[allow(non_camel_case_types)]
pub type fil_VerifyWinningPoStResponse = fil_Result<bool>;

#[allow(non_camel_case_types)]
pub type fil_VerifyWindowPoStResponse = fil_Result<bool>;

#[allow(non_camel_case_types)]
pub type fil_FinalizeTicketResponse = fil_Result<fil_32ByteArray>;

#[allow(non_camel_case_types)]
pub type fil_GeneratePieceCommitmentResponse = fil_Result<fil_GeneratePieceCommitment>;

#[repr(C)]
#[derive(Default)]
pub struct fil_GeneratePieceCommitment {
    pub comm_p: [u8; 32],
    /// The number of unpadded bytes in the original piece plus any (unpadded)
    /// alignment bytes added to create a whole merkle tree.
    pub num_bytes_aligned: u64,
}

#[allow(non_camel_case_types)]
pub type fil_GenerateDataCommitmentResponse = fil_Result<fil_32ByteArray>;

#[allow(non_camel_case_types)]
pub type fil_StringResponse = fil_Result<fil_Bytes>;

#[allow(non_camel_case_types)]
pub type fil_ClearCacheResponse = fil_Result<()>;

#[allow(non_camel_case_types)]
pub type fil_EmptySectorUpdateEncodeIntoResponse = fil_Result<fil_EmptySectorUpdateEncodeInto>;

#[repr(C)]
#[derive(Default)]
pub struct fil_EmptySectorUpdateEncodeInto {
    pub comm_r_new: [u8; 32],
    pub comm_r_last_new: [u8; 32],
    pub comm_d_new: [u8; 32],
}

#[allow(non_camel_case_types)]
pub type fil_EmptySectorUpdateDecodeFromResponse = fil_Result<()>;

#[allow(non_camel_case_types)]
pub type fil_EmptySectorUpdateRemoveEncodedDataResponse = fil_Result<()>;

#[allow(non_camel_case_types)]
pub type fil_EmptySectorUpdateProofResponse = fil_Result<fil_Bytes>;

#[allow(non_camel_case_types)]
pub type fil_PartitionProofResponse = fil_Result<fil_Array<fil_PartitionProof>>;

#[allow(non_camel_case_types)]
pub type fil_VerifyPartitionProofResponse = fil_Result<bool>;

#[allow(non_camel_case_types)]
pub type fil_VerifyEmptySectorUpdateProofResponse = fil_Result<bool>;
