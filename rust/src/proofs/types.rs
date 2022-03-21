use std::io::{Error, SeekFrom};
use std::ops::Deref;
use std::ptr;

use anyhow::Result;
use drop_struct_macro_derive::DropStructMacro;
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};
use filecoin_proofs_api::{
    seal::SealCommitPhase2Output, PieceInfo, RegisteredAggregationProof, RegisteredPoStProof,
    RegisteredSealProof, RegisteredUpdateProof, UnpaddedBytesAmount,
};

use crate::util::types::{
    clone_as_vec_from_parts, clone_box_parts, drop_box_from_parts, fil_Array, fil_Bytes, fil_Result,
};

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

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_GenerateWindowPoStResponse {
    pub error_msg: *mut libc::c_char,
    pub proofs_len: libc::size_t,
    pub proofs_ptr: *mut fil_PoStProof,
    pub faulty_sectors_len: libc::size_t,
    pub faulty_sectors_ptr: *mut u64,
    pub status_code: FCPResponseStatus,
}

impl Default for fil_GenerateWindowPoStResponse {
    fn default() -> fil_GenerateWindowPoStResponse {
        fil_GenerateWindowPoStResponse {
            error_msg: ptr::null_mut(),
            proofs_len: 0,
            proofs_ptr: ptr::null_mut(),
            faulty_sectors_len: 0,
            faulty_sectors_ptr: ptr::null_mut(),
            status_code: FCPResponseStatus::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_GenerateWindowPoStResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_GenerateSingleWindowPoStWithVanillaResponse {
    pub error_msg: *mut libc::c_char,
    pub partition_proof: fil_PartitionSnarkProof,
    pub faulty_sectors_len: libc::size_t,
    pub faulty_sectors_ptr: *mut u64,
    pub status_code: FCPResponseStatus,
}

impl Default for fil_GenerateSingleWindowPoStWithVanillaResponse {
    fn default() -> fil_GenerateSingleWindowPoStWithVanillaResponse {
        fil_GenerateSingleWindowPoStWithVanillaResponse {
            error_msg: ptr::null_mut(),
            partition_proof: fil_PartitionSnarkProof {
                registered_proof: fil_RegisteredPoStProof::StackedDrgWinning2KiBV1,
                proof: Default::default(),
            },
            faulty_sectors_len: 0,
            faulty_sectors_ptr: ptr::null_mut(),
            status_code: FCPResponseStatus::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_GenerateSingleWindowPoStWithVanillaResponse);

#[allow(non_camel_case_types)]
pub type fil_GetNumPartitionForFallbackPoStResponse = fil_Result<libc::size_t>;

#[allow(non_camel_case_types)]
pub type fil_MergeWindowPoStPartitionProofsResponse = fil_Result<fil_PoStProof>;

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_WriteWithAlignmentResponse {
    pub comm_p: [u8; 32],
    pub error_msg: *mut libc::c_char,
    pub left_alignment_unpadded: u64,
    pub status_code: FCPResponseStatus,
    pub total_write_unpadded: u64,
}

impl Default for fil_WriteWithAlignmentResponse {
    fn default() -> fil_WriteWithAlignmentResponse {
        fil_WriteWithAlignmentResponse {
            comm_p: Default::default(),
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null_mut(),
            left_alignment_unpadded: 0,
            total_write_unpadded: 0,
        }
    }
}

code_and_message_impl!(fil_WriteWithAlignmentResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_WriteWithoutAlignmentResponse {
    pub comm_p: [u8; 32],
    pub error_msg: *mut libc::c_char,
    pub status_code: FCPResponseStatus,
    pub total_write_unpadded: u64,
}

impl Default for fil_WriteWithoutAlignmentResponse {
    fn default() -> fil_WriteWithoutAlignmentResponse {
        fil_WriteWithoutAlignmentResponse {
            comm_p: Default::default(),
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null_mut(),
            total_write_unpadded: 0,
        }
    }
}

code_and_message_impl!(fil_WriteWithoutAlignmentResponse);

#[allow(non_camel_case_types)]
pub type fil_SealPreCommitPhase1Response = fil_Result<fil_Bytes>;

#[allow(non_camel_case_types)]
pub type fil_FauxRepResponse = fil_Result<fil_32ByteArray>;

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_SealPreCommitPhase2Response {
    pub error_msg: *mut libc::c_char,
    pub status_code: FCPResponseStatus,
    pub registered_proof: fil_RegisteredSealProof,
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
}

impl Default for fil_SealPreCommitPhase2Response {
    fn default() -> fil_SealPreCommitPhase2Response {
        fil_SealPreCommitPhase2Response {
            error_msg: ptr::null_mut(),
            status_code: FCPResponseStatus::FCPNoError,
            registered_proof: fil_RegisteredSealProof::StackedDrg2KiBV1,
            comm_d: Default::default(),
            comm_r: Default::default(),
        }
    }
}

code_and_message_impl!(fil_SealPreCommitPhase2Response);

#[allow(non_camel_case_types)]
pub type fil_SealCommitPhase1Response = fil_Result<fil_Bytes>;

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_SealCommitPhase2Response {
    pub status_code: FCPResponseStatus,
    pub error_msg: *mut libc::c_char,
    pub proof_ptr: *mut u8,
    pub proof_len: libc::size_t,
    pub commit_inputs_ptr: *mut fil_AggregationInputs,
    pub commit_inputs_len: libc::size_t,
}

impl From<&fil_SealCommitPhase2Response> for SealCommitPhase2Output {
    fn from(other: &fil_SealCommitPhase2Response) -> Self {
        let proof = unsafe { clone_as_vec_from_parts(other.proof_ptr, other.proof_len) };

        SealCommitPhase2Output { proof }
    }
}

impl Default for fil_SealCommitPhase2Response {
    fn default() -> fil_SealCommitPhase2Response {
        fil_SealCommitPhase2Response {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null_mut(),
            proof_ptr: ptr::null_mut(),
            proof_len: 0,
            commit_inputs_ptr: ptr::null_mut(),
            commit_inputs_len: 0,
        }
    }
}

impl Clone for fil_SealCommitPhase2Response {
    fn clone(&self) -> Self {
        let proof_ptr = unsafe { clone_box_parts(self.proof_ptr, self.proof_len) };
        let commit_inputs_ptr =
            unsafe { clone_box_parts(self.commit_inputs_ptr, self.commit_inputs_len) };

        fil_SealCommitPhase2Response {
            status_code: self.status_code,
            error_msg: self.error_msg,
            proof_ptr,
            proof_len: self.proof_len,
            commit_inputs_ptr,
            commit_inputs_len: self.commit_inputs_len,
        }
    }
}

code_and_message_impl!(fil_SealCommitPhase2Response);

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

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_GeneratePieceCommitmentResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *mut libc::c_char,
    pub comm_p: [u8; 32],
    /// The number of unpadded bytes in the original piece plus any (unpadded)
    /// alignment bytes added to create a whole merkle tree.
    pub num_bytes_aligned: u64,
}

impl Default for fil_GeneratePieceCommitmentResponse {
    fn default() -> fil_GeneratePieceCommitmentResponse {
        fil_GeneratePieceCommitmentResponse {
            status_code: FCPResponseStatus::FCPNoError,
            comm_p: Default::default(),
            error_msg: ptr::null_mut(),
            num_bytes_aligned: 0,
        }
    }
}

code_and_message_impl!(fil_GeneratePieceCommitmentResponse);

#[allow(non_camel_case_types)]
pub type fil_GenerateDataCommitmentResponse = fil_Result<fil_32ByteArray>;

///

#[allow(non_camel_case_types)]
pub type fil_StringResponse = fil_Result<fil_Bytes>;

#[allow(non_camel_case_types)]
pub type fil_ClearCacheResponse = fil_Result<()>;

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_EmptySectorUpdateEncodeIntoResponse {
    pub error_msg: *mut libc::c_char,
    pub status_code: FCPResponseStatus,
    pub comm_r_new: [u8; 32],
    pub comm_r_last_new: [u8; 32],
    pub comm_d_new: [u8; 32],
}

impl Default for fil_EmptySectorUpdateEncodeIntoResponse {
    fn default() -> fil_EmptySectorUpdateEncodeIntoResponse {
        fil_EmptySectorUpdateEncodeIntoResponse {
            error_msg: ptr::null_mut(),
            status_code: FCPResponseStatus::FCPNoError,
            comm_r_new: Default::default(),
            comm_r_last_new: Default::default(),
            comm_d_new: Default::default(),
        }
    }
}

code_and_message_impl!(fil_EmptySectorUpdateEncodeIntoResponse);

#[allow(non_camel_case_types)]
pub type fil_EmptySectorUpdateDecodeFromResponse = fil_Result<()>;

#[allow(non_camel_case_types)]
pub type fil_EmptySectorUpdateRemoveEncodedDataResponse = fil_Result<()>;

#[repr(C)]
pub struct fil_EmptySectorUpdateProofResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *mut libc::c_char,
    pub proof_len: libc::size_t,
    pub proof_ptr: *mut u8,
}

impl Default for fil_EmptySectorUpdateProofResponse {
    fn default() -> fil_EmptySectorUpdateProofResponse {
        fil_EmptySectorUpdateProofResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null_mut(),
            proof_len: 0,
            proof_ptr: ptr::null_mut(),
        }
    }
}

impl Drop for fil_EmptySectorUpdateProofResponse {
    fn drop(&mut self) {
        unsafe {
            drop_box_from_parts(self.proof_ptr);
            free_c_str(self.error_msg as *mut libc::c_char);
        }
    }
}

code_and_message_impl!(fil_EmptySectorUpdateProofResponse);

#[allow(non_camel_case_types)]
pub type fil_PartitionProofResponse = fil_Result<fil_Array<fil_PartitionProof>>;

#[allow(non_camel_case_types)]
pub type fil_VerifyPartitionProofResponse = fil_Result<bool>;

#[allow(non_camel_case_types)]
pub type fil_VerifyEmptySectorUpdateProofResponse = fil_Result<bool>;
