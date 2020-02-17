use std::io::{Error, SeekFrom};
use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
use paired::bls12_381::Bls12;
// `CodeAndMessage` is the trait implemented by `code_and_message_impl`
use anyhow::Result;
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};
use filecoin_proofs_api::{
    fr32::bytes_into_fr, Candidate, PieceInfo, RegisteredPoStProof, RegisteredSealProof,
    UnpaddedBytesAmount,
};

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
pub enum FFIRegisteredSealProof {
    StackedDrg1KiBV1,
    StackedDrg16MiBV1,
    StackedDrg256MiBV1,
    StackedDrg1GiBV1,
    StackedDrg32GiBV1,
}

impl From<RegisteredSealProof> for FFIRegisteredSealProof {
    fn from(other: RegisteredSealProof) -> Self {
        match other {
            RegisteredSealProof::StackedDrg1KiBV1 => FFIRegisteredSealProof::StackedDrg1KiBV1,
            RegisteredSealProof::StackedDrg16MiBV1 => FFIRegisteredSealProof::StackedDrg16MiBV1,
            RegisteredSealProof::StackedDrg256MiBV1 => FFIRegisteredSealProof::StackedDrg256MiBV1,
            RegisteredSealProof::StackedDrg1GiBV1 => FFIRegisteredSealProof::StackedDrg1GiBV1,
            RegisteredSealProof::StackedDrg32GiBV1 => FFIRegisteredSealProof::StackedDrg32GiBV1,
        }
    }
}

impl From<FFIRegisteredSealProof> for RegisteredSealProof {
    fn from(other: FFIRegisteredSealProof) -> Self {
        match other {
            FFIRegisteredSealProof::StackedDrg1KiBV1 => RegisteredSealProof::StackedDrg1KiBV1,
            FFIRegisteredSealProof::StackedDrg16MiBV1 => RegisteredSealProof::StackedDrg16MiBV1,
            FFIRegisteredSealProof::StackedDrg256MiBV1 => RegisteredSealProof::StackedDrg256MiBV1,
            FFIRegisteredSealProof::StackedDrg1GiBV1 => RegisteredSealProof::StackedDrg1GiBV1,
            FFIRegisteredSealProof::StackedDrg32GiBV1 => RegisteredSealProof::StackedDrg32GiBV1,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFIRegisteredPoStProof {
    StackedDrg1KiBV1,
    StackedDrg16MiBV1,
    StackedDrg256MiBV1,
    StackedDrg1GiBV1,
    StackedDrg32GiBV1,
}

impl From<RegisteredPoStProof> for FFIRegisteredPoStProof {
    fn from(other: RegisteredPoStProof) -> Self {
        match other {
            RegisteredPoStProof::StackedDrg1KiBV1 => FFIRegisteredPoStProof::StackedDrg1KiBV1,
            RegisteredPoStProof::StackedDrg16MiBV1 => FFIRegisteredPoStProof::StackedDrg16MiBV1,
            RegisteredPoStProof::StackedDrg256MiBV1 => FFIRegisteredPoStProof::StackedDrg256MiBV1,
            RegisteredPoStProof::StackedDrg1GiBV1 => FFIRegisteredPoStProof::StackedDrg1GiBV1,
            RegisteredPoStProof::StackedDrg32GiBV1 => FFIRegisteredPoStProof::StackedDrg32GiBV1,
        }
    }
}

impl From<FFIRegisteredPoStProof> for RegisteredPoStProof {
    fn from(other: FFIRegisteredPoStProof) -> Self {
        match other {
            FFIRegisteredPoStProof::StackedDrg1KiBV1 => RegisteredPoStProof::StackedDrg1KiBV1,
            FFIRegisteredPoStProof::StackedDrg16MiBV1 => RegisteredPoStProof::StackedDrg16MiBV1,
            FFIRegisteredPoStProof::StackedDrg256MiBV1 => RegisteredPoStProof::StackedDrg256MiBV1,
            FFIRegisteredPoStProof::StackedDrg1GiBV1 => RegisteredPoStProof::StackedDrg1GiBV1,
            FFIRegisteredPoStProof::StackedDrg32GiBV1 => RegisteredPoStProof::StackedDrg32GiBV1,
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct FFIPublicPieceInfo {
    pub num_bytes: u64,
    pub comm_p: [u8; 32],
}

impl From<FFIPublicPieceInfo> for PieceInfo {
    fn from(x: FFIPublicPieceInfo) -> Self {
        let FFIPublicPieceInfo { num_bytes, comm_p } = x;
        PieceInfo {
            commitment: comm_p,
            size: UnpaddedBytesAmount(num_bytes),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct FFICandidate {
    pub sector_id: u64,
    pub partial_ticket: [u8; 32],
    pub ticket: [u8; 32],
    pub sector_challenge_index: u64,
}

impl FFICandidate {
    pub fn try_into_candidate(self) -> Result<Candidate> {
        let FFICandidate {
            sector_id,
            partial_ticket,
            ticket,
            sector_challenge_index,
        } = self;

        let partial_ticket_fr = bytes_into_fr::<Bls12>(&partial_ticket)?;
        Ok(Candidate {
            sector_id: sector_id.into(),
            partial_ticket: partial_ticket_fr,
            ticket,
            sector_challenge_index,
        })
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct FFIPrivateReplicaInfo {
    pub registered_proof: FFIRegisteredPoStProof,
    pub cache_dir_path: *const libc::c_char,
    pub comm_r: [u8; 32],
    pub replica_path: *const libc::c_char,
    pub sector_id: u64,
}

#[repr(C)]
#[derive(Clone)]
pub struct FFIPublicReplicaInfo {
    pub registered_proof: FFIRegisteredPoStProof,
    pub comm_r: [u8; 32],
    pub sector_id: u64,
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GenerateCandidatesResponse {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatus,
    pub candidates_ptr: *const FFICandidate,
    pub candidates_len: libc::size_t,
}

impl Default for GenerateCandidatesResponse {
    fn default() -> GenerateCandidatesResponse {
        GenerateCandidatesResponse {
            candidates_len: 0,
            candidates_ptr: ptr::null(),
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
        }
    }
}

code_and_message_impl!(GenerateCandidatesResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GeneratePoStResponse {
    pub error_msg: *const libc::c_char,
    pub flattened_proofs_len: libc::size_t,
    pub flattened_proofs_ptr: *const u8,
    pub status_code: FCPResponseStatus,
}

impl Default for GeneratePoStResponse {
    fn default() -> GeneratePoStResponse {
        GeneratePoStResponse {
            error_msg: ptr::null(),
            flattened_proofs_len: 0,
            flattened_proofs_ptr: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
        }
    }
}

code_and_message_impl!(GeneratePoStResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct WriteWithAlignmentResponse {
    pub comm_p: [u8; 32],
    pub error_msg: *const libc::c_char,
    pub left_alignment_unpadded: u64,
    pub status_code: FCPResponseStatus,
    pub total_write_unpadded: u64,
}

impl Default for WriteWithAlignmentResponse {
    fn default() -> WriteWithAlignmentResponse {
        WriteWithAlignmentResponse {
            comm_p: Default::default(),
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            left_alignment_unpadded: 0,
            total_write_unpadded: 0,
        }
    }
}

code_and_message_impl!(WriteWithAlignmentResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct WriteWithoutAlignmentResponse {
    pub comm_p: [u8; 32],
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatus,
    pub total_write_unpadded: u64,
}

impl Default for WriteWithoutAlignmentResponse {
    fn default() -> WriteWithoutAlignmentResponse {
        WriteWithoutAlignmentResponse {
            comm_p: Default::default(),
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            total_write_unpadded: 0,
        }
    }
}

code_and_message_impl!(WriteWithoutAlignmentResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealPreCommitPhase1Response {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatus,
    pub seal_pre_commit_phase1_output_ptr: *const u8,
    pub seal_pre_commit_phase1_output_len: libc::size_t,
}

impl Default for SealPreCommitPhase1Response {
    fn default() -> SealPreCommitPhase1Response {
        SealPreCommitPhase1Response {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
            seal_pre_commit_phase1_output_ptr: ptr::null(),
            seal_pre_commit_phase1_output_len: 0,
        }
    }
}

code_and_message_impl!(SealPreCommitPhase1Response);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealPreCommitPhase2Response {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatus,
    pub registered_proof: FFIRegisteredSealProof,
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
}

impl Default for SealPreCommitPhase2Response {
    fn default() -> SealPreCommitPhase2Response {
        SealPreCommitPhase2Response {
            error_msg: ptr::null(),
            status_code: FCPResponseStatus::FCPNoError,
            registered_proof: FFIRegisteredSealProof::StackedDrg1KiBV1,
            comm_d: Default::default(),
            comm_r: Default::default(),
        }
    }
}

code_and_message_impl!(SealPreCommitPhase2Response);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealCommitPhase1Response {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub seal_commit_phase1_output_ptr: *const u8,
    pub seal_commit_phase1_output_len: libc::size_t,
}

impl Default for SealCommitPhase1Response {
    fn default() -> SealCommitPhase1Response {
        SealCommitPhase1Response {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            seal_commit_phase1_output_ptr: ptr::null(),
            seal_commit_phase1_output_len: 0,
        }
    }
}

code_and_message_impl!(SealCommitPhase1Response);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealCommitPhase2Response {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub proof_ptr: *const u8,
    pub proof_len: libc::size_t,
}

impl Default for SealCommitPhase2Response {
    fn default() -> SealCommitPhase2Response {
        SealCommitPhase2Response {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            proof_ptr: ptr::null(),
            proof_len: 0,
        }
    }
}

code_and_message_impl!(SealCommitPhase2Response);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct UnsealResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for UnsealResponse {
    fn default() -> UnsealResponse {
        UnsealResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

code_and_message_impl!(UnsealResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct UnsealRangeResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for UnsealRangeResponse {
    fn default() -> UnsealRangeResponse {
        UnsealRangeResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

code_and_message_impl!(UnsealRangeResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct VerifySealResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for VerifySealResponse {
    fn default() -> VerifySealResponse {
        VerifySealResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

code_and_message_impl!(VerifySealResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct VerifyPoStResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for VerifyPoStResponse {
    fn default() -> VerifyPoStResponse {
        VerifyPoStResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

code_and_message_impl!(VerifyPoStResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct FinalizeTicketResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub ticket: [u8; 32],
}

impl Default for FinalizeTicketResponse {
    fn default() -> Self {
        FinalizeTicketResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            ticket: [0u8; 32],
        }
    }
}

code_and_message_impl!(FinalizeTicketResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GeneratePieceCommitmentResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub comm_p: [u8; 32],
    /// The number of unpadded bytes in the original piece plus any (unpadded)
    /// alignment bytes added to create a whole merkle tree.
    pub num_bytes_aligned: u64,
}

impl Default for GeneratePieceCommitmentResponse {
    fn default() -> GeneratePieceCommitmentResponse {
        GeneratePieceCommitmentResponse {
            status_code: FCPResponseStatus::FCPNoError,
            comm_p: Default::default(),
            error_msg: ptr::null(),
            num_bytes_aligned: 0,
        }
    }
}

code_and_message_impl!(GeneratePieceCommitmentResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GenerateDataCommitmentResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub comm_d: [u8; 32],
}

impl Default for GenerateDataCommitmentResponse {
    fn default() -> GenerateDataCommitmentResponse {
        GenerateDataCommitmentResponse {
            status_code: FCPResponseStatus::FCPNoError,
            comm_d: Default::default(),
            error_msg: ptr::null(),
        }
    }
}

code_and_message_impl!(GenerateDataCommitmentResponse);

///

#[repr(C)]
#[derive(DropStructMacro)]
pub struct StringResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub string_val: *const libc::c_char,
}

impl Default for StringResponse {
    fn default() -> StringResponse {
        StringResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            string_val: ptr::null(),
        }
    }
}

code_and_message_impl!(StringResponse);
