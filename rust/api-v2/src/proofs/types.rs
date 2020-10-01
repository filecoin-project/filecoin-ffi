use std::io::{Error, SeekFrom};
use std::ptr;
use std::slice::from_raw_parts;

use anyhow::Result;
use drop_struct_macro_derive::DropStructMacro;
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage};
use filecoin_proofs_api_v2::{
    PieceInfo, RegisteredPoStProof, RegisteredSealProof, UnpaddedBytesAmount,
};

use ffi_toolkit::FCPResponseStatus as _FCPResponseStatus;

pub type FCPResponseStatusV2 = _FCPResponseStatus;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fil_32ByteArrayV2 {
    pub inner: [u8; 32],
}

/// FileDescriptorRef does not drop its file descriptor when it is dropped. Its
/// owner must manage the lifecycle of the file descriptor.
pub struct FileDescriptorRefV2(std::mem::ManuallyDrop<std::fs::File>);

impl FileDescriptorRefV2 {
    #[cfg(not(target_os = "windows"))]
    pub unsafe fn new(raw: std::os::unix::io::RawFd) -> Self {
        use std::os::unix::io::FromRawFd;
        FileDescriptorRefV2(std::mem::ManuallyDrop::new(std::fs::File::from_raw_fd(raw)))
    }
}

impl std::io::Read for FileDescriptorRefV2 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for FileDescriptorRefV2 {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.0.flush()
    }
}

impl std::io::Seek for FileDescriptorRefV2 {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Error> {
        self.0.seek(pos)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum fil_RegisteredSealProofV2 {
    StackedDrg2KiBV2,
    StackedDrg8MiBV2,
    StackedDrg512MiBV2,
    StackedDrg32GiBV2,
    StackedDrg64GiBV2,
}

impl From<RegisteredSealProof> for fil_RegisteredSealProofV2 {
    fn from(other: RegisteredSealProof) -> Self {
        match other {
            RegisteredSealProof::StackedDrg2KiBV2 => fil_RegisteredSealProofV2::StackedDrg2KiBV2,
            RegisteredSealProof::StackedDrg8MiBV2 => fil_RegisteredSealProofV2::StackedDrg8MiBV2,
            RegisteredSealProof::StackedDrg512MiBV2 => fil_RegisteredSealProofV2::StackedDrg512MiBV2,
            RegisteredSealProof::StackedDrg32GiBV2 => fil_RegisteredSealProofV2::StackedDrg32GiBV2,
            RegisteredSealProof::StackedDrg64GiBV2 => fil_RegisteredSealProofV2::StackedDrg64GiBV2,
        }
    }
}

impl From<fil_RegisteredSealProofV2> for RegisteredSealProof {
    fn from(other: fil_RegisteredSealProofV2) -> Self {
        match other {
            fil_RegisteredSealProofV2::StackedDrg2KiBV2 => RegisteredSealProof::StackedDrg2KiBV2,
            fil_RegisteredSealProofV2::StackedDrg8MiBV2 => RegisteredSealProof::StackedDrg8MiBV2,
            fil_RegisteredSealProofV2::StackedDrg512MiBV2 => RegisteredSealProof::StackedDrg512MiBV2,
            fil_RegisteredSealProofV2::StackedDrg32GiBV2 => RegisteredSealProof::StackedDrg32GiBV2,
            fil_RegisteredSealProofV2::StackedDrg64GiBV2 => RegisteredSealProof::StackedDrg64GiBV2,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum fil_RegisteredPoStProofV2 {
    StackedDrgWinning2KiBV2,
    StackedDrgWinning8MiBV2,
    StackedDrgWinning512MiBV2,
    StackedDrgWinning32GiBV2,
    StackedDrgWinning64GiBV2,
    StackedDrgWindow2KiBV2,
    StackedDrgWindow8MiBV2,
    StackedDrgWindow512MiBV2,
    StackedDrgWindow32GiBV2,
    StackedDrgWindow64GiBV2,
}

impl From<RegisteredPoStProof> for fil_RegisteredPoStProofV2 {
    fn from(other: RegisteredPoStProof) -> Self {
        use RegisteredPoStProof::*;

        match other {
            StackedDrgWinning2KiBV2 => fil_RegisteredPoStProofV2::StackedDrgWinning2KiBV2,
            StackedDrgWinning8MiBV2 => fil_RegisteredPoStProofV2::StackedDrgWinning8MiBV2,
            StackedDrgWinning512MiBV2 => fil_RegisteredPoStProofV2::StackedDrgWinning512MiBV2,
            StackedDrgWinning32GiBV2 => fil_RegisteredPoStProofV2::StackedDrgWinning32GiBV2,
            StackedDrgWinning64GiBV2 => fil_RegisteredPoStProofV2::StackedDrgWinning64GiBV2,
            StackedDrgWindow2KiBV2 => fil_RegisteredPoStProofV2::StackedDrgWindow2KiBV2,
            StackedDrgWindow8MiBV2 => fil_RegisteredPoStProofV2::StackedDrgWindow8MiBV2,
            StackedDrgWindow512MiBV2 => fil_RegisteredPoStProofV2::StackedDrgWindow512MiBV2,
            StackedDrgWindow32GiBV2 => fil_RegisteredPoStProofV2::StackedDrgWindow32GiBV2,
            StackedDrgWindow64GiBV2 => fil_RegisteredPoStProofV2::StackedDrgWindow64GiBV2,
        }
    }
}

impl From<fil_RegisteredPoStProofV2> for RegisteredPoStProof {
    fn from(other: fil_RegisteredPoStProofV2) -> Self {
        use RegisteredPoStProof::*;

        match other {
            fil_RegisteredPoStProofV2::StackedDrgWinning2KiBV2 => StackedDrgWinning2KiBV2,
            fil_RegisteredPoStProofV2::StackedDrgWinning8MiBV2 => StackedDrgWinning8MiBV2,
            fil_RegisteredPoStProofV2::StackedDrgWinning512MiBV2 => StackedDrgWinning512MiBV2,
            fil_RegisteredPoStProofV2::StackedDrgWinning32GiBV2 => StackedDrgWinning32GiBV2,
            fil_RegisteredPoStProofV2::StackedDrgWinning64GiBV2 => StackedDrgWinning64GiBV2,
            fil_RegisteredPoStProofV2::StackedDrgWindow2KiBV2 => StackedDrgWindow2KiBV2,
            fil_RegisteredPoStProofV2::StackedDrgWindow8MiBV2 => StackedDrgWindow8MiBV2,
            fil_RegisteredPoStProofV2::StackedDrgWindow512MiBV2 => StackedDrgWindow512MiBV2,
            fil_RegisteredPoStProofV2::StackedDrgWindow32GiBV2 => StackedDrgWindow32GiBV2,
            fil_RegisteredPoStProofV2::StackedDrgWindow64GiBV2 => StackedDrgWindow64GiBV2,
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct fil_PublicPieceInfoV2 {
    pub num_bytes: u64,
    pub comm_p: [u8; 32],
}

impl From<fil_PublicPieceInfoV2> for PieceInfo {
    fn from(x: fil_PublicPieceInfoV2) -> Self {
        let fil_PublicPieceInfoV2 { num_bytes, comm_p } = x;
        PieceInfo {
            commitment: comm_p,
            size: UnpaddedBytesAmount(num_bytes),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct fil_PoStProofV2 {
    pub registered_proof: fil_RegisteredPoStProofV2,
    pub proof_len: libc::size_t,
    pub proof_ptr: *const u8,
}

impl Drop for fil_PoStProofV2 {
    fn drop(&mut self) {
        let _ = unsafe {
            Vec::from_raw_parts(self.proof_ptr as *mut u8, self.proof_len, self.proof_len)
        };
    }
}

#[derive(Clone, Debug)]
pub struct PoStProofV2 {
    pub registered_proof: RegisteredPoStProof,
    pub proof: Vec<u8>,
}

impl From<fil_PoStProofV2> for PoStProofV2 {
    fn from(other: fil_PoStProofV2) -> Self {
        let proof = unsafe { from_raw_parts(other.proof_ptr, other.proof_len).to_vec() };

        PoStProofV2 {
            registered_proof: other.registered_proof.into(),
            proof,
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct fil_PrivateReplicaInfoV2 {
    pub registered_proof: fil_RegisteredPoStProofV2,
    pub cache_dir_path: *const libc::c_char,
    pub comm_r: [u8; 32],
    pub replica_path: *const libc::c_char,
    pub sector_id: u64,
}

#[repr(C)]
#[derive(Clone)]
pub struct fil_PublicReplicaInfoV2 {
    pub registered_proof: fil_RegisteredPoStProofV2,
    pub comm_r: [u8; 32],
    pub sector_id: u64,
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_GenerateWinningPoStSectorChallengeV2 {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatusV2,
    pub ids_ptr: *const u64,
    pub ids_len: libc::size_t,
}

impl Default for fil_GenerateWinningPoStSectorChallengeV2 {
    fn default() -> fil_GenerateWinningPoStSectorChallengeV2 {
        fil_GenerateWinningPoStSectorChallengeV2 {
            ids_len: 0,
            ids_ptr: ptr::null(),
            error_msg: ptr::null(),
            status_code: FCPResponseStatusV2::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_GenerateWinningPoStSectorChallengeV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_GenerateWinningPoStResponseV2 {
    pub error_msg: *const libc::c_char,
    pub proofs_len: libc::size_t,
    pub proofs_ptr: *const fil_PoStProofV2,
    pub status_code: FCPResponseStatusV2,
}

impl Default for fil_GenerateWinningPoStResponseV2 {
    fn default() -> fil_GenerateWinningPoStResponseV2 {
        fil_GenerateWinningPoStResponseV2 {
            error_msg: ptr::null(),
            proofs_len: 0,
            proofs_ptr: ptr::null(),
            status_code: FCPResponseStatusV2::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_GenerateWinningPoStResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_GenerateWindowPoStResponseV2 {
    pub error_msg: *const libc::c_char,
    pub proofs_len: libc::size_t,
    pub proofs_ptr: *const fil_PoStProofV2,
    pub faulty_sectors_len: libc::size_t,
    pub faulty_sectors_ptr: *const u64,
    pub status_code: FCPResponseStatusV2,
}

impl Default for fil_GenerateWindowPoStResponseV2 {
    fn default() -> fil_GenerateWindowPoStResponseV2 {
        fil_GenerateWindowPoStResponseV2 {
            error_msg: ptr::null(),
            proofs_len: 0,
            proofs_ptr: ptr::null(),
            faulty_sectors_len: 0,
            faulty_sectors_ptr: ptr::null(),
            status_code: FCPResponseStatusV2::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_GenerateWindowPoStResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_WriteWithAlignmentResponseV2 {
    pub comm_p: [u8; 32],
    pub error_msg: *const libc::c_char,
    pub left_alignment_unpadded: u64,
    pub status_code: FCPResponseStatusV2,
    pub total_write_unpadded: u64,
}

impl Default for fil_WriteWithAlignmentResponseV2 {
    fn default() -> fil_WriteWithAlignmentResponseV2 {
        fil_WriteWithAlignmentResponseV2 {
            comm_p: Default::default(),
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
            left_alignment_unpadded: 0,
            total_write_unpadded: 0,
        }
    }
}

code_and_message_impl!(fil_WriteWithAlignmentResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_WriteWithoutAlignmentResponseV2 {
    pub comm_p: [u8; 32],
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatusV2,
    pub total_write_unpadded: u64,
}

impl Default for fil_WriteWithoutAlignmentResponseV2 {
    fn default() -> fil_WriteWithoutAlignmentResponseV2 {
        fil_WriteWithoutAlignmentResponseV2 {
            comm_p: Default::default(),
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
            total_write_unpadded: 0,
        }
    }
}

code_and_message_impl!(fil_WriteWithoutAlignmentResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_SealPreCommitPhase1ResponseV2 {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatusV2,
    pub seal_pre_commit_phase1_output_ptr: *const u8,
    pub seal_pre_commit_phase1_output_len: libc::size_t,
}

impl Default for fil_SealPreCommitPhase1ResponseV2 {
    fn default() -> fil_SealPreCommitPhase1ResponseV2 {
        fil_SealPreCommitPhase1ResponseV2 {
            error_msg: ptr::null(),
            status_code: FCPResponseStatusV2::FCPNoError,
            seal_pre_commit_phase1_output_ptr: ptr::null(),
            seal_pre_commit_phase1_output_len: 0,
        }
    }
}

code_and_message_impl!(fil_SealPreCommitPhase1ResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_FauxRepResponseV2 {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatusV2,
    pub commitment: [u8; 32],
}

impl Default for fil_FauxRepResponseV2 {
    fn default() -> fil_FauxRepResponseV2 {
        fil_FauxRepResponseV2 {
            error_msg: ptr::null(),
            status_code: FCPResponseStatusV2::FCPNoError,
            commitment: Default::default(),
        }
    }
}

code_and_message_impl!(fil_FauxRepResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_SealPreCommitPhase2ResponseV2 {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatusV2,
    pub registered_proof: fil_RegisteredSealProofV2,
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
}

impl Default for fil_SealPreCommitPhase2ResponseV2 {
    fn default() -> fil_SealPreCommitPhase2ResponseV2 {
        fil_SealPreCommitPhase2ResponseV2 {
            error_msg: ptr::null(),
            status_code: FCPResponseStatusV2::FCPNoError,
            registered_proof: fil_RegisteredSealProofV2::StackedDrg2KiBV2,
            comm_d: Default::default(),
            comm_r: Default::default(),
        }
    }
}

code_and_message_impl!(fil_SealPreCommitPhase2ResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_SealCommitPhase1ResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
    pub seal_commit_phase1_output_ptr: *const u8,
    pub seal_commit_phase1_output_len: libc::size_t,
}

impl Default for fil_SealCommitPhase1ResponseV2 {
    fn default() -> fil_SealCommitPhase1ResponseV2 {
        fil_SealCommitPhase1ResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
            seal_commit_phase1_output_ptr: ptr::null(),
            seal_commit_phase1_output_len: 0,
        }
    }
}

code_and_message_impl!(fil_SealCommitPhase1ResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_SealCommitPhase2ResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
    pub proof_ptr: *const u8,
    pub proof_len: libc::size_t,
}

impl Default for fil_SealCommitPhase2ResponseV2 {
    fn default() -> fil_SealCommitPhase2ResponseV2 {
        fil_SealCommitPhase2ResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
            proof_ptr: ptr::null(),
            proof_len: 0,
        }
    }
}

code_and_message_impl!(fil_SealCommitPhase2ResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_UnsealRangeResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
}

impl Default for fil_UnsealRangeResponseV2 {
    fn default() -> fil_UnsealRangeResponseV2 {
        fil_UnsealRangeResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

code_and_message_impl!(fil_UnsealRangeResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_VerifySealResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for fil_VerifySealResponseV2 {
    fn default() -> fil_VerifySealResponseV2 {
        fil_VerifySealResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

code_and_message_impl!(fil_VerifySealResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_VerifyWinningPoStResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for fil_VerifyWinningPoStResponseV2 {
    fn default() -> fil_VerifyWinningPoStResponseV2 {
        fil_VerifyWinningPoStResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

code_and_message_impl!(fil_VerifyWinningPoStResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_VerifyWindowPoStResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for fil_VerifyWindowPoStResponseV2 {
    fn default() -> fil_VerifyWindowPoStResponseV2 {
        fil_VerifyWindowPoStResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

code_and_message_impl!(fil_VerifyWindowPoStResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_FinalizeTicketResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
    pub ticket: [u8; 32],
}

impl Default for fil_FinalizeTicketResponseV2 {
    fn default() -> Self {
        fil_FinalizeTicketResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
            ticket: [0u8; 32],
        }
    }
}

code_and_message_impl!(fil_FinalizeTicketResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_GeneratePieceCommitmentResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
    pub comm_p: [u8; 32],
    /// The number of unpadded bytes in the original piece plus any (unpadded)
    /// alignment bytes added to create a whole merkle tree.
    pub num_bytes_aligned: u64,
}

impl Default for fil_GeneratePieceCommitmentResponseV2 {
    fn default() -> fil_GeneratePieceCommitmentResponseV2 {
        fil_GeneratePieceCommitmentResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            comm_p: Default::default(),
            error_msg: ptr::null(),
            num_bytes_aligned: 0,
        }
    }
}

code_and_message_impl!(fil_GeneratePieceCommitmentResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_GenerateDataCommitmentResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
    pub comm_d: [u8; 32],
}

impl Default for fil_GenerateDataCommitmentResponseV2 {
    fn default() -> fil_GenerateDataCommitmentResponseV2 {
        fil_GenerateDataCommitmentResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            comm_d: Default::default(),
            error_msg: ptr::null(),
        }
    }
}

code_and_message_impl!(fil_GenerateDataCommitmentResponseV2);

///

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_StringResponseV2 {
    pub status_code: FCPResponseStatusV2,
    pub error_msg: *const libc::c_char,
    pub string_val: *const libc::c_char,
}

impl Default for fil_StringResponseV2 {
    fn default() -> fil_StringResponseV2 {
        fil_StringResponseV2 {
            status_code: FCPResponseStatusV2::FCPNoError,
            error_msg: ptr::null(),
            string_val: ptr::null(),
        }
    }
}

code_and_message_impl!(fil_StringResponseV2);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct fil_ClearCacheResponseV2 {
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatusV2,
}

impl Default for fil_ClearCacheResponseV2 {
    fn default() -> fil_ClearCacheResponseV2 {
        fil_ClearCacheResponseV2 {
            error_msg: ptr::null(),
            status_code: FCPResponseStatusV2::FCPNoError,
        }
    }
}

code_and_message_impl!(fil_ClearCacheResponseV2);
