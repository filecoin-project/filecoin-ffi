use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
// `CodeAndMessage` is the trait implemented by `code_and_message_impl`
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};

////////////////////////////////////////////////////////////////////////////////
/// VerifySealResponse
//////////////////////

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

////////////////////////////////////////////////////////////////////////////////
/// VerifyPoStResponse
//////////////////////

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

///////////////////////////////////////////////////////////////////////////////
/// GeneratePieceCommitmentResponse
///////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
/// GenerateDataCommitmentResponse
//////////////////////////////////

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
