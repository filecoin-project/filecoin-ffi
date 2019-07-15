use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
use ffi_toolkit::free_c_str;

////////////////////////////////////////////////////////////////////////////////
/// VerifySealResponse
//////////////////////

#[repr(C)]
#[derive(DropStructMacro)]
pub struct VerifySealResponse {
    pub status_code: isize,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for VerifySealResponse {
    fn default() -> VerifySealResponse {
        VerifySealResponse {
            status_code: 0,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
/// VerifyPoStResponse
//////////////////////

#[repr(C)]
#[derive(DropStructMacro)]
pub struct VerifyPoStResponse {
    pub status_code: isize,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for VerifyPoStResponse {
    fn default() -> VerifyPoStResponse {
        VerifyPoStResponse {
            status_code: 0,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// VerifyPieceInclusionProofResponse
/////////////////////////////////////

#[repr(C)]
#[derive(DropStructMacro)]
pub struct VerifyPieceInclusionProofResponse {
    pub status_code: isize,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for VerifyPieceInclusionProofResponse {
    fn default() -> Self {
        VerifyPieceInclusionProofResponse {
            status_code: 0,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// GeneratePieceCommitmentResponse
///////////////////////////////////

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GeneratePieceCommitmentResponse {
    pub status_code: isize,
    pub error_msg: *const libc::c_char,
    pub comm_p: [u8; 32],
    pub padded_and_aligned_piece_size: u64,
}

impl Default for GeneratePieceCommitmentResponse {
    fn default() -> GeneratePieceCommitmentResponse {
        GeneratePieceCommitmentResponse {
            status_code: 0,
            error_msg: ptr::null(),
            comm_p: Default::default(),
            padded_and_aligned_piece_size: 0,
        }
    }
}
