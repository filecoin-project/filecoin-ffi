use safer_ffi::prelude::*;

use crate::bls::api::{BLSDigest, BLSPrivateKey, BLSPublicKey, BLSSignature};

/// HashResponse
#[derive_ReprC]
#[repr(C)]
pub struct HashResponse {
    pub digest: BLSDigest,
}

#[ffi_export]
pub fn destroy_hash_response(ptr: repr_c::Box<HashResponse>) {
    drop(ptr);
}

/// AggregateResponse
#[derive_ReprC]
#[repr(C)]
pub struct AggregateResponse {
    pub signature: BLSSignature,
}

#[ffi_export]
pub fn destroy_aggregate_response(ptr: repr_c::Box<AggregateResponse>) {
    drop(ptr);
}

/// PrivateKeyGenerateResponse
#[derive_ReprC]
#[repr(C)]
pub struct PrivateKeyGenerateResponse {
    pub private_key: BLSPrivateKey,
}

#[ffi_export]
pub fn destroy_private_key_generate_response(ptr: repr_c::Box<PrivateKeyGenerateResponse>) {
    drop(ptr);
}

/// PrivateKeySignResponse
#[derive_ReprC]
#[repr(C)]
pub struct PrivateKeySignResponse {
    pub signature: BLSSignature,
}

#[ffi_export]
pub fn destroy_private_key_sign_response(ptr: repr_c::Box<PrivateKeySignResponse>) {
    drop(ptr);
}

/// PrivateKeyPublicKeyResponse
#[derive_ReprC]
#[repr(C)]
pub struct PrivateKeyPublicKeyResponse {
    pub public_key: BLSPublicKey,
}

#[ffi_export]
pub fn destroy_private_key_public_key_response(ptr: repr_c::Box<PrivateKeyPublicKeyResponse>) {
    drop(ptr);
}

/// AggregateResponse
#[derive_ReprC]
#[repr(C)]
pub struct ZeroSignatureResponse {
    pub signature: BLSSignature,
}

#[ffi_export]
pub fn destroy_zero_signature_response(ptr: repr_c::Box<ZeroSignatureResponse>) {
    drop(ptr);
}
