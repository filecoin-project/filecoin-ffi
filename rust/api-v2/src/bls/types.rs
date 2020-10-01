use crate::bls::api::{fil_BLSDigestV2, fil_BLSPrivateKeyV2, fil_BLSPublicKeyV2, fil_BLSSignatureV2};

/// HashResponse

#[repr(C)]
pub struct fil_HashResponseV2 {
    pub digest: fil_BLSDigestV2,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_hash_response(ptr: *mut fil_HashResponseV2) {
    let _ = Box::from_raw(ptr);
}

/// AggregateResponse

#[repr(C)]
pub struct fil_AggregateResponseV2 {
    pub signature: fil_BLSSignatureV2,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_aggregate_response(ptr: *mut fil_AggregateResponseV2) {
    let _ = Box::from_raw(ptr);
}

/// PrivateKeyGenerateResponse

#[repr(C)]
pub struct fil_PrivateKeyGenerateResponseV2 {
    pub private_key: fil_BLSPrivateKeyV2,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_private_key_generate_response(
    ptr: *mut fil_PrivateKeyGenerateResponseV2,
) {
    let _ = Box::from_raw(ptr);
}

/// PrivateKeySignResponse

#[repr(C)]
pub struct fil_PrivateKeySignResponseV2 {
    pub signature: fil_BLSSignatureV2,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_private_key_sign_response(
    ptr: *mut fil_PrivateKeySignResponseV2,
) {
    let _ = Box::from_raw(ptr);
}

/// PrivateKeyPublicKeyResponse

#[repr(C)]
pub struct fil_PrivateKeyPublicKeyResponseV2 {
    pub public_key: fil_BLSPublicKeyV2,
}

#[no_mangle]
pub unsafe extern "C" fn fil_destroy_private_key_public_key_response(
    ptr: *mut fil_PrivateKeyPublicKeyResponseV2,
) {
    let _ = Box::from_raw(ptr);
}
