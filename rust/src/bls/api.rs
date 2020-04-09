use std::slice::from_raw_parts;

use bls_signatures::{
    aggregate as aggregate_sig,
    groupy::{CurveAffine, CurveProjective, EncodedPoint, GroupDecodingError},
    hash as hash_sig,
    paired::bls12_381::{G2Affine, G2Compressed},
    verify as verify_sig, PrivateKey, PublicKey, Serialize, Signature,
};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use rayon::prelude::*;

use crate::bls::types;
use crate::proofs::types::fil_32ByteArray;

pub const SIGNATURE_BYTES: usize = 96;
pub const PRIVATE_KEY_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 48;
pub const DIGEST_BYTES: usize = 96;

#[repr(C)]
pub struct fil_BLSSignature {
    pub inner: [u8; SIGNATURE_BYTES],
}

#[repr(C)]
pub struct fil_BLSPrivateKey {
    pub inner: [u8; PRIVATE_KEY_BYTES],
}

#[repr(C)]
pub struct fil_BLSPublicKey {
    pub inner: [u8; PUBLIC_KEY_BYTES],
}

#[repr(C)]
pub struct fil_BLSDigest {
    pub inner: [u8; DIGEST_BYTES],
}

/// Unwraps or returns the passed in value.
macro_rules! try_ffi {
    ($res:expr, $val:expr) => {{
        match $res {
            Ok(res) => res,
            Err(_) => return $val,
        }
    }};
}

/// Compute the digest of a message
///
/// # Arguments
///
/// * `message_ptr` - pointer to a message byte array
/// * `message_len` - length of the byte array
#[no_mangle]
pub unsafe extern "C" fn fil_hash(
    message_ptr: *const u8,
    message_len: libc::size_t,
) -> *mut types::fil_HashResponse {
    // prep request
    let message = from_raw_parts(message_ptr, message_len);

    // call method
    let digest = hash_sig(message);

    // prep response
    let mut raw_digest: [u8; DIGEST_BYTES] = [0; DIGEST_BYTES];
    raw_digest.copy_from_slice(digest.into_affine().into_compressed().as_ref());

    let response = types::fil_HashResponse {
        digest: fil_BLSDigest { inner: raw_digest },
    };

    Box::into_raw(Box::new(response))
}

/// Aggregate signatures together into a new signature
///
/// # Arguments
///
/// * `flattened_signatures_ptr` - pointer to a byte array containing signatures
/// * `flattened_signatures_len` - length of the byte array (multiple of SIGNATURE_BYTES)
///
/// Returns `NULL` on error. Result must be freed using `destroy_aggregate_response`.
#[no_mangle]
pub unsafe extern "C" fn fil_aggregate(
    flattened_signatures_ptr: *const u8,
    flattened_signatures_len: libc::size_t,
) -> *mut types::fil_AggregateResponse {
    // prep request
    let signatures = try_ffi!(
        from_raw_parts(flattened_signatures_ptr, flattened_signatures_len)
            .par_chunks(SIGNATURE_BYTES)
            .map(|item| { Signature::from_bytes(item) })
            .collect::<Result<Vec<_>, _>>(),
        std::ptr::null_mut()
    );

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
    aggregate_sig(&signatures)
        .write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    let response = types::fil_AggregateResponse {
        signature: fil_BLSSignature {
            inner: raw_signature,
        },
    };

    Box::into_raw(Box::new(response))
}

/// Verify that a signature is the aggregated signature of hashes - pubkeys
///
/// # Arguments
///
/// * `signature_ptr`             - pointer to a signature byte array (SIGNATURE_BYTES long)
/// * `flattened_digests_ptr`     - pointer to a byte array containing digests
/// * `flattened_digests_len`     - length of the byte array (multiple of DIGEST_BYTES)
/// * `flattened_public_keys_ptr` - pointer to a byte array containing public keys
/// * `flattened_public_keys_len` - length of the array
#[no_mangle]
pub unsafe extern "C" fn fil_verify(
    signature_ptr: *const u8,
    flattened_digests_ptr: *const u8,
    flattened_digests_len: libc::size_t,
    flattened_public_keys_ptr: *const u8,
    flattened_public_keys_len: libc::size_t,
) -> libc::c_int {
    // prep request
    let raw_signature = from_raw_parts(signature_ptr, SIGNATURE_BYTES);
    let signature = try_ffi!(Signature::from_bytes(raw_signature), 0);

    let raw_digests = from_raw_parts(flattened_digests_ptr, flattened_digests_len);
    let raw_public_keys = from_raw_parts(flattened_public_keys_ptr, flattened_public_keys_len);

    if raw_digests.len() % DIGEST_BYTES != 0 {
        return 0;
    }
    if raw_public_keys.len() % PUBLIC_KEY_BYTES != 0 {
        return 0;
    }

    if raw_digests.len() / DIGEST_BYTES != raw_public_keys.len() / PUBLIC_KEY_BYTES {
        return 0;
    }

    let digests: Vec<_> = try_ffi!(
        raw_digests
            .par_chunks(DIGEST_BYTES)
            .map(|item: &[u8]| {
                let mut digest = G2Compressed::empty();
                digest.as_mut().copy_from_slice(item);

                let affine: G2Affine = digest.into_affine()?;
                let projective = affine.into_projective();
                Ok(projective)
            })
            .collect::<Result<Vec<_>, GroupDecodingError>>(),
        0
    );

    let public_keys: Vec<_> = try_ffi!(
        raw_public_keys
            .par_chunks(PUBLIC_KEY_BYTES)
            .map(|item| { PublicKey::from_bytes(item) })
            .collect::<Result<_, _>>(),
        0
    );

    verify_sig(&signature, digests.as_slice(), public_keys.as_slice()) as libc::c_int
}

/// Verify that a signature is the aggregated signature of the hhashed messages
///
/// # Arguments
///
/// * `signature_ptr`             - pointer to a signature byte array (SIGNATURE_BYTES long)
/// * `messages_ptr`              - pointer to an array containing the pointers to the messages
/// * `messages_sizes_ptr`        - pointer to an array containing the lengths of the messages
/// * `messages_len`              - length of the two messages arrays
/// * `flattened_public_keys_ptr` - pointer to a byte array containing public keys
/// * `flattened_public_keys_len` - length of the array
#[no_mangle]
pub unsafe extern "C" fn fil_hash_verify(
    signature_ptr: *const u8,
    messages_ptr: *const *const u8,
    messages_sizes_ptr: *const libc::size_t,
    messages_len: libc::size_t,
    flattened_public_keys_ptr: *const u8,
    flattened_public_keys_len: libc::size_t,
) -> libc::c_int {
    // prep request
    let raw_signature = from_raw_parts(signature_ptr, SIGNATURE_BYTES);
    let signature = try_ffi!(Signature::from_bytes(raw_signature), 0);

    let raw_messages_sizes: &[usize] = from_raw_parts(messages_sizes_ptr, messages_len);
    let raw_messages: &[*const u8] = from_raw_parts(messages_ptr, messages_len);
    let messages: Vec<&[u8]> = raw_messages
        .iter()
        .zip(raw_messages_sizes.iter())
        .map(|(ptr, size)| from_raw_parts(*ptr, *size))
        .collect();

    let raw_public_keys = from_raw_parts(flattened_public_keys_ptr, flattened_public_keys_len);

    if raw_public_keys.len() % PUBLIC_KEY_BYTES != 0 {
        return 0;
    }

    let digests: Vec<_> = messages
        .into_par_iter()
        .map(|message: &[u8]| hash_sig(message))
        .collect::<Vec<_>>();

    let public_keys: Vec<_> = try_ffi!(
        raw_public_keys
            .par_chunks(PUBLIC_KEY_BYTES)
            .map(|item| { PublicKey::from_bytes(item) })
            .collect::<Result<_, _>>(),
        0
    );

    verify_sig(&signature, &digests, &public_keys) as libc::c_int
}

/// Generate a new private key
#[no_mangle]
pub unsafe extern "C" fn fil_private_key_generate() -> *mut types::fil_PrivateKeyGenerateResponse {
    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(&mut OsRng)
        .write_bytes(&mut raw_private_key.as_mut())
        .expect("preallocated");

    let response = types::fil_PrivateKeyGenerateResponse {
        private_key: fil_BLSPrivateKey {
            inner: raw_private_key,
        },
    };

    Box::into_raw(Box::new(response))
}

/// Generate a new private key with seed
///
/// **Warning**: Use this function only for testing or with very secure seeds
///
/// # Arguments
///
/// * `raw_seed` - a seed byte array with 32 bytes
///
/// Returns `NULL` when passed a NULL pointer.
#[no_mangle]
pub unsafe extern "C" fn fil_private_key_generate_with_seed(
    raw_seed: fil_32ByteArray,
) -> *mut types::fil_PrivateKeyGenerateResponse {
    let rng = &mut ChaChaRng::from_seed(raw_seed.inner);

    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(rng)
        .write_bytes(&mut raw_private_key.as_mut())
        .expect("preallocated");

    let response = types::fil_PrivateKeyGenerateResponse {
        private_key: fil_BLSPrivateKey {
            inner: raw_private_key,
        },
    };

    Box::into_raw(Box::new(response))
}

/// Sign a message with a private key and return the signature
///
/// # Arguments
///
/// * `raw_private_key_ptr` - pointer to a private key byte array
/// * `message_ptr` - pointer to a message byte array
/// * `message_len` - length of the byte array
///
/// Returns `NULL` when passed invalid arguments.
#[no_mangle]
pub unsafe extern "C" fn fil_private_key_sign(
    raw_private_key_ptr: *const u8,
    message_ptr: *const u8,
    message_len: libc::size_t,
) -> *mut types::fil_PrivateKeySignResponse {
    // prep request
    let private_key_slice = from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);
    let private_key = try_ffi!(
        PrivateKey::from_bytes(private_key_slice),
        std::ptr::null_mut()
    );
    let message = from_raw_parts(message_ptr, message_len);

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
    PrivateKey::sign(&private_key, message)
        .write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    let response = types::fil_PrivateKeySignResponse {
        signature: fil_BLSSignature {
            inner: raw_signature,
        },
    };

    Box::into_raw(Box::new(response))
}

/// Generate the public key for a private key
///
/// # Arguments
///
/// * `raw_private_key_ptr` - pointer to a private key byte array
///
/// Returns `NULL` when passed invalid arguments.
#[no_mangle]
pub unsafe extern "C" fn fil_private_key_public_key(
    raw_private_key_ptr: *const u8,
) -> *mut types::fil_PrivateKeyPublicKeyResponse {
    let private_key_slice = from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);
    let private_key = try_ffi!(
        PrivateKey::from_bytes(private_key_slice),
        std::ptr::null_mut()
    );

    let mut raw_public_key: [u8; PUBLIC_KEY_BYTES] = [0; PUBLIC_KEY_BYTES];
    private_key
        .public_key()
        .write_bytes(&mut raw_public_key.as_mut())
        .expect("preallocated");

    let response = types::fil_PrivateKeyPublicKeyResponse {
        public_key: fil_BLSPublicKey {
            inner: raw_public_key,
        },
    };

    Box::into_raw(Box::new(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_verification() {
        unsafe {
            let private_key = (*fil_private_key_generate()).private_key.inner;
            let public_key = (*fil_private_key_public_key(&private_key[0]))
                .public_key
                .inner;
            let message = b"hello world";
            let digest = (*fil_hash(&message[0], message.len())).digest.inner;
            let signature = (*fil_private_key_sign(&private_key[0], &message[0], message.len()))
                .signature
                .inner;
            let verified = fil_verify(
                &signature[0],
                &digest[0],
                digest.len(),
                &public_key[0],
                public_key.len(),
            );

            assert_eq!(1, verified);

            let messages = [message.as_ptr()];
            let messages_sizes = [message.len()];
            let verified = fil_hash_verify(
                signature.as_ptr(),
                messages.as_ptr(),
                messages_sizes.as_ptr(),
                1,
                public_key.as_ptr(),
                public_key.len(),
            );

            assert_eq!(1, verified);

            let different_message = b"bye world";
            let different_digest = (*fil_hash(&different_message[0], different_message.len()))
                .digest
                .inner;
            let not_verified = fil_verify(
                &signature[0],
                &different_digest[0],
                different_digest.len(),
                &public_key[0],
                public_key.len(),
            );

            assert_eq!(0, not_verified);

            // garbage verification
            let different_digest = vec![0, 1, 2, 3, 4];
            let not_verified = fil_verify(
                &signature[0],
                &different_digest[0],
                different_digest.len(),
                &public_key[0],
                public_key.len(),
            );

            assert_eq!(0, not_verified);
        }
    }

    #[test]
    fn private_key_with_seed() {
        unsafe {
            let seed = fil_32ByteArray { inner: [5u8; 32] };
            let private_key = (*fil_private_key_generate_with_seed(seed))
                .private_key
                .inner;
            assert_eq!(
                [
                    54, 153, 119, 37, 67, 183, 254, 119, 191, 48, 187, 173, 95, 59, 171, 247, 14,
                    9, 161, 223, 156, 205, 36, 41, 155, 195, 244, 5, 199, 26, 221, 1
                ],
                private_key
            );
        }
    }
}
