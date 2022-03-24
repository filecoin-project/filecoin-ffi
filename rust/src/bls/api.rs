use bls_signatures::{
    aggregate as aggregate_sig, hash as hash_sig, verify as verify_sig,
    verify_messages as verify_messages_sig, Error, PrivateKey, PublicKey, Serialize, Signature,
};
use blstrs::{G2Affine, G2Projective};
use group::prime::PrimeCurveAffine;
use group::GroupEncoding;

use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use rayon::prelude::*;
use safer_ffi::prelude::*;

use crate::bls::types;
use crate::proofs::types::ByteArray32;

pub const SIGNATURE_BYTES: usize = 96;
pub const PRIVATE_KEY_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 48;
pub const DIGEST_BYTES: usize = 96;

#[derive_ReprC]
#[repr(C)]
pub struct BLSSignature {
    pub inner: [u8; SIGNATURE_BYTES],
}

#[derive_ReprC]
#[repr(C)]
pub struct BLSPrivateKey {
    pub inner: [u8; PRIVATE_KEY_BYTES],
}

#[derive_ReprC]
#[repr(C)]
pub struct BLSPublicKey {
    pub inner: [u8; PUBLIC_KEY_BYTES],
}

#[derive_ReprC]
#[repr(C)]
pub struct BLSDigest {
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
/// * `message` - reference to a message byte array
#[ffi_export]
pub fn hash(message: c_slice::Ref<u8>) -> repr_c::Box<types::HashResponse> {
    // call method
    let digest = hash_sig(&message);

    // prep response
    let mut raw_digest: [u8; DIGEST_BYTES] = [0; DIGEST_BYTES];
    raw_digest.copy_from_slice(digest.to_bytes().as_ref());

    let response = types::HashResponse {
        digest: BLSDigest { inner: raw_digest },
    };

    repr_c::Box::new(response)
}

/// Aggregate signatures together into a new signature
///
/// # Arguments
///
/// * `flattened_signatures` - byte array containing signatures
///
/// Returns `NULL` on error. Result must be freed using `destroy_aggregate_response`.
#[ffi_export]
pub fn aggregate(
    flattened_signatures: c_slice::Ref<u8>,
) -> Option<repr_c::Box<types::AggregateResponse>> {
    // prep request
    let signatures = try_ffi!(
        flattened_signatures
            .par_chunks(SIGNATURE_BYTES)
            .map(|item| { Signature::from_bytes(item) })
            .collect::<Result<Vec<_>, _>>(),
        None
    );

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];

    let aggregated = try_ffi!(aggregate_sig(&signatures), None);
    aggregated
        .write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    let response = types::AggregateResponse {
        signature: BLSSignature {
            inner: raw_signature,
        },
    };

    Some(repr_c::Box::new(response))
}

/// Verify that a signature is the aggregated signature of hashes - pubkeys
///
/// # Arguments
///
/// * `signature_ptr`             - pointer to a signature byte array (SIGNATURE_BYTES long)
/// * `flattened_digests`     - byte array containing digests
/// * `flattened_public_keys` - byte array containing public keys
#[ffi_export]
pub fn verify(
    signature: &[u8; SIGNATURE_BYTES],
    flattened_digests: c_slice::Ref<u8>,
    flattened_public_keys: c_slice::Ref<u8>,
) -> libc::c_int {
    // prep request
    let signature = try_ffi!(Signature::from_bytes(signature), 0);

    if flattened_digests.len() % DIGEST_BYTES != 0 {
        return 0;
    }
    if flattened_public_keys.len() % PUBLIC_KEY_BYTES != 0 {
        return 0;
    }

    if flattened_digests.len() / DIGEST_BYTES != flattened_public_keys.len() / PUBLIC_KEY_BYTES {
        return 0;
    }

    let digests: Vec<_> = try_ffi!(
        flattened_digests
            .par_chunks(DIGEST_BYTES)
            .map(|item: &[u8]| {
                let mut digest = [0u8; DIGEST_BYTES];
                digest.as_mut().copy_from_slice(item);

                let affine: Option<G2Affine> = Option::from(G2Affine::from_compressed(&digest));
                affine.map(Into::into).ok_or(Error::CurveDecode)
            })
            .collect::<Result<Vec<G2Projective>, Error>>(),
        0
    );

    let public_keys: Vec<_> = try_ffi!(
        flattened_public_keys
            .par_chunks(PUBLIC_KEY_BYTES)
            .map(|item| { PublicKey::from_bytes(item) })
            .collect::<Result<_, _>>(),
        0
    );

    verify_sig(&signature, digests.as_slice(), public_keys.as_slice()) as libc::c_int
}

/// Verify that a signature is the aggregated signature of the hashed messages
///
/// # Arguments
///
/// * `signature`             - pointer to a signature byte array (SIGNATURE_BYTES long)
/// * `messages`              - pointer to an array containing the pointers to the messages
/// * `messages_sizes_ptr`        - pointer to an array containing the lengths of the messages
/// * `messages_len`              - length of the two messages arrays
/// * `flattened_public_keys_ptr` - pointer to a byte array containing public keys
/// * `flattened_public_keys_len` - length of the array
#[ffi_export]
pub fn hash_verify(
    signature: &[u8; SIGNATURE_BYTES],
    flattened_messages: c_slice::Ref<u8>,
    message_sizes: c_slice::Ref<libc::size_t>,
    flattened_public_keys: c_slice::Ref<u8>,
) -> libc::c_int {
    // prep request
    let signature = try_ffi!(Signature::from_bytes(signature), 0);

    let flattened = flattened_messages;
    let chunk_sizes = message_sizes;

    // split the flattened message array into slices of individual messages to
    // be hashed
    let mut messages: Vec<&[u8]> = Vec::with_capacity(chunk_sizes.len());
    let mut offset = 0;
    for chunk_size in chunk_sizes.iter() {
        messages.push(&flattened[offset..offset + *chunk_size]);
        offset += *chunk_size
    }

    let raw_public_keys = flattened_public_keys;

    if raw_public_keys.len() % PUBLIC_KEY_BYTES != 0 {
        return 0;
    }

    let public_keys: Vec<_> = try_ffi!(
        raw_public_keys
            .par_chunks(PUBLIC_KEY_BYTES)
            .map(|item| { PublicKey::from_bytes(item) })
            .collect::<Result<_, _>>(),
        0
    );

    verify_messages_sig(&signature, &messages, &public_keys) as libc::c_int
}

/// Generate a new private key
#[ffi_export]
pub fn private_key_generate() -> repr_c::Box<types::PrivateKeyGenerateResponse> {
    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(&mut OsRng)
        .write_bytes(&mut raw_private_key.as_mut())
        .expect("preallocated");

    let response = types::PrivateKeyGenerateResponse {
        private_key: BLSPrivateKey {
            inner: raw_private_key,
        },
    };

    repr_c::Box::new(response)
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
#[ffi_export]
pub fn private_key_generate_with_seed(
    raw_seed: ByteArray32,
) -> repr_c::Box<types::PrivateKeyGenerateResponse> {
    let rng = &mut ChaChaRng::from_seed(raw_seed.inner);

    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(rng)
        .write_bytes(&mut raw_private_key.as_mut())
        .expect("preallocated");

    let response = types::PrivateKeyGenerateResponse {
        private_key: BLSPrivateKey {
            inner: raw_private_key,
        },
    };

    repr_c::Box::new(response)
}

/// Sign a message with a private key and return the signature
///
/// # Arguments
///
/// * `raw_private_key` - pointer to a private key byte array
/// * `message` - pointer to a message byte array
///
/// Returns `NULL` when passed invalid arguments.
#[ffi_export]
pub fn private_key_sign(
    raw_private_key: &[u8; PRIVATE_KEY_BYTES],
    message: c_slice::Ref<u8>,
) -> Option<repr_c::Box<types::PrivateKeySignResponse>> {
    let private_key = try_ffi!(PrivateKey::from_bytes(raw_private_key), None);

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
    PrivateKey::sign(&private_key, &message[..])
        .write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    let response = types::PrivateKeySignResponse {
        signature: BLSSignature {
            inner: raw_signature,
        },
    };

    Some(repr_c::Box::new(response))
}

/// Generate the public key for a private key
///
/// # Arguments
///
/// * `raw_private_key_ptr` - pointer to a private key byte array
///
/// Returns `NULL` when passed invalid arguments.
#[ffi_export]
pub fn private_key_public_key(
    raw_private_key: &[u8; PRIVATE_KEY_BYTES],
) -> Option<repr_c::Box<types::PrivateKeyPublicKeyResponse>> {
    let private_key = try_ffi!(PrivateKey::from_bytes(raw_private_key), None);

    let mut raw_public_key: [u8; PUBLIC_KEY_BYTES] = [0; PUBLIC_KEY_BYTES];
    private_key
        .public_key()
        .write_bytes(&mut raw_public_key.as_mut())
        .expect("preallocated");

    let response = types::PrivateKeyPublicKeyResponse {
        public_key: BLSPublicKey {
            inner: raw_public_key,
        },
    };

    Some(repr_c::Box::new(response))
}

/// Returns a zero signature, used as placeholder in Filecoin.
///
/// The return value is a pointer to a compressed signature in bytes, of length `SIGNATURE_BYTES`
#[ffi_export]
pub fn create_zero_signature() -> repr_c::Box<types::ZeroSignatureResponse> {
    let sig: Signature = G2Affine::identity().into();

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];

    sig.write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    let response = types::ZeroSignatureResponse {
        signature: BLSSignature {
            inner: raw_signature,
        },
    };

    repr_c::Box::new(response)
}

/// Frees the memory of the returned value of `create_zero_signature`.
#[ffi_export]
pub fn drop_signature(sig: repr_c::Box<types::ZeroSignatureResponse>) {
    drop(sig);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_verification() {
        let private_key = private_key_generate().private_key.inner;
        let public_key = private_key_public_key(&private_key)
            .unwrap()
            .public_key
            .inner;
        let message = b"hello world";
        let digest = hash(message[..].into()).digest.inner;
        let signature = private_key_sign(&private_key, message[..].into())
            .unwrap()
            .signature
            .inner;
        let verified = verify(&signature, digest[..].into(), public_key[..].into());

        assert_eq!(1, verified);

        let message_sizes = vec![message.len()];
        let flattened_messages = message;

        let verified = hash_verify(
            &signature,
            flattened_messages[..].into(),
            message_sizes[..].into(),
            public_key[..].into(),
        );

        assert_eq!(1, verified);

        let different_message = b"bye world";
        let different_digest = hash(different_message[..].into()).digest.inner;
        let not_verified = verify(
            &signature,
            different_digest[..].into(),
            public_key[..].into(),
        );

        assert_eq!(0, not_verified);

        // garbage verification
        let different_digest = vec![0, 1, 2, 3, 4];
        let not_verified = verify(
            &signature,
            different_digest[..].into(),
            public_key[..].into(),
        );

        assert_eq!(0, not_verified);
    }

    #[test]
    fn private_key_with_seed() {
        let seed = ByteArray32 { inner: [5u8; 32] };
        let private_key = private_key_generate_with_seed(seed).private_key.inner;
        assert_eq!(
            [
                56, 13, 181, 159, 37, 1, 12, 96, 45, 77, 254, 118, 103, 235, 218, 176, 220, 241,
                142, 119, 206, 233, 83, 35, 26, 15, 118, 198, 192, 120, 179, 52
            ],
            private_key,
        );
    }

    #[test]
    fn test_zero_key() {
        let resp = create_zero_signature();
        let sig = Signature::from_bytes(&(*resp).signature.inner).unwrap();

        assert_eq!(sig, Signature::from(G2Affine::identity()));

        types::destroy_zero_signature_response(resp);
    }
}
