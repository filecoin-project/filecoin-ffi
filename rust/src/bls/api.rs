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

pub const SIGNATURE_BYTES: usize = 96;
pub const PRIVATE_KEY_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 48;
pub const DIGEST_BYTES: usize = 96;

pub type BLSSignature = [u8; SIGNATURE_BYTES];
pub type BLSPrivateKey = [u8; PRIVATE_KEY_BYTES];
pub type BLSPublicKey = [u8; PUBLIC_KEY_BYTES];
pub type BLSDigest = [u8; DIGEST_BYTES];

/// Unwraps or returns the passed in value.
macro_rules! try_ffi {
    ($res:expr, $val:expr) => {{
        match $res {
            Ok(res) => res,
            Err(_) => return $val,
        }
    }};
}

#[ffi_export]
fn destroy_box_bls_digest(ptr: repr_c::Box<BLSDigest>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_box_bls_private_key(ptr: repr_c::Box<BLSPrivateKey>) {
    drop(ptr);
}

#[ffi_export]
fn destroy_box_bls_public_key(ptr: repr_c::Box<BLSPublicKey>) {
    drop(ptr);
}
#[ffi_export]
fn destroy_box_bls_signature(ptr: repr_c::Box<BLSSignature>) {
    drop(ptr);
}

/// Compute the digest of a message
///
/// # Arguments
///
/// * `message` - reference to a message byte array
#[ffi_export]
pub fn hash(message: c_slice::Ref<u8>) -> repr_c::Box<BLSDigest> {
    // call method
    let raw_digest = hash_sig(&message).to_bytes();
    let digest: [u8; DIGEST_BYTES] = raw_digest.as_ref().try_into().expect("known size");

    repr_c::Box::new(digest)
}

/// Aggregate signatures together into a new signature
///
/// # Arguments
///
/// * `flattened_signatures` - byte array containing signatures
///
/// Returns `None` on error. Result must be freed using `destroy_aggregate_response`.
#[ffi_export]
pub fn aggregate(flattened_signatures: c_slice::Ref<u8>) -> Option<repr_c::Box<BLSSignature>> {
    // prep request
    let signatures = try_ffi!(
        flattened_signatures
            .par_chunks(SIGNATURE_BYTES)
            .map(|item| { Signature::from_bytes(item) })
            .collect::<Result<Vec<_>, _>>(),
        None
    );

    let mut signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];

    let aggregated = try_ffi!(aggregate_sig(&signatures), None);
    aggregated
        .write_bytes(&mut signature.as_mut())
        .expect("preallocated");

    Some(repr_c::Box::new(signature))
}

/// Verify that a signature is the aggregated signature of hashes - pubkeys
///
/// # Arguments
///
/// * `signature`             - signature byte array (SIGNATURE_BYTES long)
/// * `flattened_digests`     - byte array containing digests
/// * `flattened_public_keys` - byte array containing public keys
#[ffi_export]
pub fn verify(
    signature: c_slice::Ref<u8>,
    flattened_digests: c_slice::Ref<u8>,
    flattened_public_keys: c_slice::Ref<u8>,
) -> bool {
    // prep request
    let signature = try_ffi!(Signature::from_bytes(&signature), false);

    if flattened_digests.len() % DIGEST_BYTES != 0 {
        return false;
    }
    if flattened_public_keys.len() % PUBLIC_KEY_BYTES != 0 {
        return false;
    }

    if flattened_digests.len() / DIGEST_BYTES != flattened_public_keys.len() / PUBLIC_KEY_BYTES {
        return false;
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
        false
    );

    let public_keys: Vec<_> = try_ffi!(
        flattened_public_keys
            .par_chunks(PUBLIC_KEY_BYTES)
            .map(|item| { PublicKey::from_bytes(item) })
            .collect::<Result<_, _>>(),
        false
    );

    verify_sig(&signature, digests.as_slice(), public_keys.as_slice())
}

/// Verify that a signature is the aggregated signature of the hashed messages
///
/// # Arguments
///
/// * `signature`             - signature byte array (SIGNATURE_BYTES long)
/// * `messages`              - array containing the pointers to the messages
/// * `messages_sizes`        - array containing the lengths of the messages
/// * `messages_len`          - length of the two messages arrays
/// * `flattened_public_keys` - byte array containing public keys
#[ffi_export]
pub fn hash_verify(
    signature: c_slice::Ref<u8>,
    flattened_messages: c_slice::Ref<u8>,
    message_sizes: c_slice::Ref<libc::size_t>,
    flattened_public_keys: c_slice::Ref<u8>,
) -> bool {
    // prep request
    let signature = try_ffi!(Signature::from_bytes(&signature), false);

    // split the flattened message array into slices of individual messages to be hashed
    let mut messages: Vec<&[u8]> = Vec::with_capacity(message_sizes.len());
    let mut offset = 0;
    for chunk_size in message_sizes.iter() {
        messages.push(&flattened_messages[offset..offset + *chunk_size]);
        offset += *chunk_size
    }

    if flattened_public_keys.len() % PUBLIC_KEY_BYTES != 0 {
        return false;
    }

    let public_keys: Vec<_> = try_ffi!(
        flattened_public_keys
            .par_chunks(PUBLIC_KEY_BYTES)
            .map(|item| { PublicKey::from_bytes(item) })
            .collect::<Result<_, _>>(),
        false
    );

    verify_messages_sig(&signature, &messages, &public_keys)
}

/// Generate a new private key
#[ffi_export]
pub fn private_key_generate() -> repr_c::Box<BLSPrivateKey> {
    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(&mut OsRng)
        .write_bytes(&mut raw_private_key.as_mut())
        .expect("preallocated");

    repr_c::Box::new(raw_private_key)
}

/// Generate a new private key with seed
///
/// **Warning**: Use this function only for testing or with very secure seeds
///
/// # Arguments
///
/// * `raw_seed` - a seed byte array with 32 bytes
#[ffi_export]
pub fn private_key_generate_with_seed(raw_seed: &[u8; 32]) -> repr_c::Box<BLSPrivateKey> {
    let rng = &mut ChaChaRng::from_seed(*raw_seed);

    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(rng)
        .write_bytes(&mut raw_private_key.as_mut())
        .expect("preallocated");

    repr_c::Box::new(raw_private_key)
}

/// Sign a message with a private key and return the signature
///
/// # Arguments
///
/// * `raw_private_key` - private key byte array
/// * `message` - message byte array
///
/// Returns `None` when passed invalid arguments.
#[ffi_export]
pub fn private_key_sign(
    raw_private_key: c_slice::Ref<u8>,
    message: c_slice::Ref<u8>,
) -> Option<repr_c::Box<BLSSignature>> {
    let private_key = try_ffi!(PrivateKey::from_bytes(&raw_private_key), None);

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
    PrivateKey::sign(&private_key, &message[..])
        .write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    Some(repr_c::Box::new(raw_signature))
}

/// Generate the public key for a private key
///
/// # Arguments
///
/// * `raw_private_key` - private key byte array
///
/// Returns `None` when passed invalid arguments.
#[ffi_export]
pub fn private_key_public_key(
    raw_private_key: c_slice::Ref<u8>,
) -> Option<repr_c::Box<BLSPublicKey>> {
    let private_key = try_ffi!(PrivateKey::from_bytes(&raw_private_key), None);

    let mut raw_public_key: [u8; PUBLIC_KEY_BYTES] = [0; PUBLIC_KEY_BYTES];
    private_key
        .public_key()
        .write_bytes(&mut raw_public_key.as_mut())
        .expect("preallocated");

    Some(repr_c::Box::new(raw_public_key))
}

/// Returns a zero signature, used as placeholder in Filecoin.
///
/// The return value is a pointer to a compressed signature in bytes, of length `SIGNATURE_BYTES`
#[ffi_export]
pub fn create_zero_signature() -> repr_c::Box<BLSSignature> {
    let sig: Signature = G2Affine::identity().into();

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];

    sig.write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    repr_c::Box::new(raw_signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_verification() {
        let private_key = private_key_generate();
        let public_key = private_key_public_key(private_key[..].into()).unwrap();
        let message = b"hello world";
        let digest = hash(message[..].into());
        let signature = private_key_sign(private_key[..].into(), message[..].into()).unwrap();
        let verified = verify(
            signature[..].into(),
            digest[..].into(),
            public_key[..].into(),
        );

        assert!(verified);

        let message_sizes = vec![message.len()];
        let flattened_messages = message;

        let verified = hash_verify(
            signature[..].into(),
            flattened_messages[..].into(),
            message_sizes[..].into(),
            public_key[..].into(),
        );

        assert!(verified);

        let different_message = b"bye world";
        let different_digest = hash(different_message[..].into());
        let not_verified = verify(
            signature[..].into(),
            different_digest[..].into(),
            public_key[..].into(),
        );

        assert!(!not_verified);

        // garbage verification
        let different_digest = vec![0, 1, 2, 3, 4];
        let not_verified = verify(
            signature[..].into(),
            different_digest[..].into(),
            public_key[..].into(),
        );

        assert!(!not_verified);
    }

    #[test]
    fn private_key_with_seed() {
        let seed = [5u8; 32];
        let private_key = private_key_generate_with_seed(&seed);
        assert_eq!(
            &[
                56, 13, 181, 159, 37, 1, 12, 96, 45, 77, 254, 118, 103, 235, 218, 176, 220, 241,
                142, 119, 206, 233, 83, 35, 26, 15, 118, 198, 192, 120, 179, 52
            ],
            &private_key[..],
        );
    }

    #[test]
    fn test_zero_key() {
        let resp = create_zero_signature();
        let sig = Signature::from_bytes(&(*resp)).unwrap();

        assert_eq!(sig, Signature::from(G2Affine::identity()));
    }
}
