/* ffi_common Header */

#ifdef __cplusplus
extern "C" {
#endif


#ifndef ffi_common_H
#define ffi_common_H

/* Generated with cbindgen:0.14.6 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define DIGEST_BYTES 96

#define PRIVATE_KEY_BYTES 32

#define PUBLIC_KEY_BYTES 48

#define SIGNATURE_BYTES 96

typedef enum {
  FCPResponseStatus_FCPNoError = 0,
  FCPResponseStatus_FCPUnclassifiedError = 1,
  FCPResponseStatus_FCPCallerError = 2,
  FCPResponseStatus_FCPReceiverError = 3,
} FCPResponseStatus;

typedef struct {
  uint8_t inner[SIGNATURE_BYTES];
} fil_BLSSignature;

/**
 * AggregateResponse
 */
typedef struct {
  fil_BLSSignature signature;
} fil_AggregateResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  size_t devices_len;
  const char *const *devices_ptr;
} fil_GpuDeviceResponse;

typedef struct {
  uint8_t inner[DIGEST_BYTES];
} fil_BLSDigest;

/**
 * HashResponse
 */
typedef struct {
  fil_BLSDigest digest;
} fil_HashResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
} fil_InitLogFdResponse;

typedef struct {
  uint8_t inner[PRIVATE_KEY_BYTES];
} fil_BLSPrivateKey;

/**
 * PrivateKeyGenerateResponse
 */
typedef struct {
  fil_BLSPrivateKey private_key;
} fil_PrivateKeyGenerateResponse;

typedef struct {
  uint8_t inner[PUBLIC_KEY_BYTES];
} fil_BLSPublicKey;

/**
 * PrivateKeyPublicKeyResponse
 */
typedef struct {
  fil_BLSPublicKey public_key;
} fil_PrivateKeyPublicKeyResponse;

/**
 * PrivateKeySignResponse
 */
typedef struct {
  fil_BLSSignature signature;
} fil_PrivateKeySignResponse;

typedef struct {
  uint8_t inner[32];
} fil_32ByteArray;

/**
 * Aggregate signatures together into a new signature
 *
 * # Arguments
 *
 * * `flattened_signatures_ptr` - pointer to a byte array containing signatures
 * * `flattened_signatures_len` - length of the byte array (multiple of SIGNATURE_BYTES)
 *
 * Returns `NULL` on error. Result must be freed using `destroy_aggregate_response`.
 */
fil_AggregateResponse *fil_aggregate(const uint8_t *flattened_signatures_ptr,
                                     size_t flattened_signatures_len);

void fil_destroy_aggregate_response_v2(fil_AggregateResponse *ptr);

void fil_destroy_gpu_device_response(fil_GpuDeviceResponse *ptr);

void fil_destroy_hash_response_v2(fil_HashResponse *ptr);

void fil_destroy_init_log_fd_response(fil_InitLogFdResponse *ptr);

void fil_destroy_private_key_generate_response_v2(fil_PrivateKeyGenerateResponse *ptr);

void fil_destroy_private_key_public_key_response_v2(fil_PrivateKeyPublicKeyResponse *ptr);

void fil_destroy_private_key_sign_response_v2(fil_PrivateKeySignResponse *ptr);

/**
 * Returns an array of strings containing the device names that can be used.
 */
fil_GpuDeviceResponse *fil_get_gpu_devices(void);

/**
 * Compute the digest of a message
 *
 * # Arguments
 *
 * * `message_ptr` - pointer to a message byte array
 * * `message_len` - length of the byte array
 */
fil_HashResponse *fil_hash(const uint8_t *message_ptr, size_t message_len);

/**
 * Verify that a signature is the aggregated signature of the hhashed messages
 *
 * # Arguments
 *
 * * `signature_ptr`             - pointer to a signature byte array (SIGNATURE_BYTES long)
 * * `messages_ptr`              - pointer to an array containing the pointers to the messages
 * * `messages_sizes_ptr`        - pointer to an array containing the lengths of the messages
 * * `messages_len`              - length of the two messages arrays
 * * `flattened_public_keys_ptr` - pointer to a byte array containing public keys
 * * `flattened_public_keys_len` - length of the array
 */
int fil_hash_verify(const uint8_t *signature_ptr,
                    const uint8_t *flattened_messages_ptr,
                    size_t flattened_messages_len,
                    const size_t *message_sizes_ptr,
                    size_t message_sizes_len,
                    const uint8_t *flattened_public_keys_ptr,
                    size_t flattened_public_keys_len);

/**
 * Initializes the logger with a file descriptor where logs will be logged into.
 *
 * This is usually a pipe that was opened on the receiving side of the logs. The logger is
 * initialized on the invocation, subsequent calls won't have any effect.
 *
 * This function must be called right at the start, before any other call. Else the logger will
 * be initializes implicitely and log to stderr.
 */
fil_InitLogFdResponse *fil_init_log_fd(int log_fd);

/**
 * Generate a new private key
 */
fil_PrivateKeyGenerateResponse *fil_private_key_generate(void);

/**
 * Generate a new private key with seed
 *
 * **Warning**: Use this function only for testing or with very secure seeds
 *
 * # Arguments
 *
 * * `raw_seed` - a seed byte array with 32 bytes
 *
 * Returns `NULL` when passed a NULL pointer.
 */
fil_PrivateKeyGenerateResponse *fil_private_key_generate_with_seed(fil_32ByteArray raw_seed);

/**
 * Generate the public key for a private key
 *
 * # Arguments
 *
 * * `raw_private_key_ptr` - pointer to a private key byte array
 *
 * Returns `NULL` when passed invalid arguments.
 */
fil_PrivateKeyPublicKeyResponse *fil_private_key_public_key(const uint8_t *raw_private_key_ptr);

/**
 * Sign a message with a private key and return the signature
 *
 * # Arguments
 *
 * * `raw_private_key_ptr` - pointer to a private key byte array
 * * `message_ptr` - pointer to a message byte array
 * * `message_len` - length of the byte array
 *
 * Returns `NULL` when passed invalid arguments.
 */
fil_PrivateKeySignResponse *fil_private_key_sign(const uint8_t *raw_private_key_ptr,
                                                 const uint8_t *message_ptr,
                                                 size_t message_len);

/**
 * Verify that a signature is the aggregated signature of hashes - pubkeys
 *
 * # Arguments
 *
 * * `signature_ptr`             - pointer to a signature byte array (SIGNATURE_BYTES long)
 * * `flattened_digests_ptr`     - pointer to a byte array containing digests
 * * `flattened_digests_len`     - length of the byte array (multiple of DIGEST_BYTES)
 * * `flattened_public_keys_ptr` - pointer to a byte array containing public keys
 * * `flattened_public_keys_len` - length of the array
 */
int fil_verify(const uint8_t *signature_ptr,
               const uint8_t *flattened_digests_ptr,
               size_t flattened_digests_len,
               const uint8_t *flattened_public_keys_ptr,
               size_t flattened_public_keys_len);

#endif /* ffi_common_H */

#ifdef __cplusplus
} /* extern "C" */
#endif
