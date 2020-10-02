/* filcrypto-v2 Header */

#ifdef __cplusplus
extern "C" {
#endif


#ifndef filcrypto_v2_H
#define filcrypto_v2_H

/* Generated with cbindgen:0.14.6 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum {
  FCPResponseStatus_FCPNoError = 0,
  FCPResponseStatus_FCPUnclassifiedError = 1,
  FCPResponseStatus_FCPCallerError = 2,
  FCPResponseStatus_FCPReceiverError = 3,
} FCPResponseStatus;

typedef enum {
  fil_RegisteredPoStProof_StackedDrgWinning2KiBV2,
  fil_RegisteredPoStProof_StackedDrgWinning8MiBV2,
  fil_RegisteredPoStProof_StackedDrgWinning512MiBV2,
  fil_RegisteredPoStProof_StackedDrgWinning32GiBV2,
  fil_RegisteredPoStProof_StackedDrgWinning64GiBV2,
  fil_RegisteredPoStProof_StackedDrgWindow2KiBV2,
  fil_RegisteredPoStProof_StackedDrgWindow8MiBV2,
  fil_RegisteredPoStProof_StackedDrgWindow512MiBV2,
  fil_RegisteredPoStProof_StackedDrgWindow32GiBV2,
  fil_RegisteredPoStProof_StackedDrgWindow64GiBV2,
} fil_RegisteredPoStProof;

typedef enum {
  fil_RegisteredSealProof_StackedDrg2KiBV2,
  fil_RegisteredSealProof_StackedDrg8MiBV2,
  fil_RegisteredSealProof_StackedDrg512MiBV2,
  fil_RegisteredSealProof_StackedDrg32GiBV2,
  fil_RegisteredSealProof_StackedDrg64GiBV2,
} fil_RegisteredSealProof;

typedef struct {
  const char *error_msg;
  FCPResponseStatus status_code;
} fil_ClearCacheResponse;

typedef struct {
  const char *error_msg;
  FCPResponseStatus status_code;
  uint8_t commitment[32];
} fil_FauxRepResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  uint8_t ticket[32];
} fil_FinalizeTicketResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  uint8_t comm_d[32];
} fil_GenerateDataCommitmentResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  uint8_t comm_p[32];
  /**
   * The number of unpadded bytes in the original piece plus any (unpadded)
   * alignment bytes added to create a whole merkle tree.
   */
  uint64_t num_bytes_aligned;
} fil_GeneratePieceCommitmentResponse;

typedef struct {
  fil_RegisteredPoStProof registered_proof;
  size_t proof_len;
  const uint8_t *proof_ptr;
} fil_PoStProof;

typedef struct {
  const char *error_msg;
  size_t proofs_len;
  const fil_PoStProof *proofs_ptr;
  size_t faulty_sectors_len;
  const uint64_t *faulty_sectors_ptr;
  FCPResponseStatus status_code;
} fil_GenerateWindowPoStResponse;

typedef struct {
  const char *error_msg;
  size_t proofs_len;
  const fil_PoStProof *proofs_ptr;
  FCPResponseStatus status_code;
} fil_GenerateWinningPoStResponse;

typedef struct {
  const char *error_msg;
  FCPResponseStatus status_code;
  const uint64_t *ids_ptr;
  size_t ids_len;
} fil_GenerateWinningPoStSectorChallenge;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  const uint8_t *seal_commit_phase1_output_ptr;
  size_t seal_commit_phase1_output_len;
} fil_SealCommitPhase1Response;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  const uint8_t *proof_ptr;
  size_t proof_len;
} fil_SealCommitPhase2Response;

typedef struct {
  const char *error_msg;
  FCPResponseStatus status_code;
  const uint8_t *seal_pre_commit_phase1_output_ptr;
  size_t seal_pre_commit_phase1_output_len;
} fil_SealPreCommitPhase1Response;

typedef struct {
  const char *error_msg;
  FCPResponseStatus status_code;
  fil_RegisteredSealProof registered_proof;
  uint8_t comm_d[32];
  uint8_t comm_r[32];
} fil_SealPreCommitPhase2Response;

/**
 *
 */
typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  const char *string_val;
} fil_StringResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
} fil_UnsealRangeResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  bool is_valid;
} fil_VerifySealResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  bool is_valid;
} fil_VerifyWindowPoStResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  bool is_valid;
} fil_VerifyWinningPoStResponse;

typedef struct {
  uint8_t comm_p[32];
  const char *error_msg;
  uint64_t left_alignment_unpadded;
  FCPResponseStatus status_code;
  uint64_t total_write_unpadded;
} fil_WriteWithAlignmentResponse;

typedef struct {
  uint8_t comm_p[32];
  const char *error_msg;
  FCPResponseStatus status_code;
  uint64_t total_write_unpadded;
} fil_WriteWithoutAlignmentResponse;

typedef struct {
  uint64_t num_bytes;
  uint8_t comm_p[32];
} fil_PublicPieceInfo;

typedef struct {
  fil_RegisteredPoStProof registered_proof;
  const char *cache_dir_path;
  uint8_t comm_r[32];
  const char *replica_path;
  uint64_t sector_id;
} fil_PrivateReplicaInfo;

typedef struct {
  fil_RegisteredPoStProof registered_proof;
  uint8_t comm_r[32];
  uint64_t sector_id;
} fil_PublicReplicaInfo;

fil_ClearCacheResponse *fil_clear_cache_v2(uint64_t sector_size, const char *cache_dir_path);

void fil_destroy_clear_cache_response_v2(fil_ClearCacheResponse *ptr);

void fil_destroy_fauxrep_response_v2(fil_FauxRepResponse *ptr);

void fil_destroy_finalize_ticket_response_v2(fil_FinalizeTicketResponse *ptr);

void fil_destroy_generate_data_commitment_response_v2(fil_GenerateDataCommitmentResponse *ptr);

void fil_destroy_generate_piece_commitment_response_v2(fil_GeneratePieceCommitmentResponse *ptr);

void fil_destroy_generate_window_post_response_v2(fil_GenerateWindowPoStResponse *ptr);

void fil_destroy_generate_winning_post_response_v2(fil_GenerateWinningPoStResponse *ptr);

void fil_destroy_generate_winning_post_sector_challenge_v2(fil_GenerateWinningPoStSectorChallenge *ptr);

void fil_destroy_seal_commit_phase1_response_v2(fil_SealCommitPhase1Response *ptr);

void fil_destroy_seal_commit_phase2_response_v2(fil_SealCommitPhase2Response *ptr);

void fil_destroy_seal_pre_commit_phase1_response_v2(fil_SealPreCommitPhase1Response *ptr);

void fil_destroy_seal_pre_commit_phase2_response_v2(fil_SealPreCommitPhase2Response *ptr);

void fil_destroy_string_response_v2(fil_StringResponse *ptr);

void fil_destroy_unseal_range_response_v2(fil_UnsealRangeResponse *ptr);

/**
 * Deallocates a VerifySealResponse.
 *
 */
void fil_destroy_verify_seal_response_v2(fil_VerifySealResponse *ptr);

void fil_destroy_verify_window_post_response_v2(fil_VerifyWindowPoStResponse *ptr);

/**
 * Deallocates a VerifyPoStResponse.
 *
 */
void fil_destroy_verify_winning_post_response_v2(fil_VerifyWinningPoStResponse *ptr);

void fil_destroy_write_with_alignment_response_v2(fil_WriteWithAlignmentResponse *ptr);

void fil_destroy_write_without_alignment_response_v2(fil_WriteWithoutAlignmentResponse *ptr);

fil_FauxRepResponse *fil_fauxrep2_v2(fil_RegisteredSealProof registered_proof,
                                     const char *cache_dir_path,
                                     const char *existing_p_aux_path);

fil_FauxRepResponse *fil_fauxrep_v2(fil_RegisteredSealProof registered_proof,
                                    const char *cache_dir_path,
                                    const char *sealed_sector_path);

/**
 * Returns the merkle root for a sector containing the provided pieces.
 */
fil_GenerateDataCommitmentResponse *fil_generate_data_commitment_v2(fil_RegisteredSealProof registered_proof,
                                                                    const fil_PublicPieceInfo *pieces_ptr,
                                                                    size_t pieces_len);

/**
 * Returns the merkle root for a piece after piece padding and alignment.
 * The caller is responsible for closing the passed in file descriptor.
 */
fil_GeneratePieceCommitmentResponse *fil_generate_piece_commitment_v2(fil_RegisteredSealProof registered_proof,
                                                                      int piece_fd_raw,
                                                                      uint64_t unpadded_piece_size);

/**
 * TODO: document
 *
 */
fil_GenerateWindowPoStResponse *fil_generate_window_post_v2(fil_32ByteArray randomness,
                                                            const fil_PrivateReplicaInfo *replicas_ptr,
                                                            size_t replicas_len,
                                                            fil_32ByteArray prover_id);

/**
 * TODO: document
 *
 */
fil_GenerateWinningPoStSectorChallenge *fil_generate_winning_post_sector_challenge_v2(fil_RegisteredPoStProof registered_proof,
                                                                                      fil_32ByteArray randomness,
                                                                                      uint64_t sector_set_len,
                                                                                      fil_32ByteArray prover_id);

/**
 * TODO: document
 *
 */
fil_GenerateWinningPoStResponse *fil_generate_winning_post_v2(fil_32ByteArray randomness,
                                                              const fil_PrivateReplicaInfo *replicas_ptr,
                                                              size_t replicas_len,
                                                              fil_32ByteArray prover_id);

/**
 * Returns the number of user bytes that will fit into a staged sector.
 *
 */
uint64_t fil_get_max_user_bytes_per_staged_sector_v2(fil_RegisteredSealProof registered_proof);

/**
 * Returns the identity of the circuit for the provided PoSt proof type.
 *
 */
fil_StringResponse *fil_get_post_circuit_identifier_v2(fil_RegisteredPoStProof registered_proof);

/**
 * Returns the CID of the Groth parameter file for generating a PoSt.
 *
 */
fil_StringResponse *fil_get_post_params_cid_v2(fil_RegisteredPoStProof registered_proof);

/**
 * Returns the path from which the proofs library expects to find the Groth
 * parameter file used when generating a PoSt.
 *
 */
fil_StringResponse *fil_get_post_params_path_v2(fil_RegisteredPoStProof registered_proof);

/**
 * Returns the CID of the verifying key-file for verifying a PoSt proof.
 *
 */
fil_StringResponse *fil_get_post_verifying_key_cid_v2(fil_RegisteredPoStProof registered_proof);

/**
 * Returns the path from which the proofs library expects to find the verifying
 * key-file used when verifying a PoSt proof.
 *
 */
fil_StringResponse *fil_get_post_verifying_key_path_v2(fil_RegisteredPoStProof registered_proof);

/**
 * Returns the version of the provided seal proof.
 *
 */
fil_StringResponse *fil_get_post_version_v2(fil_RegisteredPoStProof registered_proof);

/**
 * Returns the identity of the circuit for the provided seal proof.
 *
 */
fil_StringResponse *fil_get_seal_circuit_identifier_v2(fil_RegisteredSealProof registered_proof);

/**
 * Returns the CID of the Groth parameter file for sealing.
 *
 */
fil_StringResponse *fil_get_seal_params_cid_v2(fil_RegisteredSealProof registered_proof);

/**
 * Returns the path from which the proofs library expects to find the Groth
 * parameter file used when sealing.
 *
 */
fil_StringResponse *fil_get_seal_params_path_v2(fil_RegisteredSealProof registered_proof);

/**
 * Returns the CID of the verifying key-file for verifying a seal proof.
 *
 */
fil_StringResponse *fil_get_seal_verifying_key_cid_v2(fil_RegisteredSealProof registered_proof);

/**
 * Returns the path from which the proofs library expects to find the verifying
 * key-file used when verifying a seal proof.
 *
 */
fil_StringResponse *fil_get_seal_verifying_key_path_v2(fil_RegisteredSealProof registered_proof);

/**
 * Returns the version of the provided seal proof type.
 *
 */
fil_StringResponse *fil_get_seal_version_v2(fil_RegisteredSealProof registered_proof);

/**
 * TODO: document
 *
 */
fil_SealCommitPhase1Response *fil_seal_commit_phase1_v2(fil_RegisteredSealProof registered_proof,
                                                        fil_32ByteArray comm_r,
                                                        fil_32ByteArray comm_d,
                                                        const char *cache_dir_path,
                                                        const char *replica_path,
                                                        uint64_t sector_id,
                                                        fil_32ByteArray prover_id,
                                                        fil_32ByteArray ticket,
                                                        fil_32ByteArray seed,
                                                        const fil_PublicPieceInfo *pieces_ptr,
                                                        size_t pieces_len);

fil_SealCommitPhase2Response *fil_seal_commit_phase2_v2(const uint8_t *seal_commit_phase1_output_ptr,
                                                        size_t seal_commit_phase1_output_len,
                                                        uint64_t sector_id,
                                                        fil_32ByteArray prover_id);

/**
 * TODO: document
 *
 */
fil_SealPreCommitPhase1Response *fil_seal_pre_commit_phase1_v2(fil_RegisteredSealProof registered_proof,
                                                               const char *cache_dir_path,
                                                               const char *staged_sector_path,
                                                               const char *sealed_sector_path,
                                                               uint64_t sector_id,
                                                               fil_32ByteArray prover_id,
                                                               fil_32ByteArray ticket,
                                                               const fil_PublicPieceInfo *pieces_ptr,
                                                               size_t pieces_len);

/**
 * TODO: document
 *
 */
fil_SealPreCommitPhase2Response *fil_seal_pre_commit_phase2_v2(const uint8_t *seal_pre_commit_phase1_output_ptr,
                                                               size_t seal_pre_commit_phase1_output_len,
                                                               const char *cache_dir_path,
                                                               const char *sealed_sector_path);

/**
 * TODO: document
 */
fil_UnsealRangeResponse *fil_unseal_range_v2(fil_RegisteredSealProof registered_proof,
                                             const char *cache_dir_path,
                                             int sealed_sector_fd_raw,
                                             int unseal_output_fd_raw,
                                             uint64_t sector_id,
                                             fil_32ByteArray prover_id,
                                             fil_32ByteArray ticket,
                                             fil_32ByteArray comm_d,
                                             uint64_t unpadded_byte_index,
                                             uint64_t unpadded_bytes_amount);

/**
 * Verifies the output of seal.
 *
 */
fil_VerifySealResponse *fil_verify_seal_v2(fil_RegisteredSealProof registered_proof,
                                           fil_32ByteArray comm_r,
                                           fil_32ByteArray comm_d,
                                           fil_32ByteArray prover_id,
                                           fil_32ByteArray ticket,
                                           fil_32ByteArray seed,
                                           uint64_t sector_id,
                                           const uint8_t *proof_ptr,
                                           size_t proof_len);

/**
 * Verifies that a proof-of-spacetime is valid.
 */
fil_VerifyWindowPoStResponse *fil_verify_window_post_v2(fil_32ByteArray randomness,
                                                        const fil_PublicReplicaInfo *replicas_ptr,
                                                        size_t replicas_len,
                                                        const fil_PoStProof *proofs_ptr,
                                                        size_t proofs_len,
                                                        fil_32ByteArray prover_id);

/**
 * Verifies that a proof-of-spacetime is valid.
 */
fil_VerifyWinningPoStResponse *fil_verify_winning_post_v2(fil_32ByteArray randomness,
                                                          const fil_PublicReplicaInfo *replicas_ptr,
                                                          size_t replicas_len,
                                                          const fil_PoStProof *proofs_ptr,
                                                          size_t proofs_len,
                                                          fil_32ByteArray prover_id);

/**
 * TODO: document
 *
 */
fil_WriteWithAlignmentResponse *fil_write_with_alignment_v2(fil_RegisteredSealProof registered_proof,
                                                            int src_fd,
                                                            uint64_t src_size,
                                                            int dst_fd,
                                                            const uint64_t *existing_piece_sizes_ptr,
                                                            size_t existing_piece_sizes_len);

/**
 * TODO: document
 *
 */
fil_WriteWithoutAlignmentResponse *fil_write_without_alignment_v2(fil_RegisteredSealProof registered_proof,
                                                                  int src_fd,
                                                                  uint64_t src_size,
                                                                  int dst_fd);

#endif /* filcrypto_v2_H */

#ifdef __cplusplus
} /* extern "C" */
#endif
