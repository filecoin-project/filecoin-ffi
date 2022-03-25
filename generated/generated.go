package generated

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

func AsSliceRefUint8(goBytes []byte) SliceRefUint8 {
	len := len(goBytes)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefUint8{
			ptr: (*C.uint8_t)(unsafe.Pointer(&goBytes)),
			len: C.size_t(len),
		}
	}
	return SliceRefUint8{
		ptr: (*C.uint8_t)(unsafe.Pointer(&goBytes[0])),
		len: C.size_t(len),
	}
}

func AsSliceRefUint(goSlice []uint) SliceRefUint {
	len := len(goSlice)

	if len == 0 {
		// can't take element 0 of an empty slice
		return SliceRefUint{
			ptr: (*C.size_t)(unsafe.Pointer(&goSlice)),
			len: C.size_t(len),
		}
	}

	return SliceRefUint{
		ptr: (*C.size_t)(unsafe.Pointer(&goSlice[0])),
		len: C.size_t(len),
	}
}

func AsByteArray32(goSlice []byte) ByteArray32 {
	var ary ByteArray32
	for idx := range goSlice[:32] {
		ary.inner.idx[idx] = C.uchar(goSlice[idx])
	}
	return ary
}

func Hash(message SliceRefUint8) *HashResponse {
	return C.hash(message)
}

func (ptr *HashResponse) Destroy() {
	C.destroy_hash_response(ptr)
}

// // DestroyGpuDeviceResponse function as declared in filecoin-ffi/filcrypto.h:108
// func DestroyGpuDeviceResponse(ptr *ResultSliceBoxedSliceBoxedUint8T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_gpu_device_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyInitLogFdResponse function as declared in filecoin-ffi/filcrypto.h:119
// func DestroyInitLogFdResponse(ptr *ResultVoidT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_init_log_fd_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// Aggregate function as declared in filecoin-ffi/filcrypto.h:200
func Aggregate(flattenedSignatures SliceRefUint8) *AggregateResponse {
	return C.aggregate(flattenedSignatures)
}

func (ptr *AggregateResponse) Destroy() {
	C.destroy_aggregate_response(ptr)
}

// Verify function as declared in filecoin-ffi/filcrypto.h:212
func Verify(signature SliceRefUint8, flattenedDigests SliceRefUint8, flattenedPublicKeys SliceRefUint8) C.int32_t {
	return C.verify(signature, flattenedDigests, flattenedPublicKeys)
}

// HashVerify function as declared in filecoin-ffi/filcrypto.h:256
func HashVerify(signature SliceRefUint8, flattenedMessages SliceRefUint8, messageSizes SliceRefUint, flattenedPublicKeys SliceRefUint8) C.int32_t {
	return C.hash_verify(signature, flattenedMessages, messageSizes, flattenedPublicKeys)
}

func PrivateKeyGenerate() *PrivateKeyGenerateResponse {
	return C.private_key_generate()
}

func PrivateKeyGenerateWithSeed(rawSeed ByteArray32) *PrivateKeyGenerateResponse {
	return C.private_key_generate_with_seed(rawSeed)
}

func PrivateKeySign(rawPrivateKey SliceRefUint8, message SliceRefUint8) *PrivateKeySignResponse {
	return C.private_key_sign(rawPrivateKey, message)
}

func (ptr *PrivateKeySignResponse) Destroy() {
	C.destroy_private_key_sign_response(ptr)
}

func PrivateKeyPublicKey(rawPrivateKey SliceRefUint8) *PrivateKeyPublicKeyResponse {
	return C.private_key_public_key(rawPrivateKey)
}

func (ptr *PrivateKeyPublicKeyResponse) Destroy() {
	C.destroy_private_key_public_key_response(ptr)
}

func CreateZeroSignature() *ZeroSignatureResponse {
	return C.create_zero_signature()
}

func (ptr *ZeroSignatureResponse) Destroy() {
	C.drop_signature(ptr)
}

// // GetGpuDevices function as declared in filecoin-ffi/filcrypto.h:381
// func GetGpuDevices() *ResultSliceBoxedSliceBoxedUint8T {
// 	__ret := C.get_gpu_devices()
// 	__v := NewResultSliceBoxedSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // InitLogFd function as declared in filecoin-ffi/filcrypto.h:392
// func InitLogFd(logFd Int32T) *ResultVoidT {
// 	clogFd, clogFdAllocMap := (C.int32_t)(logFd), cgoAllocsUnknown
// 	__ret := C.init_log_fd(clogFd)
// 	runtime.KeepAlive(clogFdAllocMap)
// 	__v := NewResultVoidTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // WriteWithAlignment function as declared in filecoin-ffi/filcrypto.h:478
// func WriteWithAlignment(registeredProof RegisteredSealProofT, srcFd Int32T, srcSize Uint64T, dstFd Int32T, existingPieceSizes SliceRefUint64T) *ResultWriteWithAlignmentT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	csrcFd, csrcFdAllocMap := (C.int32_t)(srcFd), cgoAllocsUnknown
// 	csrcSize, csrcSizeAllocMap := (C.uint64_t)(srcSize), cgoAllocsUnknown
// 	cdstFd, cdstFdAllocMap := (C.int32_t)(dstFd), cgoAllocsUnknown
// 	cexistingPieceSizes, cexistingPieceSizesAllocMap := existingPieceSizes.PassValue()
// 	__ret := C.write_with_alignment(cregisteredProof, csrcFd, csrcSize, cdstFd, cexistingPieceSizes)
// 	runtime.KeepAlive(cexistingPieceSizesAllocMap)
// 	runtime.KeepAlive(cdstFdAllocMap)
// 	runtime.KeepAlive(csrcSizeAllocMap)
// 	runtime.KeepAlive(csrcFdAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultWriteWithAlignmentTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // WriteWithoutAlignment function as declared in filecoin-ffi/filcrypto.h:506
// func WriteWithoutAlignment(registeredProof RegisteredSealProofT, srcFd Int32T, srcSize Uint64T, dstFd Int32T) *ResultWriteWithoutAlignmentT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	csrcFd, csrcFdAllocMap := (C.int32_t)(srcFd), cgoAllocsUnknown
// 	csrcSize, csrcSizeAllocMap := (C.uint64_t)(srcSize), cgoAllocsUnknown
// 	cdstFd, cdstFdAllocMap := (C.int32_t)(dstFd), cgoAllocsUnknown
// 	__ret := C.write_without_alignment(cregisteredProof, csrcFd, csrcSize, cdstFd)
// 	runtime.KeepAlive(cdstFdAllocMap)
// 	runtime.KeepAlive(csrcSizeAllocMap)
// 	runtime.KeepAlive(csrcFdAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultWriteWithoutAlignmentTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // Fauxrep function as declared in filecoin-ffi/filcrypto.h:522
// func Fauxrep(registeredProof RegisteredSealProofT, cacheDirPath SliceRefUint8T, sealedSectorPath SliceRefUint8T) *ResultByteArray32T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	ccacheDirPath, ccacheDirPathAllocMap := cacheDirPath.PassValue()
// 	csealedSectorPath, csealedSectorPathAllocMap := sealedSectorPath.PassValue()
// 	__ret := C.fauxrep(cregisteredProof, ccacheDirPath, csealedSectorPath)
// 	runtime.KeepAlive(csealedSectorPathAllocMap)
// 	runtime.KeepAlive(ccacheDirPathAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultByteArray32TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // Fauxrep2 function as declared in filecoin-ffi/filcrypto.h:527
// func Fauxrep2(registeredProof RegisteredSealProofT, cacheDirPath SliceRefUint8T, existingPAuxPath SliceRefUint8T) *ResultByteArray32T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	ccacheDirPath, ccacheDirPathAllocMap := cacheDirPath.PassValue()
// 	cexistingPAuxPath, cexistingPAuxPathAllocMap := existingPAuxPath.PassValue()
// 	__ret := C.fauxrep2(cregisteredProof, ccacheDirPath, cexistingPAuxPath)
// 	runtime.KeepAlive(cexistingPAuxPathAllocMap)
// 	runtime.KeepAlive(ccacheDirPathAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultByteArray32TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // SealPreCommitPhase1 function as declared in filecoin-ffi/filcrypto.h:580
// func SealPreCommitPhase1(registeredProof RegisteredSealProofT, cacheDirPath SliceRefUint8T, stagedSectorPath SliceRefUint8T, sealedSectorPath SliceRefUint8T, sectorId Uint64T, proverId ByteArray32T, ticket ByteArray32T, pieces SliceRefPublicPieceInfoT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	ccacheDirPath, ccacheDirPathAllocMap := cacheDirPath.PassValue()
// 	cstagedSectorPath, cstagedSectorPathAllocMap := stagedSectorPath.PassValue()
// 	csealedSectorPath, csealedSectorPathAllocMap := sealedSectorPath.PassValue()
// 	csectorId, csectorIdAllocMap := (C.uint64_t)(sectorId), cgoAllocsUnknown
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	cticket, cticketAllocMap := ticket.PassValue()
// 	cpieces, cpiecesAllocMap := pieces.PassValue()
// 	__ret := C.seal_pre_commit_phase1(cregisteredProof, ccacheDirPath, cstagedSectorPath, csealedSectorPath, csectorId, cproverId, cticket, cpieces)
// 	runtime.KeepAlive(cpiecesAllocMap)
// 	runtime.KeepAlive(cticketAllocMap)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(csectorIdAllocMap)
// 	runtime.KeepAlive(csealedSectorPathAllocMap)
// 	runtime.KeepAlive(cstagedSectorPathAllocMap)
// 	runtime.KeepAlive(ccacheDirPathAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // SealPreCommitPhase2 function as declared in filecoin-ffi/filcrypto.h:613
// func SealPreCommitPhase2(sealPreCommitPhase1Output SliceRefUint8T, cacheDirPath SliceRefUint8T, sealedSectorPath SliceRefUint8T) *ResultSealPreCommitPhase2T {
// 	csealPreCommitPhase1Output, csealPreCommitPhase1OutputAllocMap := sealPreCommitPhase1Output.PassValue()
// 	ccacheDirPath, ccacheDirPathAllocMap := cacheDirPath.PassValue()
// 	csealedSectorPath, csealedSectorPathAllocMap := sealedSectorPath.PassValue()
// 	__ret := C.seal_pre_commit_phase2(csealPreCommitPhase1Output, ccacheDirPath, csealedSectorPath)
// 	runtime.KeepAlive(csealedSectorPathAllocMap)
// 	runtime.KeepAlive(ccacheDirPathAllocMap)
// 	runtime.KeepAlive(csealPreCommitPhase1OutputAllocMap)
// 	__v := NewResultSealPreCommitPhase2TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // SealCommitPhase1 function as declared in filecoin-ffi/filcrypto.h:621
// func SealCommitPhase1(registeredProof RegisteredSealProofT, commR ByteArray32T, commD ByteArray32T, cacheDirPath SliceRefUint8T, replicaPath SliceRefUint8T, sectorId Uint64T, proverId ByteArray32T, ticket ByteArray32T, seed ByteArray32T, pieces SliceRefPublicPieceInfoT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	ccommR, ccommRAllocMap := commR.PassValue()
// 	ccommD, ccommDAllocMap := commD.PassValue()
// 	ccacheDirPath, ccacheDirPathAllocMap := cacheDirPath.PassValue()
// 	creplicaPath, creplicaPathAllocMap := replicaPath.PassValue()
// 	csectorId, csectorIdAllocMap := (C.uint64_t)(sectorId), cgoAllocsUnknown
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	cticket, cticketAllocMap := ticket.PassValue()
// 	cseed, cseedAllocMap := seed.PassValue()
// 	cpieces, cpiecesAllocMap := pieces.PassValue()
// 	__ret := C.seal_commit_phase1(cregisteredProof, ccommR, ccommD, ccacheDirPath, creplicaPath, csectorId, cproverId, cticket, cseed, cpieces)
// 	runtime.KeepAlive(cpiecesAllocMap)
// 	runtime.KeepAlive(cseedAllocMap)
// 	runtime.KeepAlive(cticketAllocMap)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(csectorIdAllocMap)
// 	runtime.KeepAlive(creplicaPathAllocMap)
// 	runtime.KeepAlive(ccacheDirPathAllocMap)
// 	runtime.KeepAlive(ccommDAllocMap)
// 	runtime.KeepAlive(ccommRAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // SealCommitPhase2 function as declared in filecoin-ffi/filcrypto.h:649
// func SealCommitPhase2(sealCommitPhase1Output SliceRefUint8T, sectorId Uint64T, proverId ByteArray32T) *ResultSealCommitPhase2T {
// 	csealCommitPhase1Output, csealCommitPhase1OutputAllocMap := sealCommitPhase1Output.PassValue()
// 	csectorId, csectorIdAllocMap := (C.uint64_t)(sectorId), cgoAllocsUnknown
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	__ret := C.seal_commit_phase2(csealCommitPhase1Output, csectorId, cproverId)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(csectorIdAllocMap)
// 	runtime.KeepAlive(csealCommitPhase1OutputAllocMap)
// 	__v := NewResultSealCommitPhase2TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // AggregateSealProofs function as declared in filecoin-ffi/filcrypto.h:724
// func AggregateSealProofs(registeredProof RegisteredSealProofT, registeredAggregation RegisteredAggregationProofT, commRs SliceBoxedByteArray32T, seeds SliceBoxedByteArray32T, sealCommitResponses SliceRefSealCommitPhase2T) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	cregisteredAggregation, cregisteredAggregationAllocMap := (C.RegisteredAggregationProof_t)(registeredAggregation), cgoAllocsUnknown
// 	ccommRs, ccommRsAllocMap := commRs.PassValue()
// 	cseeds, cseedsAllocMap := seeds.PassValue()
// 	csealCommitResponses, csealCommitResponsesAllocMap := sealCommitResponses.PassValue()
// 	__ret := C.aggregate_seal_proofs(cregisteredProof, cregisteredAggregation, ccommRs, cseeds, csealCommitResponses)
// 	runtime.KeepAlive(csealCommitResponsesAllocMap)
// 	runtime.KeepAlive(cseedsAllocMap)
// 	runtime.KeepAlive(ccommRsAllocMap)
// 	runtime.KeepAlive(cregisteredAggregationAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // VerifyAggregateSealProof function as declared in filecoin-ffi/filcrypto.h:788
// func VerifyAggregateSealProof(registeredProof RegisteredSealProofT, registeredAggregation RegisteredAggregationProofT, proverId ByteArray32T, proof SliceRefUint8T, commitInputs SliceRefAggregationInputsT) *ResultBoolT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	cregisteredAggregation, cregisteredAggregationAllocMap := (C.RegisteredAggregationProof_t)(registeredAggregation), cgoAllocsUnknown
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	cproof, cproofAllocMap := proof.PassValue()
// 	ccommitInputs, ccommitInputsAllocMap := commitInputs.PassValue()
// 	__ret := C.verify_aggregate_seal_proof(cregisteredProof, cregisteredAggregation, cproverId, cproof, ccommitInputs)
// 	runtime.KeepAlive(ccommitInputsAllocMap)
// 	runtime.KeepAlive(cproofAllocMap)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(cregisteredAggregationAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultBoolTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // UnsealRange function as declared in filecoin-ffi/filcrypto.h:798
// func UnsealRange(registeredProof RegisteredSealProofT, cacheDirPath SliceRefUint8T, sealedSectorFdRaw Int32T, unsealOutputFdRaw Int32T, sectorId Uint64T, proverId ByteArray32T, ticket ByteArray32T, commD ByteArray32T, unpaddedByteIndex Uint64T, unpaddedBytesAmount Uint64T) *ResultVoidT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	ccacheDirPath, ccacheDirPathAllocMap := cacheDirPath.PassValue()
// 	csealedSectorFdRaw, csealedSectorFdRawAllocMap := (C.int32_t)(sealedSectorFdRaw), cgoAllocsUnknown
// 	cunsealOutputFdRaw, cunsealOutputFdRawAllocMap := (C.int32_t)(unsealOutputFdRaw), cgoAllocsUnknown
// 	csectorId, csectorIdAllocMap := (C.uint64_t)(sectorId), cgoAllocsUnknown
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	cticket, cticketAllocMap := ticket.PassValue()
// 	ccommD, ccommDAllocMap := commD.PassValue()
// 	cunpaddedByteIndex, cunpaddedByteIndexAllocMap := (C.uint64_t)(unpaddedByteIndex), cgoAllocsUnknown
// 	cunpaddedBytesAmount, cunpaddedBytesAmountAllocMap := (C.uint64_t)(unpaddedBytesAmount), cgoAllocsUnknown
// 	__ret := C.unseal_range(cregisteredProof, ccacheDirPath, csealedSectorFdRaw, cunsealOutputFdRaw, csectorId, cproverId, cticket, ccommD, cunpaddedByteIndex, cunpaddedBytesAmount)
// 	runtime.KeepAlive(cunpaddedBytesAmountAllocMap)
// 	runtime.KeepAlive(cunpaddedByteIndexAllocMap)
// 	runtime.KeepAlive(ccommDAllocMap)
// 	runtime.KeepAlive(cticketAllocMap)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(csectorIdAllocMap)
// 	runtime.KeepAlive(cunsealOutputFdRawAllocMap)
// 	runtime.KeepAlive(csealedSectorFdRawAllocMap)
// 	runtime.KeepAlive(ccacheDirPathAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultVoidTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // VerifySeal function as declared in filecoin-ffi/filcrypto.h:813
// func VerifySeal(registeredProof RegisteredSealProofT, commR ByteArray32T, commD ByteArray32T, proverId ByteArray32T, ticket ByteArray32T, seed ByteArray32T, sectorId Uint64T, proof SliceRefUint8T) *ResultBoolT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	ccommR, ccommRAllocMap := commR.PassValue()
// 	ccommD, ccommDAllocMap := commD.PassValue()
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	cticket, cticketAllocMap := ticket.PassValue()
// 	cseed, cseedAllocMap := seed.PassValue()
// 	csectorId, csectorIdAllocMap := (C.uint64_t)(sectorId), cgoAllocsUnknown
// 	cproof, cproofAllocMap := proof.PassValue()
// 	__ret := C.verify_seal(cregisteredProof, ccommR, ccommD, cproverId, cticket, cseed, csectorId, cproof)
// 	runtime.KeepAlive(cproofAllocMap)
// 	runtime.KeepAlive(csectorIdAllocMap)
// 	runtime.KeepAlive(cseedAllocMap)
// 	runtime.KeepAlive(cticketAllocMap)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(ccommDAllocMap)
// 	runtime.KeepAlive(ccommRAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultBoolTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateWinningPostSectorChallenge function as declared in filecoin-ffi/filcrypto.h:897
// func GenerateWinningPostSectorChallenge(registeredProof RegisteredPoStProofT, randomness ByteArray32T, sectorSetLen Uint64T, proverId ByteArray32T) *ResultSliceBoxedUint64T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	crandomness, crandomnessAllocMap := randomness.PassValue()
// 	csectorSetLen, csectorSetLenAllocMap := (C.uint64_t)(sectorSetLen), cgoAllocsUnknown
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	__ret := C.generate_winning_post_sector_challenge(cregisteredProof, crandomness, csectorSetLen, cproverId)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(csectorSetLenAllocMap)
// 	runtime.KeepAlive(crandomnessAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint64TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateFallbackSectorChallenges function as declared in filecoin-ffi/filcrypto.h:926
// func GenerateFallbackSectorChallenges(registeredProof RegisteredPoStProofT, randomness ByteArray32T, sectorIds SliceRefUint64T, proverId ByteArray32T) *ResultGenerateFallbackSectorChallengesT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	crandomness, crandomnessAllocMap := randomness.PassValue()
// 	csectorIds, csectorIdsAllocMap := sectorIds.PassValue()
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	__ret := C.generate_fallback_sector_challenges(cregisteredProof, crandomness, csectorIds, cproverId)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(csectorIdsAllocMap)
// 	runtime.KeepAlive(crandomnessAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultGenerateFallbackSectorChallengesTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateSingleVanillaProof function as declared in filecoin-ffi/filcrypto.h:949
// func GenerateSingleVanillaProof(replica PrivateReplicaInfoT, challenges SliceRefUint64T) *ResultSliceBoxedUint8T {
// 	creplica, creplicaAllocMap := replica.PassValue()
// 	cchallenges, cchallengesAllocMap := challenges.PassValue()
// 	__ret := C.generate_single_vanilla_proof(creplica, cchallenges)
// 	runtime.KeepAlive(cchallengesAllocMap)
// 	runtime.KeepAlive(creplicaAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateWinningPostWithVanilla function as declared in filecoin-ffi/filcrypto.h:1029
// func GenerateWinningPostWithVanilla(registeredProof RegisteredPoStProofT, randomness ByteArray32T, proverId ByteArray32T, vanillaProofs SliceRefSliceBoxedUint8T) *ResultSliceBoxedPoStProofT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	crandomness, crandomnessAllocMap := randomness.PassValue()
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	cvanillaProofs, cvanillaProofsAllocMap := vanillaProofs.PassValue()
// 	__ret := C.generate_winning_post_with_vanilla(cregisteredProof, crandomness, cproverId, cvanillaProofs)
// 	runtime.KeepAlive(cvanillaProofsAllocMap)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(crandomnessAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedPoStProofTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateWinningPost function as declared in filecoin-ffi/filcrypto.h:1065
// func GenerateWinningPost(randomness ByteArray32T, replicas SliceRefPrivateReplicaInfoT, proverId ByteArray32T) *ResultSliceBoxedPoStProofT {
// 	crandomness, crandomnessAllocMap := randomness.PassValue()
// 	creplicas, creplicasAllocMap := replicas.PassValue()
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	__ret := C.generate_winning_post(crandomness, creplicas, cproverId)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(creplicasAllocMap)
// 	runtime.KeepAlive(crandomnessAllocMap)
// 	__v := NewResultSliceBoxedPoStProofTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // VerifyWinningPost function as declared in filecoin-ffi/filcrypto.h:1137
// func VerifyWinningPost(randomness ByteArray32T, replicas SliceRefPublicReplicaInfoT, proofs SliceRefPoStProofT, proverId ByteArray32T) *ResultBoolT {
// 	crandomness, crandomnessAllocMap := randomness.PassValue()
// 	creplicas, creplicasAllocMap := replicas.PassValue()
// 	cproofs, cproofsAllocMap := proofs.PassValue()
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	__ret := C.verify_winning_post(crandomness, creplicas, cproofs, cproverId)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(cproofsAllocMap)
// 	runtime.KeepAlive(creplicasAllocMap)
// 	runtime.KeepAlive(crandomnessAllocMap)
// 	__v := NewResultBoolTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateWindowPostWithVanilla function as declared in filecoin-ffi/filcrypto.h:1164
// func GenerateWindowPostWithVanilla(registeredProof RegisteredPoStProofT, randomness ByteArray32T, proverId ByteArray32T, vanillaProofs SliceRefSliceBoxedUint8T) *ResultGenerateWindowPoStT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	crandomness, crandomnessAllocMap := randomness.PassValue()
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	cvanillaProofs, cvanillaProofsAllocMap := vanillaProofs.PassValue()
// 	__ret := C.generate_window_post_with_vanilla(cregisteredProof, crandomness, cproverId, cvanillaProofs)
// 	runtime.KeepAlive(cvanillaProofsAllocMap)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(crandomnessAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultGenerateWindowPoStTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateWindowPost function as declared in filecoin-ffi/filcrypto.h:1173
// func GenerateWindowPost(randomness ByteArray32T, replicas SliceRefPrivateReplicaInfoT, proverId ByteArray32T) *ResultGenerateWindowPoStT {
// 	crandomness, crandomnessAllocMap := randomness.PassValue()
// 	creplicas, creplicasAllocMap := replicas.PassValue()
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	__ret := C.generate_window_post(crandomness, creplicas, cproverId)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(creplicasAllocMap)
// 	runtime.KeepAlive(crandomnessAllocMap)
// 	__v := NewResultGenerateWindowPoStTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // VerifyWindowPost function as declared in filecoin-ffi/filcrypto.h:1181
// func VerifyWindowPost(randomness ByteArray32T, replicas SliceRefPublicReplicaInfoT, proofs SliceRefPoStProofT, proverId ByteArray32T) *ResultBoolT {
// 	crandomness, crandomnessAllocMap := randomness.PassValue()
// 	creplicas, creplicasAllocMap := replicas.PassValue()
// 	cproofs, cproofsAllocMap := proofs.PassValue()
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	__ret := C.verify_window_post(crandomness, creplicas, cproofs, cproverId)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(cproofsAllocMap)
// 	runtime.KeepAlive(creplicasAllocMap)
// 	runtime.KeepAlive(crandomnessAllocMap)
// 	__v := NewResultBoolTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // MergeWindowPostPartitionProofs function as declared in filecoin-ffi/filcrypto.h:1235
// func MergeWindowPostPartitionProofs(registeredProof RegisteredPoStProofT, partitionProofs SliceRefPartitionSnarkProofT) *ResultPoStProofT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	cpartitionProofs, cpartitionProofsAllocMap := partitionProofs.PassValue()
// 	__ret := C.merge_window_post_partition_proofs(cregisteredProof, cpartitionProofs)
// 	runtime.KeepAlive(cpartitionProofsAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultPoStProofTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetNumPartitionForFallbackPost function as declared in filecoin-ffi/filcrypto.h:1252
// func GetNumPartitionForFallbackPost(registeredProof RegisteredPoStProofT, numSectors SizeT) *ResultSizeT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	cnumSectors, cnumSectorsAllocMap := (C.size_t)(numSectors), cgoAllocsUnknown
// 	__ret := C.get_num_partition_for_fallback_post(cregisteredProof, cnumSectors)
// 	runtime.KeepAlive(cnumSectorsAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSizeTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateSingleWindowPostWithVanilla function as declared in filecoin-ffi/filcrypto.h:1277
// func GenerateSingleWindowPostWithVanilla(registeredProof RegisteredPoStProofT, randomness ByteArray32T, proverId ByteArray32T, vanillaProofs SliceRefSliceBoxedUint8T, partitionIndex SizeT) *ResultGenerateSingleWindowPoStWithVanillaT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	crandomness, crandomnessAllocMap := randomness.PassValue()
// 	cproverId, cproverIdAllocMap := proverId.PassValue()
// 	cvanillaProofs, cvanillaProofsAllocMap := vanillaProofs.PassValue()
// 	cpartitionIndex, cpartitionIndexAllocMap := (C.size_t)(partitionIndex), cgoAllocsUnknown
// 	__ret := C.generate_single_window_post_with_vanilla(cregisteredProof, crandomness, cproverId, cvanillaProofs, cpartitionIndex)
// 	runtime.KeepAlive(cpartitionIndexAllocMap)
// 	runtime.KeepAlive(cvanillaProofsAllocMap)
// 	runtime.KeepAlive(cproverIdAllocMap)
// 	runtime.KeepAlive(crandomnessAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultGenerateSingleWindowPoStWithVanillaTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // EmptySectorUpdateEncodeInto function as declared in filecoin-ffi/filcrypto.h:1330
// func EmptySectorUpdateEncodeInto(registeredProof RegisteredUpdateProofT, newReplicaPath SliceRefUint8T, newCacheDirPath SliceRefUint8T, sectorKeyPath SliceRefUint8T, sectorKeyCacheDirPath SliceRefUint8T, stagedDataPath SliceRefUint8T, pieces SliceRefPublicPieceInfoT) *ResultEmptySectorUpdateEncodeIntoT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredUpdateProof_t)(registeredProof), cgoAllocsUnknown
// 	cnewReplicaPath, cnewReplicaPathAllocMap := newReplicaPath.PassValue()
// 	cnewCacheDirPath, cnewCacheDirPathAllocMap := newCacheDirPath.PassValue()
// 	csectorKeyPath, csectorKeyPathAllocMap := sectorKeyPath.PassValue()
// 	csectorKeyCacheDirPath, csectorKeyCacheDirPathAllocMap := sectorKeyCacheDirPath.PassValue()
// 	cstagedDataPath, cstagedDataPathAllocMap := stagedDataPath.PassValue()
// 	cpieces, cpiecesAllocMap := pieces.PassValue()
// 	__ret := C.empty_sector_update_encode_into(cregisteredProof, cnewReplicaPath, cnewCacheDirPath, csectorKeyPath, csectorKeyCacheDirPath, cstagedDataPath, cpieces)
// 	runtime.KeepAlive(cpiecesAllocMap)
// 	runtime.KeepAlive(cstagedDataPathAllocMap)
// 	runtime.KeepAlive(csectorKeyCacheDirPathAllocMap)
// 	runtime.KeepAlive(csectorKeyPathAllocMap)
// 	runtime.KeepAlive(cnewCacheDirPathAllocMap)
// 	runtime.KeepAlive(cnewReplicaPathAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultEmptySectorUpdateEncodeIntoTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // EmptySectorUpdateDecodeFrom function as declared in filecoin-ffi/filcrypto.h:1342
// func EmptySectorUpdateDecodeFrom(registeredProof RegisteredUpdateProofT, outDataPath SliceRefUint8T, replicaPath SliceRefUint8T, sectorKeyPath SliceRefUint8T, sectorKeyCacheDirPath SliceRefUint8T, commDNew ByteArray32T) *ResultVoidT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredUpdateProof_t)(registeredProof), cgoAllocsUnknown
// 	coutDataPath, coutDataPathAllocMap := outDataPath.PassValue()
// 	creplicaPath, creplicaPathAllocMap := replicaPath.PassValue()
// 	csectorKeyPath, csectorKeyPathAllocMap := sectorKeyPath.PassValue()
// 	csectorKeyCacheDirPath, csectorKeyCacheDirPathAllocMap := sectorKeyCacheDirPath.PassValue()
// 	ccommDNew, ccommDNewAllocMap := commDNew.PassValue()
// 	__ret := C.empty_sector_update_decode_from(cregisteredProof, coutDataPath, creplicaPath, csectorKeyPath, csectorKeyCacheDirPath, ccommDNew)
// 	runtime.KeepAlive(ccommDNewAllocMap)
// 	runtime.KeepAlive(csectorKeyCacheDirPathAllocMap)
// 	runtime.KeepAlive(csectorKeyPathAllocMap)
// 	runtime.KeepAlive(creplicaPathAllocMap)
// 	runtime.KeepAlive(coutDataPathAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultVoidTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // EmptySectorUpdateRemoveEncodedData function as declared in filecoin-ffi/filcrypto.h:1353
// func EmptySectorUpdateRemoveEncodedData(registeredProof RegisteredUpdateProofT, sectorKeyPath SliceRefUint8T, sectorKeyCacheDirPath SliceRefUint8T, replicaPath SliceRefUint8T, replicaCachePath SliceRefUint8T, dataPath SliceRefUint8T, commDNew ByteArray32T) *ResultVoidT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredUpdateProof_t)(registeredProof), cgoAllocsUnknown
// 	csectorKeyPath, csectorKeyPathAllocMap := sectorKeyPath.PassValue()
// 	csectorKeyCacheDirPath, csectorKeyCacheDirPathAllocMap := sectorKeyCacheDirPath.PassValue()
// 	creplicaPath, creplicaPathAllocMap := replicaPath.PassValue()
// 	creplicaCachePath, creplicaCachePathAllocMap := replicaCachePath.PassValue()
// 	cdataPath, cdataPathAllocMap := dataPath.PassValue()
// 	ccommDNew, ccommDNewAllocMap := commDNew.PassValue()
// 	__ret := C.empty_sector_update_remove_encoded_data(cregisteredProof, csectorKeyPath, csectorKeyCacheDirPath, creplicaPath, creplicaCachePath, cdataPath, ccommDNew)
// 	runtime.KeepAlive(ccommDNewAllocMap)
// 	runtime.KeepAlive(cdataPathAllocMap)
// 	runtime.KeepAlive(creplicaCachePathAllocMap)
// 	runtime.KeepAlive(creplicaPathAllocMap)
// 	runtime.KeepAlive(csectorKeyCacheDirPathAllocMap)
// 	runtime.KeepAlive(csectorKeyPathAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultVoidTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateEmptySectorUpdatePartitionProofs function as declared in filecoin-ffi/filcrypto.h:1365
// func GenerateEmptySectorUpdatePartitionProofs(registeredProof RegisteredUpdateProofT, commROld ByteArray32T, commRNew ByteArray32T, commDNew ByteArray32T, sectorKeyPath SliceRefUint8T, sectorKeyCacheDirPath SliceRefUint8T, replicaPath SliceRefUint8T, replicaCachePath SliceRefUint8T) *ResultSliceBoxedSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredUpdateProof_t)(registeredProof), cgoAllocsUnknown
// 	ccommROld, ccommROldAllocMap := commROld.PassValue()
// 	ccommRNew, ccommRNewAllocMap := commRNew.PassValue()
// 	ccommDNew, ccommDNewAllocMap := commDNew.PassValue()
// 	csectorKeyPath, csectorKeyPathAllocMap := sectorKeyPath.PassValue()
// 	csectorKeyCacheDirPath, csectorKeyCacheDirPathAllocMap := sectorKeyCacheDirPath.PassValue()
// 	creplicaPath, creplicaPathAllocMap := replicaPath.PassValue()
// 	creplicaCachePath, creplicaCachePathAllocMap := replicaCachePath.PassValue()
// 	__ret := C.generate_empty_sector_update_partition_proofs(cregisteredProof, ccommROld, ccommRNew, ccommDNew, csectorKeyPath, csectorKeyCacheDirPath, creplicaPath, creplicaCachePath)
// 	runtime.KeepAlive(creplicaCachePathAllocMap)
// 	runtime.KeepAlive(creplicaPathAllocMap)
// 	runtime.KeepAlive(csectorKeyCacheDirPathAllocMap)
// 	runtime.KeepAlive(csectorKeyPathAllocMap)
// 	runtime.KeepAlive(ccommDNewAllocMap)
// 	runtime.KeepAlive(ccommRNewAllocMap)
// 	runtime.KeepAlive(ccommROldAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // VerifyEmptySectorUpdatePartitionProofs function as declared in filecoin-ffi/filcrypto.h:1378
// func VerifyEmptySectorUpdatePartitionProofs(registeredProof RegisteredUpdateProofT, proofs SliceRefSliceBoxedUint8T, commROld ByteArray32T, commRNew ByteArray32T, commDNew ByteArray32T) *ResultBoolT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredUpdateProof_t)(registeredProof), cgoAllocsUnknown
// 	cproofs, cproofsAllocMap := proofs.PassValue()
// 	ccommROld, ccommROldAllocMap := commROld.PassValue()
// 	ccommRNew, ccommRNewAllocMap := commRNew.PassValue()
// 	ccommDNew, ccommDNewAllocMap := commDNew.PassValue()
// 	__ret := C.verify_empty_sector_update_partition_proofs(cregisteredProof, cproofs, ccommROld, ccommRNew, ccommDNew)
// 	runtime.KeepAlive(ccommDNewAllocMap)
// 	runtime.KeepAlive(ccommRNewAllocMap)
// 	runtime.KeepAlive(ccommROldAllocMap)
// 	runtime.KeepAlive(cproofsAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultBoolTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateEmptySectorUpdateProofWithVanilla function as declared in filecoin-ffi/filcrypto.h:1388
// func GenerateEmptySectorUpdateProofWithVanilla(registeredProof RegisteredUpdateProofT, vanillaProofs SliceRefSliceBoxedUint8T, commROld ByteArray32T, commRNew ByteArray32T, commDNew ByteArray32T) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredUpdateProof_t)(registeredProof), cgoAllocsUnknown
// 	cvanillaProofs, cvanillaProofsAllocMap := vanillaProofs.PassValue()
// 	ccommROld, ccommROldAllocMap := commROld.PassValue()
// 	ccommRNew, ccommRNewAllocMap := commRNew.PassValue()
// 	ccommDNew, ccommDNewAllocMap := commDNew.PassValue()
// 	__ret := C.generate_empty_sector_update_proof_with_vanilla(cregisteredProof, cvanillaProofs, ccommROld, ccommRNew, ccommDNew)
// 	runtime.KeepAlive(ccommDNewAllocMap)
// 	runtime.KeepAlive(ccommRNewAllocMap)
// 	runtime.KeepAlive(ccommROldAllocMap)
// 	runtime.KeepAlive(cvanillaProofsAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateEmptySectorUpdateProof function as declared in filecoin-ffi/filcrypto.h:1398
// func GenerateEmptySectorUpdateProof(registeredProof RegisteredUpdateProofT, commROld ByteArray32T, commRNew ByteArray32T, commDNew ByteArray32T, sectorKeyPath SliceRefUint8T, sectorKeyCacheDirPath SliceRefUint8T, replicaPath SliceRefUint8T, replicaCachePath SliceRefUint8T) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredUpdateProof_t)(registeredProof), cgoAllocsUnknown
// 	ccommROld, ccommROldAllocMap := commROld.PassValue()
// 	ccommRNew, ccommRNewAllocMap := commRNew.PassValue()
// 	ccommDNew, ccommDNewAllocMap := commDNew.PassValue()
// 	csectorKeyPath, csectorKeyPathAllocMap := sectorKeyPath.PassValue()
// 	csectorKeyCacheDirPath, csectorKeyCacheDirPathAllocMap := sectorKeyCacheDirPath.PassValue()
// 	creplicaPath, creplicaPathAllocMap := replicaPath.PassValue()
// 	creplicaCachePath, creplicaCachePathAllocMap := replicaCachePath.PassValue()
// 	__ret := C.generate_empty_sector_update_proof(cregisteredProof, ccommROld, ccommRNew, ccommDNew, csectorKeyPath, csectorKeyCacheDirPath, creplicaPath, creplicaCachePath)
// 	runtime.KeepAlive(creplicaCachePathAllocMap)
// 	runtime.KeepAlive(creplicaPathAllocMap)
// 	runtime.KeepAlive(csectorKeyCacheDirPathAllocMap)
// 	runtime.KeepAlive(csectorKeyPathAllocMap)
// 	runtime.KeepAlive(ccommDNewAllocMap)
// 	runtime.KeepAlive(ccommRNewAllocMap)
// 	runtime.KeepAlive(ccommROldAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // VerifyEmptySectorUpdateProof function as declared in filecoin-ffi/filcrypto.h:1411
// func VerifyEmptySectorUpdateProof(registeredProof RegisteredUpdateProofT, proof SliceRefUint8T, commROld ByteArray32T, commRNew ByteArray32T, commDNew ByteArray32T) *ResultBoolT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredUpdateProof_t)(registeredProof), cgoAllocsUnknown
// 	cproof, cproofAllocMap := proof.PassValue()
// 	ccommROld, ccommROldAllocMap := commROld.PassValue()
// 	ccommRNew, ccommRNewAllocMap := commRNew.PassValue()
// 	ccommDNew, ccommDNewAllocMap := commDNew.PassValue()
// 	__ret := C.verify_empty_sector_update_proof(cregisteredProof, cproof, ccommROld, ccommRNew, ccommDNew)
// 	runtime.KeepAlive(ccommDNewAllocMap)
// 	runtime.KeepAlive(ccommRNewAllocMap)
// 	runtime.KeepAlive(ccommROldAllocMap)
// 	runtime.KeepAlive(cproofAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultBoolTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GeneratePieceCommitment function as declared in filecoin-ffi/filcrypto.h:1440
// func GeneratePieceCommitment(registeredProof RegisteredSealProofT, pieceFdRaw Int32T, unpaddedPieceSize Uint64T) *ResultGeneratePieceCommitmentT {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	cpieceFdRaw, cpieceFdRawAllocMap := (C.int32_t)(pieceFdRaw), cgoAllocsUnknown
// 	cunpaddedPieceSize, cunpaddedPieceSizeAllocMap := (C.uint64_t)(unpaddedPieceSize), cgoAllocsUnknown
// 	__ret := C.generate_piece_commitment(cregisteredProof, cpieceFdRaw, cunpaddedPieceSize)
// 	runtime.KeepAlive(cunpaddedPieceSizeAllocMap)
// 	runtime.KeepAlive(cpieceFdRawAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultGeneratePieceCommitmentTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GenerateDataCommitment function as declared in filecoin-ffi/filcrypto.h:1448
// func GenerateDataCommitment(registeredProof RegisteredSealProofT, pieces SliceRefPublicPieceInfoT) *ResultByteArray32T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	cpieces, cpiecesAllocMap := pieces.PassValue()
// 	__ret := C.generate_data_commitment(cregisteredProof, cpieces)
// 	runtime.KeepAlive(cpiecesAllocMap)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultByteArray32TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // ClearCache function as declared in filecoin-ffi/filcrypto.h:1452
// func ClearCache(sectorSize Uint64T, cacheDirPath SliceRefUint8T) *ResultVoidT {
// 	csectorSize, csectorSizeAllocMap := (C.uint64_t)(sectorSize), cgoAllocsUnknown
// 	ccacheDirPath, ccacheDirPathAllocMap := cacheDirPath.PassValue()
// 	__ret := C.clear_cache(csectorSize, ccacheDirPath)
// 	runtime.KeepAlive(ccacheDirPathAllocMap)
// 	runtime.KeepAlive(csectorSizeAllocMap)
// 	__v := NewResultVoidTRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetMaxUserBytesPerStagedSector function as declared in filecoin-ffi/filcrypto.h:1459
// func GetMaxUserBytesPerStagedSector(registeredProof RegisteredSealProofT) Uint64T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_max_user_bytes_per_staged_sector(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := (Uint64T)(__ret)
// 	return __v
// }

// // GetSealParamsCid function as declared in filecoin-ffi/filcrypto.h:1465
// func GetSealParamsCid(registeredProof RegisteredSealProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_seal_params_cid(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetSealVerifyingKeyCid function as declared in filecoin-ffi/filcrypto.h:1471
// func GetSealVerifyingKeyCid(registeredProof RegisteredSealProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_seal_verifying_key_cid(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetSealParamsPath function as declared in filecoin-ffi/filcrypto.h:1478
// func GetSealParamsPath(registeredProof RegisteredSealProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_seal_params_path(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetSealVerifyingKeyPath function as declared in filecoin-ffi/filcrypto.h:1485
// func GetSealVerifyingKeyPath(registeredProof RegisteredSealProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_seal_verifying_key_path(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetSealCircuitIdentifier function as declared in filecoin-ffi/filcrypto.h:1491
// func GetSealCircuitIdentifier(registeredProof RegisteredSealProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_seal_circuit_identifier(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetSealVersion function as declared in filecoin-ffi/filcrypto.h:1497
// func GetSealVersion(registeredProof RegisteredSealProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredSealProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_seal_version(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetPostParamsCid function as declared in filecoin-ffi/filcrypto.h:1503
// func GetPostParamsCid(registeredProof RegisteredPoStProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_post_params_cid(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetPostVerifyingKeyCid function as declared in filecoin-ffi/filcrypto.h:1509
// func GetPostVerifyingKeyCid(registeredProof RegisteredPoStProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_post_verifying_key_cid(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetPostParamsPath function as declared in filecoin-ffi/filcrypto.h:1516
// func GetPostParamsPath(registeredProof RegisteredPoStProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_post_params_path(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetPostVerifyingKeyPath function as declared in filecoin-ffi/filcrypto.h:1523
// func GetPostVerifyingKeyPath(registeredProof RegisteredPoStProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_post_verifying_key_path(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetPostCircuitIdentifier function as declared in filecoin-ffi/filcrypto.h:1529
// func GetPostCircuitIdentifier(registeredProof RegisteredPoStProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_post_circuit_identifier(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // GetPostVersion function as declared in filecoin-ffi/filcrypto.h:1535
// func GetPostVersion(registeredProof RegisteredPoStProofT) *ResultSliceBoxedUint8T {
// 	cregisteredProof, cregisteredProofAllocMap := (C.RegisteredPoStProof_t)(registeredProof), cgoAllocsUnknown
// 	__ret := C.get_post_version(cregisteredProof)
// 	runtime.KeepAlive(cregisteredProofAllocMap)
// 	__v := NewResultSliceBoxedUint8TRef(unsafe.Pointer(__ret))
// 	return __v
// }

// // DestroyWriteWithAlignmentResponse function as declared in filecoin-ffi/filcrypto.h:1541
// func DestroyWriteWithAlignmentResponse(ptr *ResultWriteWithAlignmentT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_write_with_alignment_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyWriteWithoutAlignmentResponse function as declared in filecoin-ffi/filcrypto.h:1547
// func DestroyWriteWithoutAlignmentResponse(ptr *ResultWriteWithoutAlignmentT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_write_without_alignment_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyFauxrepResponse function as declared in filecoin-ffi/filcrypto.h:1553
// func DestroyFauxrepResponse(ptr *ResultByteArray32T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_fauxrep_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroySealPreCommitPhase1Response function as declared in filecoin-ffi/filcrypto.h:1559
// func DestroySealPreCommitPhase1Response(ptr *ResultSliceBoxedUint8T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_seal_pre_commit_phase1_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroySealPreCommitPhase2Response function as declared in filecoin-ffi/filcrypto.h:1565
// func DestroySealPreCommitPhase2Response(ptr *ResultSealPreCommitPhase2T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_seal_pre_commit_phase2_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroySealCommitPhase1Response function as declared in filecoin-ffi/filcrypto.h:1571
// func DestroySealCommitPhase1Response(ptr *ResultSliceBoxedUint8T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_seal_commit_phase1_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroySealCommitPhase2Response function as declared in filecoin-ffi/filcrypto.h:1577
// func DestroySealCommitPhase2Response(ptr *ResultSealCommitPhase2T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_seal_commit_phase2_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyUnsealRangeResponse function as declared in filecoin-ffi/filcrypto.h:1583
// func DestroyUnsealRangeResponse(ptr *ResultVoidT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_unseal_range_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGeneratePieceCommitmentResponse function as declared in filecoin-ffi/filcrypto.h:1589
// func DestroyGeneratePieceCommitmentResponse(ptr *ResultGeneratePieceCommitmentT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_generate_piece_commitment_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGenerateDataCommitmentResponse function as declared in filecoin-ffi/filcrypto.h:1595
// func DestroyGenerateDataCommitmentResponse(ptr *ResultByteArray32T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_generate_data_commitment_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyStringResponse function as declared in filecoin-ffi/filcrypto.h:1601
// func DestroyStringResponse(ptr *ResultSliceBoxedUint8T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_string_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyVerifySealResponse function as declared in filecoin-ffi/filcrypto.h:1607
// func DestroyVerifySealResponse(ptr *ResultBoolT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_verify_seal_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyVerifyAggregateSealResponse function as declared in filecoin-ffi/filcrypto.h:1613
// func DestroyVerifyAggregateSealResponse(ptr *ResultBoolT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_verify_aggregate_seal_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyFinalizeTicketResponse function as declared in filecoin-ffi/filcrypto.h:1619
// func DestroyFinalizeTicketResponse(ptr *ResultByteArray32T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_finalize_ticket_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyVerifyWinningPostResponse function as declared in filecoin-ffi/filcrypto.h:1625
// func DestroyVerifyWinningPostResponse(ptr *ResultBoolT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_verify_winning_post_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyVerifyWindowPostResponse function as declared in filecoin-ffi/filcrypto.h:1631
// func DestroyVerifyWindowPostResponse(ptr *ResultBoolT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_verify_window_post_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGenerateFallbackSectorChallengesResponse function as declared in filecoin-ffi/filcrypto.h:1637
// func DestroyGenerateFallbackSectorChallengesResponse(ptr *ResultGenerateFallbackSectorChallengesT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_generate_fallback_sector_challenges_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGenerateSingleVanillaProofResponse function as declared in filecoin-ffi/filcrypto.h:1643
// func DestroyGenerateSingleVanillaProofResponse(ptr *ResultSliceBoxedUint8T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_generate_single_vanilla_proof_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGenerateSingleWindowPostWithVanillaResponse function as declared in filecoin-ffi/filcrypto.h:1649
// func DestroyGenerateSingleWindowPostWithVanillaResponse(ptr *ResultGenerateSingleWindowPoStWithVanillaT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_generate_single_window_post_with_vanilla_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGetNumPartitionForFallbackPostResponse function as declared in filecoin-ffi/filcrypto.h:1655
// func DestroyGetNumPartitionForFallbackPostResponse(ptr *ResultSizeT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_get_num_partition_for_fallback_post_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyMergeWindowPostPartitionProofsResponse function as declared in filecoin-ffi/filcrypto.h:1661
// func DestroyMergeWindowPostPartitionProofsResponse(ptr *ResultPoStProofT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_merge_window_post_partition_proofs_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGenerateWinningPostResponse function as declared in filecoin-ffi/filcrypto.h:1667
// func DestroyGenerateWinningPostResponse(ptr *ResultSliceBoxedPoStProofT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_generate_winning_post_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGenerateWindowPostResponse function as declared in filecoin-ffi/filcrypto.h:1673
// func DestroyGenerateWindowPostResponse(ptr *ResultGenerateWindowPoStT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_generate_window_post_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGenerateWinningPostSectorChallenge function as declared in filecoin-ffi/filcrypto.h:1679
// func DestroyGenerateWinningPostSectorChallenge(ptr *ResultSliceBoxedUint64T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_generate_winning_post_sector_challenge(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyClearCacheResponse function as declared in filecoin-ffi/filcrypto.h:1685
// func DestroyClearCacheResponse(ptr *ResultVoidT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_clear_cache_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyAggregateProof function as declared in filecoin-ffi/filcrypto.h:1691
// func DestroyAggregateProof(ptr *ResultSliceBoxedUint8T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_aggregate_proof(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyEmptySectorUpdateGenerateProofResponse function as declared in filecoin-ffi/filcrypto.h:1697
// func DestroyEmptySectorUpdateGenerateProofResponse(ptr *ResultSliceBoxedUint8T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_empty_sector_update_generate_proof_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyEmptySectorUpdateVerifyProofResponse function as declared in filecoin-ffi/filcrypto.h:1703
// func DestroyEmptySectorUpdateVerifyProofResponse(ptr *ResultBoolT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_empty_sector_update_verify_proof_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyGenerateEmptySectorUpdatePartitionProofResponse function as declared in filecoin-ffi/filcrypto.h:1709
// func DestroyGenerateEmptySectorUpdatePartitionProofResponse(ptr *ResultSliceBoxedSliceBoxedUint8T) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_generate_empty_sector_update_partition_proof_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyVerifyEmptySectorUpdatePartitionProofResponse function as declared in filecoin-ffi/filcrypto.h:1715
// func DestroyVerifyEmptySectorUpdatePartitionProofResponse(ptr *ResultBoolT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_verify_empty_sector_update_partition_proof_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyEmptySectorUpdateEncodeIntoResponse function as declared in filecoin-ffi/filcrypto.h:1721
// func DestroyEmptySectorUpdateEncodeIntoResponse(ptr *ResultEmptySectorUpdateEncodeIntoT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_empty_sector_update_encode_into_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyEmptySectorUpdateDecodeFromResponse function as declared in filecoin-ffi/filcrypto.h:1727
// func DestroyEmptySectorUpdateDecodeFromResponse(ptr *ResultVoidT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_empty_sector_update_decode_from_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

// // DestroyEmptySectorUpdateRemoveEncodedDataResponse function as declared in filecoin-ffi/filcrypto.h:1733
// func DestroyEmptySectorUpdateRemoveEncodedDataResponse(ptr *ResultVoidT) {
// 	cptr, cptrAllocMap := ptr.PassRef()
// 	C.destroy_empty_sector_update_remove_encoded_data_response(cptr)
// 	runtime.KeepAlive(cptrAllocMap)
// }

func (ptr *PrivateKeyGenerateResponse) Destroy() {
	C.destroy_private_key_generate_response(ptr)
}
