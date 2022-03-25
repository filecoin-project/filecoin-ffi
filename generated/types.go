package generated

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

// FCPResponseStatusT type as declared in filecoin-ffi/filcrypto.h:25
type FCPResponseStatus int64

// SliceBoxedUint8T as declared in filecoin-ffi/filcrypto.h:68
type SliceBoxedUint8 = C.struct_slice_boxed_uint8

// // SliceBoxedSliceBoxedUint8T as declared in filecoin-ffi/filcrypto.h:96
// type SliceBoxedSliceBoxedUint8T struct {
// 	Ptr            []SliceBoxedUint8T
// 	Len            SizeT
// 	refe6bf5160    *C.slice_boxed_slice_boxed_uint8_t
// 	allocse6bf5160 interface{}
// }

// // ResultSliceBoxedSliceBoxedUint8T as declared in filecoin-ffi/filcrypto.h:106
// type ResultSliceBoxedSliceBoxedUint8T struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          SliceBoxedSliceBoxedUint8T
// 	ref44f2cc9e    *C.Result_slice_boxed_slice_boxed_uint8_t
// 	allocs44f2cc9e interface{}
// }

// // ResultVoidT as declared in filecoin-ffi/filcrypto.h:117
// type ResultVoidT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	ref4381f081    *C.Result_void_t
// 	allocs4381f081 interface{}
// }

// SliceRefUint8T as declared in filecoin-ffi/filcrypto.h:147
type SliceRefUint8 = C.slice_ref_uint8_t

// BLSDigestT as declared in filecoin-ffi/filcrypto.h:155
type BLSDigest = C.BLSDigest_t

func (ptr *BLSDigest) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.inner.idx[0])), 96)
}

// HashResponseT as declared in filecoin-ffi/filcrypto.h:164
type HashResponse = C.HashResponse_t

func (ptr *HashResponse) Digest() []byte {
	return ptr.digest.Slice()
}

type BLSSignature = C.BLSSignature_t

func (ptr *BLSSignature) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.inner.idx[0])), 96)
}

type AggregateResponse = C.AggregateResponse_t

func (ptr *AggregateResponse) Signature() []byte {
	return ptr.signature.Slice()
}

type SliceRefUint = C.slice_ref_size_t

type BLSPrivateKey = C.BLSPrivateKey_t

func (ptr *BLSPrivateKey) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.inner.idx[0])), 32)
}

type PrivateKeyGenerateResponse = C.PrivateKeyGenerateResponse_t

func (ptr *PrivateKeyGenerateResponse) PrivateKey() []byte {
	return ptr.private_key.Slice()
}

type ByteArray32 = C.ByteArray32_t

type PrivateKeySignResponse = C.PrivateKeySignResponse_t

func (ptr *PrivateKeySignResponse) Signature() []byte {
	return ptr.signature.Slice()
}

type BLSPublicKey = C.BLSPublicKey_t

func (ptr *BLSPublicKey) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&ptr.inner.idx[0])), 48)
}

type PrivateKeyPublicKeyResponse = C.PrivateKeyPublicKeyResponse_t

func (ptr *PrivateKeyPublicKeyResponse) PublicKey() []byte {
	return ptr.public_key.Slice()
}

type ZeroSignatureResponse = C.ZeroSignatureResponse_t

func (ptr *ZeroSignatureResponse) Signature() []byte {
	return ptr.signature.Slice()
}

// // RegisteredSealProofT type as declared in filecoin-ffi/filcrypto.h:399
// type RegisteredSealProofT int64

// // SliceRefUint64T as declared in filecoin-ffi/filcrypto.h:453
// type SliceRefUint64T struct {
// 	Ptr            []Uint64T
// 	Len            SizeT
// 	reff34e6912    *C.slice_ref_uint64_t
// 	allocsf34e6912 interface{}
// }

// // WriteWithAlignmentT as declared in filecoin-ffi/filcrypto.h:463
// type WriteWithAlignmentT struct {
// 	CommP                 Uint832ArrayT
// 	LeftAlignmentUnpadded Uint64T
// 	TotalWriteUnpadded    Uint64T
// 	ref3531b450           *C.WriteWithAlignment_t
// 	allocs3531b450        interface{}
// }

// // ResultWriteWithAlignmentT as declared in filecoin-ffi/filcrypto.h:473
// type ResultWriteWithAlignmentT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          WriteWithAlignmentT
// 	refed31278e    *C.Result_WriteWithAlignment_t
// 	allocsed31278e interface{}
// }

// // WriteWithoutAlignmentT as declared in filecoin-ffi/filcrypto.h:491
// type WriteWithoutAlignmentT struct {
// 	CommP              Uint832ArrayT
// 	TotalWriteUnpadded Uint64T
// 	ref591a420c        *C.WriteWithoutAlignment_t
// 	allocs591a420c     interface{}
// }

// // ResultWriteWithoutAlignmentT as declared in filecoin-ffi/filcrypto.h:501
// type ResultWriteWithoutAlignmentT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          WriteWithoutAlignmentT
// 	ref84618337    *C.Result_WriteWithoutAlignment_t
// 	allocs84618337 interface{}
// }

// // ResultByteArray32T as declared in filecoin-ffi/filcrypto.h:520
// type ResultByteArray32T struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          ByteArray32T
// 	ref4c37f9af    *C.Result_ByteArray32_t
// 	allocs4c37f9af interface{}
// }

// // PublicPieceInfoT as declared in filecoin-ffi/filcrypto.h:538
// type PublicPieceInfoT struct {
// 	NumBytes       Uint64T
// 	CommP          Uint832ArrayT
// 	ref41775798    *C.PublicPieceInfo_t
// 	allocs41775798 interface{}
// }

// // SliceRefPublicPieceInfoT as declared in filecoin-ffi/filcrypto.h:565
// type SliceRefPublicPieceInfoT struct {
// 	Ptr            []PublicPieceInfoT
// 	Len            SizeT
// 	ref28c8f598    *C.slice_ref_PublicPieceInfo_t
// 	allocs28c8f598 interface{}
// }

// // ResultSliceBoxedUint8T as declared in filecoin-ffi/filcrypto.h:575
// type ResultSliceBoxedUint8T struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          SliceBoxedUint8T
// 	ref2ceefbe4    *C.Result_slice_boxed_uint8_t
// 	allocs2ceefbe4 interface{}
// }

// // SealPreCommitPhase2T as declared in filecoin-ffi/filcrypto.h:598
// type SealPreCommitPhase2T struct {
// 	RegisteredProof RegisteredSealProofT
// 	CommD           Uint832ArrayT
// 	CommR           Uint832ArrayT
// 	refcd07a1fc     *C.SealPreCommitPhase2_t
// 	allocscd07a1fc  interface{}
// }

// // ResultSealPreCommitPhase2T as declared in filecoin-ffi/filcrypto.h:608
// type ResultSealPreCommitPhase2T struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          SealPreCommitPhase2T
// 	refacb45ebc    *C.Result_SealPreCommitPhase2_t
// 	allocsacb45ebc interface{}
// }

// // SealCommitPhase2T as declared in filecoin-ffi/filcrypto.h:637
// type SealCommitPhase2T struct {
// 	Proof          SliceBoxedUint8T
// 	ref66b8d6ea    *C.SealCommitPhase2_t
// 	allocs66b8d6ea interface{}
// }

// // ResultSealCommitPhase2T as declared in filecoin-ffi/filcrypto.h:647
// type ResultSealCommitPhase2T struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          SealCommitPhase2T
// 	refb3d64060    *C.Result_SealCommitPhase2_t
// 	allocsb3d64060 interface{}
// }

// // RegisteredAggregationProofT type as declared in filecoin-ffi/filcrypto.h:658
// type RegisteredAggregationProofT int64

// // SliceBoxedByteArray32T as declared in filecoin-ffi/filcrypto.h:695
// type SliceBoxedByteArray32T struct {
// 	Ptr            []ByteArray32T
// 	Len            SizeT
// 	refe3015bfe    *C.slice_boxed_ByteArray32_t
// 	allocse3015bfe interface{}
// }

// // SliceRefSealCommitPhase2T as declared in filecoin-ffi/filcrypto.h:722
// type SliceRefSealCommitPhase2T struct {
// 	Ptr            []SealCommitPhase2T
// 	Len            SizeT
// 	ref66d16948    *C.slice_ref_SealCommitPhase2_t
// 	allocs66d16948 interface{}
// }

// // AggregationInputsT as declared in filecoin-ffi/filcrypto.h:743
// type AggregationInputsT struct {
// 	CommR          ByteArray32T
// 	CommD          ByteArray32T
// 	SectorId       Uint64T
// 	Ticket         ByteArray32T
// 	Seed           ByteArray32T
// 	refb10889cf    *C.AggregationInputs_t
// 	allocsb10889cf interface{}
// }

// // SliceRefAggregationInputsT as declared in filecoin-ffi/filcrypto.h:770
// type SliceRefAggregationInputsT struct {
// 	Ptr            []AggregationInputsT
// 	Len            SizeT
// 	ref89d022b4    *C.slice_ref_AggregationInputs_t
// 	allocs89d022b4 interface{}
// }

// // ResultBoolT as declared in filecoin-ffi/filcrypto.h:783
// type ResultBoolT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          bool
// 	reff0bebe68    *C.Result_bool_t
// 	allocsf0bebe68 interface{}
// }

// // RegisteredPoStProofT type as declared in filecoin-ffi/filcrypto.h:827
// type RegisteredPoStProofT int64

// // SliceBoxedUint64T as declared in filecoin-ffi/filcrypto.h:882
// type SliceBoxedUint64T struct {
// 	Ptr            []Uint64T
// 	Len            SizeT
// 	ref280caf77    *C.slice_boxed_uint64_t
// 	allocs280caf77 interface{}
// }

// // ResultSliceBoxedUint64T as declared in filecoin-ffi/filcrypto.h:892
// type ResultSliceBoxedUint64T struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          SliceBoxedUint64T
// 	reff00c3ca9    *C.Result_slice_boxed_uint64_t
// 	allocsf00c3ca9 interface{}
// }

// // GenerateFallbackSectorChallengesT as declared in filecoin-ffi/filcrypto.h:911
// type GenerateFallbackSectorChallengesT struct {
// 	Ids              SliceBoxedUint64T
// 	Challenges       SliceBoxedUint64T
// 	ChallengesStride SizeT
// 	ref1a0802cf      *C.GenerateFallbackSectorChallenges_t
// 	allocs1a0802cf   interface{}
// }

// // ResultGenerateFallbackSectorChallengesT as declared in filecoin-ffi/filcrypto.h:921
// type ResultGenerateFallbackSectorChallengesT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          GenerateFallbackSectorChallengesT
// 	ref69d095cd    *C.Result_GenerateFallbackSectorChallenges_t
// 	allocs69d095cd interface{}
// }

// // PrivateReplicaInfoT as declared in filecoin-ffi/filcrypto.h:944
// type PrivateReplicaInfoT struct {
// 	RegisteredProof RegisteredPoStProofT
// 	CacheDirPath    SliceBoxedUint8T
// 	CommR           Uint832ArrayT
// 	ReplicaPath     SliceBoxedUint8T
// 	SectorId        Uint64T
// 	ref4fcd660f     *C.PrivateReplicaInfo_t
// 	allocs4fcd660f  interface{}
// }

// // SliceRefSliceBoxedUint8T as declared in filecoin-ffi/filcrypto.h:978
// type SliceRefSliceBoxedUint8T struct {
// 	Ptr            []SliceBoxedUint8T
// 	Len            SizeT
// 	ref198e5437    *C.slice_ref_slice_boxed_uint8_t
// 	allocs198e5437 interface{}
// }

// // PoStProofT as declared in filecoin-ffi/filcrypto.h:986
// type PoStProofT struct {
// 	RegisteredProof RegisteredPoStProofT
// 	Proof           SliceBoxedUint8T
// 	ref6b19d074     *C.PoStProof_t
// 	allocs6b19d074  interface{}
// }

// // SliceBoxedPoStProofT as declared in filecoin-ffi/filcrypto.h:1014
// type SliceBoxedPoStProofT struct {
// 	Ptr            []PoStProofT
// 	Len            SizeT
// 	ref9a32842f    *C.slice_boxed_PoStProof_t
// 	allocs9a32842f interface{}
// }

// // ResultSliceBoxedPoStProofT as declared in filecoin-ffi/filcrypto.h:1024
// type ResultSliceBoxedPoStProofT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          SliceBoxedPoStProofT
// 	ref47494514    *C.Result_slice_boxed_PoStProof_t
// 	allocs47494514 interface{}
// }

// // SliceRefPrivateReplicaInfoT as declared in filecoin-ffi/filcrypto.h:1060
// type SliceRefPrivateReplicaInfoT struct {
// 	Ptr            []PrivateReplicaInfoT
// 	Len            SizeT
// 	ref88221610    *C.slice_ref_PrivateReplicaInfo_t
// 	allocs88221610 interface{}
// }

// // PublicReplicaInfoT as declared in filecoin-ffi/filcrypto.h:1078
// type PublicReplicaInfoT struct {
// 	RegisteredProof RegisteredPoStProofT
// 	CommR           Uint832ArrayT
// 	SectorId        Uint64T
// 	ref2f93037      *C.PublicReplicaInfo_t
// 	allocs2f93037   interface{}
// }

// // SliceRefPublicReplicaInfoT as declared in filecoin-ffi/filcrypto.h:1105
// type SliceRefPublicReplicaInfoT struct {
// 	Ptr            []PublicReplicaInfoT
// 	Len            SizeT
// 	ref3a219b4c    *C.slice_ref_PublicReplicaInfo_t
// 	allocs3a219b4c interface{}
// }

// // SliceRefPoStProofT as declared in filecoin-ffi/filcrypto.h:1132
// type SliceRefPoStProofT struct {
// 	Ptr            []PoStProofT
// 	Len            SizeT
// 	refd15cdd4b    *C.slice_ref_PoStProof_t
// 	allocsd15cdd4b interface{}
// }

// // GenerateWindowPoStT as declared in filecoin-ffi/filcrypto.h:1149
// type GenerateWindowPoStT struct {
// 	Proofs         SliceBoxedPoStProofT
// 	FaultySectors  SliceBoxedUint64T
// 	refcee66945    *C.GenerateWindowPoSt_t
// 	allocscee66945 interface{}
// }

// // ResultGenerateWindowPoStT as declared in filecoin-ffi/filcrypto.h:1159
// type ResultGenerateWindowPoStT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          GenerateWindowPoStT
// 	ref16e6fa9b    *C.Result_GenerateWindowPoSt_t
// 	allocs16e6fa9b interface{}
// }

// // PartitionSnarkProofT as declared in filecoin-ffi/filcrypto.h:1193
// type PartitionSnarkProofT struct {
// 	RegisteredProof RegisteredPoStProofT
// 	Proof           SliceBoxedUint8T
// 	ref66732a1e     *C.PartitionSnarkProof_t
// 	allocs66732a1e  interface{}
// }

// // SliceRefPartitionSnarkProofT as declared in filecoin-ffi/filcrypto.h:1220
// type SliceRefPartitionSnarkProofT struct {
// 	Ptr            []PartitionSnarkProofT
// 	Len            SizeT
// 	refebbcc89b    *C.slice_ref_PartitionSnarkProof_t
// 	allocsebbcc89b interface{}
// }

// // ResultPoStProofT as declared in filecoin-ffi/filcrypto.h:1230
// type ResultPoStProofT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          PoStProofT
// 	ref20cbfc0b    *C.Result_PoStProof_t
// 	allocs20cbfc0b interface{}
// }

// // ResultSizeT as declared in filecoin-ffi/filcrypto.h:1247
// type ResultSizeT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          SizeT
// 	refdf6206d4    *C.Result_size_t
// 	allocsdf6206d4 interface{}
// }

// // GenerateSingleWindowPoStWithVanillaT as declared in filecoin-ffi/filcrypto.h:1262
// type GenerateSingleWindowPoStWithVanillaT struct {
// 	PartitionProof PartitionSnarkProofT
// 	FaultySectors  SliceBoxedUint64T
// 	refe1ddcd34    *C.GenerateSingleWindowPoStWithVanilla_t
// 	allocse1ddcd34 interface{}
// }

// // ResultGenerateSingleWindowPoStWithVanillaT as declared in filecoin-ffi/filcrypto.h:1272
// type ResultGenerateSingleWindowPoStWithVanillaT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          GenerateSingleWindowPoStWithVanillaT
// 	ref54515f12    *C.Result_GenerateSingleWindowPoStWithVanilla_t
// 	allocs54515f12 interface{}
// }

// // RegisteredUpdateProofT type as declared in filecoin-ffi/filcrypto.h:1288
// type RegisteredUpdateProofT int64

// // EmptySectorUpdateEncodeIntoT as declared in filecoin-ffi/filcrypto.h:1315
// type EmptySectorUpdateEncodeIntoT struct {
// 	CommRNew       Uint832ArrayT
// 	CommRLastNew   Uint832ArrayT
// 	CommDNew       Uint832ArrayT
// 	ref7572da08    *C.EmptySectorUpdateEncodeInto_t
// 	allocs7572da08 interface{}
// }

// // ResultEmptySectorUpdateEncodeIntoT as declared in filecoin-ffi/filcrypto.h:1325
// type ResultEmptySectorUpdateEncodeIntoT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          EmptySectorUpdateEncodeIntoT
// 	reff6d56df3    *C.Result_EmptySectorUpdateEncodeInto_t
// 	allocsf6d56df3 interface{}
// }

// // GeneratePieceCommitmentT as declared in filecoin-ffi/filcrypto.h:1424
// type GeneratePieceCommitmentT struct {
// 	CommP           Uint832ArrayT
// 	NumBytesAligned Uint64T
// 	refba03f700     *C.GeneratePieceCommitment_t
// 	allocsba03f700  interface{}
// }

// // ResultGeneratePieceCommitmentT as declared in filecoin-ffi/filcrypto.h:1434
// type ResultGeneratePieceCommitmentT struct {
// 	StatusCode     FCPResponseStatusT
// 	ErrorMsg       SliceBoxedUint8T
// 	Value          GeneratePieceCommitmentT
// 	ref6ad23765    *C.Result_GeneratePieceCommitment_t
// 	allocs6ad23765 interface{}
// }

// // SizeT type as declared in headerstubs/stddef.h:1
// type SizeT uint

// // Uint8T type as declared in headerstubs/stdint.h:1
// type Uint8T byte

// // Int32T type as declared in headerstubs/stdint.h:2
// type Int32T int64

// // Uint32T type as declared in headerstubs/stdint.h:3
// type Uint32T uint64

// // Int64T type as declared in headerstubs/stdint.h:4
// type Int64T int64

// // Uint64T type as declared in headerstubs/stdint.h:5
// type Uint64T uint64

// // UintptrT type as declared in headerstubs/stdint.h:6
// type UintptrT uint64
