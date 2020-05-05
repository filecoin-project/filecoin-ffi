package generated

/*
#cgo LDFLAGS: -L${SRCDIR}/.. -lfilcrypto
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
#include "cgo_helpers.h"
*/
import "C"
import (
	"unsafe"
)

func (x *FilPrivateReplicaInfo) AllocateProxy() func() {
	mem81a31e9b := allocFilPrivateReplicaInfoMemory(1)
	ref81a31e9b := (*C.fil_PrivateReplicaInfo)(mem81a31e9b)
	ref81a31e9b.cache_dir_path = C.CString(x.CacheDirPath)
	ref81a31e9b.comm_r = *(*[32]C.uint8_t)(unsafe.Pointer(&x.CommR))
	ref81a31e9b.registered_proof = (C.fil_RegisteredPoStProof)(x.RegisteredProof)
	ref81a31e9b.replica_path = C.CString(x.ReplicaPath)
	ref81a31e9b.sector_id = (C.uint64_t)(x.SectorId)

	x.ref81a31e9b = ref81a31e9b

	return func() {
		C.free(unsafe.Pointer(ref81a31e9b.cache_dir_path))
		C.free(unsafe.Pointer(ref81a31e9b.replica_path))
		C.free(unsafe.Pointer(ref81a31e9b))
	}
}

func (x *FilPoStProof) AllocateProxy() func() {
	mem3451bfa := allocFilPoStProofMemory(1)
	ref3451bfa := (*C.fil_PoStProof)(mem3451bfa)

	ref3451bfa.registered_proof = (C.fil_RegisteredPoStProof)(x.RegisteredProof)
	ref3451bfa.proof_len = (C.size_t)(x.ProofLen)
	ref3451bfa.proof_ptr = (*C.uchar)(unsafe.Pointer(C.CString(x.ProofPtr)))

	x.ref3451bfa = ref3451bfa

	return func() {
		C.free(unsafe.Pointer(ref3451bfa.proof_ptr))
		C.free(unsafe.Pointer(ref3451bfa))
	}
}
