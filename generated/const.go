// WARNING: This file has automatically been generated
// Code generated by https://git.io/c-for-go. DO NOT EDIT.

package generated

/*
#cgo LDFLAGS: -L${SRCDIR}/.. -lfilecoin
#cgo pkg-config: ${SRCDIR}/../filecoin.pc
#include "../filecoin.h"
#include <stdlib.h>
#include "cgo_helpers.h"
*/
import "C"

// FCPResponseStatus as declared in filecoin-ffi/filecoin.h:31
type FCPResponseStatus int32

// FCPResponseStatus enumeration from filecoin-ffi/filecoin.h:31
const (
	FCPResponseStatusFCPNoError           FCPResponseStatus = C.FCPResponseStatus_FCPNoError
	FCPResponseStatusFCPUnclassifiedError FCPResponseStatus = C.FCPResponseStatus_FCPUnclassifiedError
	FCPResponseStatusFCPCallerError       FCPResponseStatus = C.FCPResponseStatus_FCPCallerError
	FCPResponseStatusFCPReceiverError     FCPResponseStatus = C.FCPResponseStatus_FCPReceiverError
)

// FilRegisteredPoStProof as declared in filecoin-ffi/filecoin.h:38
type FilRegisteredPoStProof int32

// FilRegisteredPoStProof enumeration from filecoin-ffi/filecoin.h:38
const (
	FilRegisteredPoStProofStackedDrg2KiBV1   FilRegisteredPoStProof = C.fil_RegisteredPoStProof_StackedDrg2KiBV1
	FilRegisteredPoStProofStackedDrg8MiBV1   FilRegisteredPoStProof = C.fil_RegisteredPoStProof_StackedDrg8MiBV1
	FilRegisteredPoStProofStackedDrg512MiBV1 FilRegisteredPoStProof = C.fil_RegisteredPoStProof_StackedDrg512MiBV1
	FilRegisteredPoStProofStackedDrg32GiBV1  FilRegisteredPoStProof = C.fil_RegisteredPoStProof_StackedDrg32GiBV1
)

// FilRegisteredSealProof as declared in filecoin-ffi/filecoin.h:45
type FilRegisteredSealProof int32

// FilRegisteredSealProof enumeration from filecoin-ffi/filecoin.h:45
const (
	FilRegisteredSealProofStackedDrg2KiBV1   FilRegisteredSealProof = C.fil_RegisteredSealProof_StackedDrg2KiBV1
	FilRegisteredSealProofStackedDrg8MiBV1   FilRegisteredSealProof = C.fil_RegisteredSealProof_StackedDrg8MiBV1
	FilRegisteredSealProofStackedDrg512MiBV1 FilRegisteredSealProof = C.fil_RegisteredSealProof_StackedDrg512MiBV1
	FilRegisteredSealProofStackedDrg32GiBV1  FilRegisteredSealProof = C.fil_RegisteredSealProof_StackedDrg32GiBV1
)
