package generated

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

const (
	// FCPRESPONSESTATUSNOERROR as declared in filecoin-ffi/filcrypto.h:29
	FCPRESPONSESTATUSNOERROR = C.F_C_P_RESPONSE_STATUS_NO_ERROR
	// FCPRESPONSESTATUSUNCLASSIFIEDERROR as declared in filecoin-ffi/filcrypto.h:31
	FCPRESPONSESTATUSUNCLASSIFIEDERROR = C.F_C_P_RESPONSE_STATUS_UNCLASSIFIED_ERROR
	// FCPRESPONSESTATUSCALLERERROR as declared in filecoin-ffi/filcrypto.h:33
	FCPRESPONSESTATUSCALLERERROR = C.F_C_P_RESPONSE_STATUS_CALLER_ERROR
	// FCPRESPONSESTATUSRECEIVERERROR as declared in filecoin-ffi/filcrypto.h:35
	FCPRESPONSESTATUSRECEIVERERROR = C.F_C_P_RESPONSE_STATUS_RECEIVER_ERROR
)

const (
	// REGISTEREDSEALPROOFSTACKEDDRG2KIBV1 as declared in filecoin-ffi/filcrypto.h:403
	REGISTEREDSEALPROOFSTACKEDDRG2KIBV1 = C.REGISTERED_SEAL_PROOF_STACKED_DRG2_KI_B_V1
	// REGISTEREDSEALPROOFSTACKEDDRG8MIBV1 as declared in filecoin-ffi/filcrypto.h:405
	REGISTEREDSEALPROOFSTACKEDDRG8MIBV1 = C.REGISTERED_SEAL_PROOF_STACKED_DRG8_MI_B_V1
	// REGISTEREDSEALPROOFSTACKEDDRG512MIBV1 as declared in filecoin-ffi/filcrypto.h:407
	REGISTEREDSEALPROOFSTACKEDDRG512MIBV1 = C.REGISTERED_SEAL_PROOF_STACKED_DRG512_MI_B_V1
	// REGISTEREDSEALPROOFSTACKEDDRG32GIBV1 as declared in filecoin-ffi/filcrypto.h:409
	REGISTEREDSEALPROOFSTACKEDDRG32GIBV1 = C.REGISTERED_SEAL_PROOF_STACKED_DRG32_GI_B_V1
	// REGISTEREDSEALPROOFSTACKEDDRG64GIBV1 as declared in filecoin-ffi/filcrypto.h:411
	REGISTEREDSEALPROOFSTACKEDDRG64GIBV1 = C.REGISTERED_SEAL_PROOF_STACKED_DRG64_GI_B_V1
	// REGISTEREDSEALPROOFSTACKEDDRG2KIBV11 as declared in filecoin-ffi/filcrypto.h:413
	REGISTEREDSEALPROOFSTACKEDDRG2KIBV11 = C.REGISTERED_SEAL_PROOF_STACKED_DRG2_KI_B_V1_1
	// REGISTEREDSEALPROOFSTACKEDDRG8MIBV11 as declared in filecoin-ffi/filcrypto.h:415
	REGISTEREDSEALPROOFSTACKEDDRG8MIBV11 = C.REGISTERED_SEAL_PROOF_STACKED_DRG8_MI_B_V1_1
	// REGISTEREDSEALPROOFSTACKEDDRG512MIBV11 as declared in filecoin-ffi/filcrypto.h:417
	REGISTEREDSEALPROOFSTACKEDDRG512MIBV11 = C.REGISTERED_SEAL_PROOF_STACKED_DRG512_MI_B_V1_1
	// REGISTEREDSEALPROOFSTACKEDDRG32GIBV11 as declared in filecoin-ffi/filcrypto.h:419
	REGISTEREDSEALPROOFSTACKEDDRG32GIBV11 = C.REGISTERED_SEAL_PROOF_STACKED_DRG32_GI_B_V1_1
	// REGISTEREDSEALPROOFSTACKEDDRG64GIBV11 as declared in filecoin-ffi/filcrypto.h:421
	REGISTEREDSEALPROOFSTACKEDDRG64GIBV11 = C.REGISTERED_SEAL_PROOF_STACKED_DRG64_GI_B_V1_1
)

const (
	// REGISTEREDAGGREGATIONPROOFSNARKPACKV1 as declared in filecoin-ffi/filcrypto.h:662
	REGISTEREDAGGREGATIONPROOFSNARKPACKV1 = C.REGISTERED_AGGREGATION_PROOF_SNARK_PACK_V1
)

const (
	// REGISTEREDPOSTPROOFSTACKEDDRGWINNING2KIBV1 as declared in filecoin-ffi/filcrypto.h:831
	REGISTEREDPOSTPROOFSTACKEDDRGWINNING2KIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING2_KI_B_V1
	// REGISTEREDPOSTPROOFSTACKEDDRGWINNING8MIBV1 as declared in filecoin-ffi/filcrypto.h:833
	REGISTEREDPOSTPROOFSTACKEDDRGWINNING8MIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING8_MI_B_V1
	// REGISTEREDPOSTPROOFSTACKEDDRGWINNING512MIBV1 as declared in filecoin-ffi/filcrypto.h:835
	REGISTEREDPOSTPROOFSTACKEDDRGWINNING512MIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING512_MI_B_V1
	// REGISTEREDPOSTPROOFSTACKEDDRGWINNING32GIBV1 as declared in filecoin-ffi/filcrypto.h:837
	REGISTEREDPOSTPROOFSTACKEDDRGWINNING32GIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING32_GI_B_V1
	// REGISTEREDPOSTPROOFSTACKEDDRGWINNING64GIBV1 as declared in filecoin-ffi/filcrypto.h:839
	REGISTEREDPOSTPROOFSTACKEDDRGWINNING64GIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING64_GI_B_V1
	// REGISTEREDPOSTPROOFSTACKEDDRGWINDOW2KIBV1 as declared in filecoin-ffi/filcrypto.h:841
	REGISTEREDPOSTPROOFSTACKEDDRGWINDOW2KIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW2_KI_B_V1
	// REGISTEREDPOSTPROOFSTACKEDDRGWINDOW8MIBV1 as declared in filecoin-ffi/filcrypto.h:843
	REGISTEREDPOSTPROOFSTACKEDDRGWINDOW8MIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW8_MI_B_V1
	// REGISTEREDPOSTPROOFSTACKEDDRGWINDOW512MIBV1 as declared in filecoin-ffi/filcrypto.h:845
	REGISTEREDPOSTPROOFSTACKEDDRGWINDOW512MIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW512_MI_B_V1
	// REGISTEREDPOSTPROOFSTACKEDDRGWINDOW32GIBV1 as declared in filecoin-ffi/filcrypto.h:847
	REGISTEREDPOSTPROOFSTACKEDDRGWINDOW32GIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW32_GI_B_V1
	// REGISTEREDPOSTPROOFSTACKEDDRGWINDOW64GIBV1 as declared in filecoin-ffi/filcrypto.h:849
	REGISTEREDPOSTPROOFSTACKEDDRGWINDOW64GIBV1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW64_GI_B_V1
)

const (
	// REGISTEREDUPDATEPROOFSTACKEDDRG2KIBV1 as declared in filecoin-ffi/filcrypto.h:1292
	REGISTEREDUPDATEPROOFSTACKEDDRG2KIBV1 = C.REGISTERED_UPDATE_PROOF_STACKED_DRG2_KI_B_V1
	// REGISTEREDUPDATEPROOFSTACKEDDRG8MIBV1 as declared in filecoin-ffi/filcrypto.h:1294
	REGISTEREDUPDATEPROOFSTACKEDDRG8MIBV1 = C.REGISTERED_UPDATE_PROOF_STACKED_DRG8_MI_B_V1
	// REGISTEREDUPDATEPROOFSTACKEDDRG512MIBV1 as declared in filecoin-ffi/filcrypto.h:1296
	REGISTEREDUPDATEPROOFSTACKEDDRG512MIBV1 = C.REGISTERED_UPDATE_PROOF_STACKED_DRG512_MI_B_V1
	// REGISTEREDUPDATEPROOFSTACKEDDRG32GIBV1 as declared in filecoin-ffi/filcrypto.h:1298
	REGISTEREDUPDATEPROOFSTACKEDDRG32GIBV1 = C.REGISTERED_UPDATE_PROOF_STACKED_DRG32_GI_B_V1
	// REGISTEREDUPDATEPROOFSTACKEDDRG64GIBV1 as declared in filecoin-ffi/filcrypto.h:1300
	REGISTEREDUPDATEPROOFSTACKEDDRG64GIBV1 = C.REGISTERED_UPDATE_PROOF_STACKED_DRG64_GI_B_V1
)
