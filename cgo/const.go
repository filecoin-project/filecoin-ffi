package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

const (
	FCPResponseStatusNoError           = C.F_C_P_RESPONSE_STATUS_NO_ERROR
	FCPResponseStatusUnclassifiedError = C.F_C_P_RESPONSE_STATUS_UNCLASSIFIED_ERROR
	FCPResponseStatusCallerError       = C.F_C_P_RESPONSE_STATUS_CALLER_ERROR
	FCPResponseStatusReceiverError     = C.F_C_P_RESPONSE_STATUS_RECEIVER_ERROR
)

const (
	RegisteredSealProofStackedDrg2KiBV1                              = C.REGISTERED_SEAL_PROOF_STACKED_DRG2_KI_B_V1
	RegisteredSealProofStackedDrg8MiBV1                              = C.REGISTERED_SEAL_PROOF_STACKED_DRG8_MI_B_V1
	RegisteredSealProofStackedDrg512MiBV1                            = C.REGISTERED_SEAL_PROOF_STACKED_DRG512_MI_B_V1
	RegisteredSealProofStackedDrg32GiBV1                             = C.REGISTERED_SEAL_PROOF_STACKED_DRG32_GI_B_V1
	RegisteredSealProofStackedDrg64GiBV1                             = C.REGISTERED_SEAL_PROOF_STACKED_DRG64_GI_B_V1
	RegisteredSealProofStackedDrg2KiBV11                             = C.REGISTERED_SEAL_PROOF_STACKED_DRG2_KI_B_V1_1
	RegisteredSealProofStackedDrg8MiBV11                             = C.REGISTERED_SEAL_PROOF_STACKED_DRG8_MI_B_V1_1
	RegisteredSealProofStackedDrg512MiBV11                           = C.REGISTERED_SEAL_PROOF_STACKED_DRG512_MI_B_V1_1
	RegisteredSealProofStackedDrg32GiBV11                            = C.REGISTERED_SEAL_PROOF_STACKED_DRG32_GI_B_V1_1
	RegisteredSealProofStackedDrg64GiBV11                            = C.REGISTERED_SEAL_PROOF_STACKED_DRG64_GI_B_V1_1
	RegisteredSealProofStackedDrg2KiBV11_Feat_SyntheticPoRep         = C.REGISTERED_SEAL_PROOF_STACKED_DRG2_KI_B_V1_1__FEAT__SYNTHETIC_PO_REP
	RegisteredSealProofStackedDrg8MiBV11_Feat_SyntheticPoRep         = C.REGISTERED_SEAL_PROOF_STACKED_DRG8_MI_B_V1_1__FEAT__SYNTHETIC_PO_REP
	RegisteredSealProofStackedDrg512MiBV11_Feat_SyntheticPoRep       = C.REGISTERED_SEAL_PROOF_STACKED_DRG512_MI_B_V1_1__FEAT__SYNTHETIC_PO_REP
	RegisteredSealProofStackedDrg32GiBV11_Feat_SyntheticPoRep        = C.REGISTERED_SEAL_PROOF_STACKED_DRG32_GI_B_V1_1__FEAT__SYNTHETIC_PO_REP
	RegisteredSealProofStackedDrg64GiBV11_Feat_SyntheticPoRep        = C.REGISTERED_SEAL_PROOF_STACKED_DRG64_GI_B_V1_1__FEAT__SYNTHETIC_PO_REP
	RegisteredSealProofStackedDrg2KiBV1_2_Feat_NonInteractivePoRep   = C.REGISTERED_SEAL_PROOF_STACKED_DRG2_KI_B_V1_2__FEAT__NON_INTERACTIVE_PO_REP
	RegisteredSealProofStackedDrg8MiBV1_2_Feat_NonInteractivePoRep   = C.REGISTERED_SEAL_PROOF_STACKED_DRG8_MI_B_V1_2__FEAT__NON_INTERACTIVE_PO_REP
	RegisteredSealProofStackedDrg512MiBV1_2_Feat_NonInteractivePoRep = C.REGISTERED_SEAL_PROOF_STACKED_DRG512_MI_B_V1_2__FEAT__NON_INTERACTIVE_PO_REP
	RegisteredSealProofStackedDrg32GiBV1_2_Feat_NonInteractivePoRep  = C.REGISTERED_SEAL_PROOF_STACKED_DRG32_GI_B_V1_2__FEAT__NON_INTERACTIVE_PO_REP
	RegisteredSealProofStackedDrg64GiBV1_2_Feat_NonInteractivePoRep  = C.REGISTERED_SEAL_PROOF_STACKED_DRG64_GI_B_V1_2__FEAT__NON_INTERACTIVE_PO_REP
)

const (
	RegisteredAggregationProofSnarkPackV1 = C.REGISTERED_AGGREGATION_PROOF_SNARK_PACK_V1
	RegisteredAggregationProofSnarkPackV2 = C.REGISTERED_AGGREGATION_PROOF_SNARK_PACK_V2
)

const (
	RegisteredPoStProofStackedDrgWinning2KiBV1    = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING2_KI_B_V1
	RegisteredPoStProofStackedDrgWinning8MiBV1    = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING8_MI_B_V1
	RegisteredPoStProofStackedDrgWinning512MiBV1  = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING512_MI_B_V1
	RegisteredPoStProofStackedDrgWinning32GiBV1   = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING32_GI_B_V1
	RegisteredPoStProofStackedDrgWinning64GiBV1   = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINNING64_GI_B_V1
	RegisteredPoStProofStackedDrgWindow2KiBV1     = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW2_KI_B_V1
	RegisteredPoStProofStackedDrgWindow8MiBV1     = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW8_MI_B_V1
	RegisteredPoStProofStackedDrgWindow512MiBV1   = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW512_MI_B_V1
	RegisteredPoStProofStackedDrgWindow32GiBV1    = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW32_GI_B_V1
	RegisteredPoStProofStackedDrgWindow64GiBV1    = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW64_GI_B_V1
	RegisteredPoStProofStackedDrgWindow2KiBV1_1   = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW2_KI_B_V1_1
	RegisteredPoStProofStackedDrgWindow8MiBV1_1   = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW8_MI_B_V1_1
	RegisteredPoStProofStackedDrgWindow512MiBV1_1 = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW512_MI_B_V1_1
	RegisteredPoStProofStackedDrgWindow32GiBV1_1  = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW32_GI_B_V1_1
	RegisteredPoStProofStackedDrgWindow64GiBV1_1  = C.REGISTERED_PO_ST_PROOF_STACKED_DRG_WINDOW64_GI_B_V1_1
)

const (
	RegisteredUpdateProofStackedDrg2KiBV1   = C.REGISTERED_UPDATE_PROOF_STACKED_DRG2_KI_B_V1
	RegisteredUpdateProofStackedDrg8MiBV1   = C.REGISTERED_UPDATE_PROOF_STACKED_DRG8_MI_B_V1
	RegisteredUpdateProofStackedDrg512MiBV1 = C.REGISTERED_UPDATE_PROOF_STACKED_DRG512_MI_B_V1
	RegisteredUpdateProofStackedDrg32GiBV1  = C.REGISTERED_UPDATE_PROOF_STACKED_DRG32_GI_B_V1
	RegisteredUpdateProofStackedDrg64GiBV1  = C.REGISTERED_UPDATE_PROOF_STACKED_DRG64_GI_B_V1
)
