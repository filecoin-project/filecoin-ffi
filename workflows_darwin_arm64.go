//go:build darwin && arm64 && cgo && !ffi_source

package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/prebuilt/darwin-arm64"
)

func WorkflowProofsLifecycle(t TestHelper) {
	prebuilt.WorkflowProofsLifecycle(t)
}

func WorkflowGetGPUDevicesDoesNotProduceAnError(t TestHelper) {
	prebuilt.WorkflowGetGPUDevicesDoesNotProduceAnError(t)
}

func WorkflowRegisteredSealProofFunctions(t TestHelper) {
	prebuilt.WorkflowRegisteredSealProofFunctions(t)
}

func WorkflowRegisteredPoStProofFunctions(t TestHelper) {
	prebuilt.WorkflowRegisteredPoStProofFunctions(t)
}

func WorkflowGenerateWinningPoStSectorChallengeEdgeCase(t TestHelper) {
	prebuilt.WorkflowGenerateWinningPoStSectorChallengeEdgeCase(t)
}

func WorkflowGenerateWinningPoStSectorChallenge(t TestHelper) {
	prebuilt.WorkflowGenerateWinningPoStSectorChallenge(t)
}

type TestHelper = prebuilt.TestHelper
