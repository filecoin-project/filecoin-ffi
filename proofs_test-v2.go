package ffi

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/filecoin-project/filecoin-ffi/generated_v2"

	"github.com/stretchr/testify/assert"

	commcid "github.com/filecoin-project/go-fil-commcid"

	// FIXME: local fork for upgrade testing
	//"github.com/filecoin-project/go-state-types/abi"
	"github.com/cryptonemo/go-state-types/abi"

	"github.com/stretchr/testify/require"
)

func TestRegisteredSealProofFunctionsV2(t *testing.T) {
	WorkflowRegisteredSealProofFunctionsV2(newTestingTeeHelper(t))
}

func TestRegisteredPoStProofFunctionsV2(t *testing.T) {
	WorkflowRegisteredPoStProofFunctionsV2(newTestingTeeHelper(t))
}

func TestProofsLifecycleV2(t *testing.T) {
	WorkflowProofsLifecycleV2(newTestingTeeHelper(t))
}

func TestGetGPUDevicesDoesNotProduceAnErrorV2(t *testing.T) {
	WorkflowGetGPUDevicesDoesNotProduceAnErrorV2(newTestingTeeHelper(t))
}

func TestGenerateWinningPoStSectorChallengeV2(t *testing.T) {
	WorkflowGenerateWinningPoStSectorChallengeV2(newTestingTeeHelper(t))
}

func TestGenerateWinningPoStSectorChallengeEdgeCaseV2(t *testing.T) {
	WorkflowGenerateWinningPoStSectorChallengeEdgeCaseV2(newTestingTeeHelper(t))
}

func TestJsonMarshalSymmetryV2(t *testing.T) {
	for i := 0; i < 100; i++ {
		xs := make([]publicSectorInfo, 10)
		for j := 0; j < 10; j++ {
			var x publicSectorInfo
			var commR [32]byte
			_, err := io.ReadFull(rand.Reader, commR[:])
			require.NoError(t, err)

			// commR is defined as 32 long above, error can be safely ignored
			x.SealedCID, _ = commcid.ReplicaCommitmentV1ToCID(commR[:])

			n, err := rand.Int(rand.Reader, big.NewInt(500))
			require.NoError(t, err)
			x.SectorNum = abi.SectorNumber(n.Uint64())
			xs[j] = x
		}
		toSerialize := newSortedPublicSectorInfo(xs...)

		serialized, err := toSerialize.MarshalJSON()
		require.NoError(t, err)

		var fromSerialized SortedPublicSectorInfo
		err = fromSerialized.UnmarshalJSON(serialized)
		require.NoError(t, err)

		require.Equal(t, toSerialize, fromSerialized)
	}
}

func TestDoesNotExhaustFileDescriptorsV2(t *testing.T) {
	m := 500         // loops
	n := uint64(508) // quantity of piece bytes

	for i := 0; i < m; i++ {
		// create a temporary file over which we'll compute CommP
		file, err := ioutil.TempFile("", "")
		if err != nil {
			panic(err)
		}

		// create a slice of random bytes (represents our piece)
		b := make([]byte, n)

		// load up our byte slice with random bytes
		if _, err = rand.Read(b); err != nil {
			panic(err)
		}

		// write buffer to temp file
		if _, err := bytes.NewBuffer(b).WriteTo(file); err != nil {
			panic(err)
		}

		// seek to beginning of file
		if _, err := file.Seek(0, 0); err != nil {
			panic(err)
		}

		if _, err = GeneratePieceCID(abi.RegisteredSealProof_StackedDrg2KiBV2, file.Name(), abi.UnpaddedPieceSize(n)); err != nil {
			panic(err)
		}

		if err = file.Close(); err != nil {
			panic(err)
		}
	}
}

func newTestingTeeHelperV2(t *testing.T) *testingTeeHelperV2 {
	return &testingTeeHelperV2{t: t}
}

type testingTeeHelperV2 struct {
	t *testing.T
}

func (tth *testingTeeHelperV2) RequireTrueV2(value bool, msgAndArgs ...interface{}) {
	require.True(tth.t, value, msgAndArgs)
}

func (tth *testingTeeHelperV2) RequireNoErrorV2(err error, msgAndArgs ...interface{}) {
	require.NoError(tth.t, err, msgAndArgs)
}

func (tth *testingTeeHelperV2) RequireEqualV2(expected interface{}, actual interface{}, msgAndArgs ...interface{}) {
	require.Equal(tth.t, expected, actual, msgAndArgs)
}

func (tth *testingTeeHelperV2) AssertNoErrorV2(err error, msgAndArgs ...interface{}) bool {
	return assert.NoError(tth.t, err, msgAndArgs)
}

func (tth *testingTeeHelperV2) AssertEqualV2(expected, actual interface{}, msgAndArgs ...interface{}) bool {
	return assert.Equal(tth.t, expected, actual, msgAndArgs)
}

func (tth *testingTeeHelperV2) AssertTrueV2(value bool, msgAndArgs ...interface{}) bool {
	return assert.True(tth.t, value, msgAndArgs)
}

func TestProofTypesV2(t *testing.T) {
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWinning2KiBV2, abi.RegisteredPoStProof_StackedDrgWinning2KiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWinning8MiBV2, abi.RegisteredPoStProof_StackedDrgWinning8MiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWinning512MiBV2, abi.RegisteredPoStProof_StackedDrgWinning512MiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWinning32GiBV2, abi.RegisteredPoStProof_StackedDrgWinning32GiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWinning64GiBV2, abi.RegisteredPoStProof_StackedDrgWinning64GiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWindow2KiBV2, abi.RegisteredPoStProof_StackedDrgWindow2KiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWindow8MiBV2, abi.RegisteredPoStProof_StackedDrgWindow8MiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWindow512MiBV2, abi.RegisteredPoStProof_StackedDrgWindow512MiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWindow32GiBV2, abi.RegisteredPoStProof_StackedDrgWindow32GiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredPoStProofStackedDrgWindow64GiBV2, abi.RegisteredPoStProof_StackedDrgWindow64GiBV2)

	assert.EqualValues(t, generated_v2.FilRegisteredSealProofStackedDrg2KiBV2, abi.RegisteredSealProof_StackedDrg2KiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredSealProofStackedDrg8MiBV2, abi.RegisteredSealProof_StackedDrg8MiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredSealProofStackedDrg512MiBV2, abi.RegisteredSealProof_StackedDrg512MiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredSealProofStackedDrg32GiBV2, abi.RegisteredSealProof_StackedDrg32GiBV2)
	assert.EqualValues(t, generated_v2.FilRegisteredSealProofStackedDrg64GiBV2, abi.RegisteredSealProof_StackedDrg64GiBV2)
}
