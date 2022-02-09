package ffi

import (
	"math"
	"testing"

	"github.com/filecoin-project/go-state-types/big"
	"github.com/stretchr/testify/require"
)

func checkSplitBigInt(t *testing.T, i big.Int, hi, lo uint64) {
	hiA, loA, err := splitBigInt(i)
	require.NoError(t, err)
	require.Equal(t, hi, hiA, "hi not equal")
	require.Equal(t, lo, loA, "lo not equal")
}

func TestSplitBigIntZero(t *testing.T) {
	checkSplitBigInt(t, big.Zero(), 0, 0)
}

func TestSplitBigIntOne(t *testing.T) {
	checkSplitBigInt(t, big.NewInt(1), 0, 1)
}

func TestSplitBigIntMax64(t *testing.T) {
	checkSplitBigInt(t, big.NewIntUnsigned(math.MaxUint64), 0, math.MaxUint64)
}

func TestSplitBigIntLarge(t *testing.T) {
	checkSplitBigInt(t, big.Mul(big.NewIntUnsigned(math.MaxUint64), big.NewInt(8)), 0x7, math.MaxUint64^0x7)
}
func TestSplitBigIntNeg(t *testing.T) {
	_, _, err := splitBigInt(big.NewInt(-1))
	require.Error(t, err)
}
