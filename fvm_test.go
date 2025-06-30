package ffi

import (
	"math"
	"testing"

	"github.com/filecoin-project/go-state-types/big"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
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

func splitBigInt(i big.Int) (hi uint64, lo uint64, err error) {
	if i.Sign() < 0 {
		return 0, 0, xerrors.Errorf("negative number: %s", i)
	}
	words := i.Bits()
	switch len(words) {
	case 2:
		hi = uint64(words[1])
		fallthrough
	case 1:
		lo = uint64(words[0])
	case 0:
	default:
		return 0, 0, xerrors.Errorf("exceeds max bigint size: %s", i)
	}
	return hi, lo, nil
}
