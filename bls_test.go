package ffi

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/filecoin-project/filecoin-ffi/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeterministicPrivateKeyGeneration(t *testing.T) {
	for i := 0; i < 10000; i++ {
		var xs [32]byte
		n, err := rand.Read(xs[:])
		require.NoError(t, err)
		require.Equal(t, len(xs), n)

		first := PrivateKeyGenerateWithSeed(xs)
		secnd := PrivateKeyGenerateWithSeed(xs)

		assert.Equal(t, first, secnd)
	}
}

func TestBLSSigningAndVerification(t *testing.T) {
	// generate private keys
	fooPrivateKey := PrivateKeyGenerate()
	barPrivateKey := PrivateKeyGenerate()

	// get the public keys for the private keys
	fooPublicKey := PrivateKeyPublicKey(fooPrivateKey)
	barPublicKey := PrivateKeyPublicKey(barPrivateKey)

	// make messages to sign with the keys
	fooMessage := types.Message("hello foo")
	barMessage := types.Message("hello bar!")

	// calculate the digests of the messages
	fooDigest := Hash(fooMessage)
	barDigest := Hash(barMessage)

	// get the signature when signing the messages with the private keys
	fooSignature := PrivateKeySign(fooPrivateKey, fooMessage)
	barSignature := PrivateKeySign(barPrivateKey, barMessage)

	// get the aggregateSign
	aggregateSign := Aggregate([]types.Signature{*fooSignature, *barSignature})

	// assert the foo message was signed with the foo key
	assert.True(t, Verify(fooSignature, []types.Digest{fooDigest}, []types.PublicKey{*fooPublicKey}))

	// assert the bar message was signed with the bar key
	assert.True(t, Verify(barSignature, []types.Digest{barDigest}, []types.PublicKey{*barPublicKey}))

	// assert the foo message was signed with the foo key
	assert.True(t, HashVerify(fooSignature, []types.Message{fooMessage}, []types.PublicKey{*fooPublicKey}))

	// assert the bar message was signed with the bar key
	assert.True(t, HashVerify(barSignature, []types.Message{barMessage}, []types.PublicKey{*barPublicKey}))

	// assert the foo message was not signed by the bar key
	assert.False(t, Verify(fooSignature, []types.Digest{fooDigest}, []types.PublicKey{*barPublicKey}))

	// assert the bar/foo message was not signed by the foo/bar key
	assert.False(t, Verify(barSignature, []types.Digest{barDigest}, []types.PublicKey{*fooPublicKey}))
	assert.False(t, Verify(barSignature, []types.Digest{fooDigest}, []types.PublicKey{*barPublicKey}))
	assert.False(t, Verify(fooSignature, []types.Digest{barDigest}, []types.PublicKey{*fooPublicKey}))

	//assert the foo and bar message was signed with the foo and bar key
	assert.True(t, HashVerify(aggregateSign, []types.Message{fooMessage, barMessage}, []types.PublicKey{*fooPublicKey, *barPublicKey}))

	//assert the bar and foo message was not signed by the foo and bar key
	assert.False(t, HashVerify(aggregateSign, []types.Message{fooMessage, barMessage}, []types.PublicKey{*fooPublicKey}))
}

func BenchmarkBLSVerify(b *testing.B) {
	priv := PrivateKeyGenerate()

	msg := types.Message("this is a message that i will be signing")
	digest := Hash(msg)

	sig := PrivateKeySign(priv, msg)
	// fmt.Println("SIG SIZE: ", len(sig))
	// fmt.Println("SIG: ", sig)
	pubk := PrivateKeyPublicKey(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(sig, []types.Digest{digest}, []types.PublicKey{*pubk}) {
			b.Fatal("failed to verify")
		}
	}
}

func TestBlsAggregateErrors(t *testing.T) {
	t.Run("no signatures", func(t *testing.T) {
		var empty []types.Signature
		out := Aggregate(empty)
		require.Nil(t, out)
	})

	t.Run("nil signatures", func(t *testing.T) {
		out := Aggregate(nil)
		require.Nil(t, out)
	})
}

func BenchmarkBLSVerifyBatch(b *testing.B) {
	b.Run("10", benchmarkBLSVerifyBatchSize(10))
	b.Run("50", benchmarkBLSVerifyBatchSize(50))
	b.Run("100", benchmarkBLSVerifyBatchSize(100))
	b.Run("300", benchmarkBLSVerifyBatchSize(300))
	b.Run("1000", benchmarkBLSVerifyBatchSize(1000))
	b.Run("4000", benchmarkBLSVerifyBatchSize(4000))
}

func benchmarkBLSVerifyBatchSize(size int) func(b *testing.B) {
	return func(b *testing.B) {
		var digests []types.Digest
		var sigs []types.Signature
		var pubks []types.PublicKey
		for i := 0; i < size; i++ {
			msg := types.Message(fmt.Sprintf("cats cats cats cats %d %d %d dogs", i, i, i))
			digests = append(digests, Hash(msg))
			priv := PrivateKeyGenerate()
			sig := PrivateKeySign(priv, msg)
			sigs = append(sigs, *sig)
			pubk := PrivateKeyPublicKey(priv)
			pubks = append(pubks, *pubk)
		}

		t := time.Now()
		agsig := Aggregate(sigs)
		fmt.Println("Aggregate took: ", time.Since(t))

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !Verify(agsig, digests, pubks) {
				b.Fatal("failed to verify")
			}
		}
	}
}

func BenchmarkBLSHashAndVerify(b *testing.B) {
	priv := PrivateKeyGenerate()

	msg := types.Message("this is a message that i will be signing")
	sig := PrivateKeySign(priv, msg)

	// fmt.Println("SIG SIZE: ", len(sig))
	// fmt.Println("SIG: ", sig)
	pubk := PrivateKeyPublicKey(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		digest := Hash(msg)
		if !Verify(sig, []types.Digest{digest}, []types.PublicKey{*pubk}) {
			b.Fatal("failed to verify")
		}
	}
}

func BenchmarkBLSHashVerify(b *testing.B) {
	priv := PrivateKeyGenerate()

	msg := types.Message("this is a message that i will be signing")
	sig := PrivateKeySign(priv, msg)

	// fmt.Println("SIG SIZE: ", len(sig))
	// fmt.Println("SIG: ", sig)
	pubk := PrivateKeyPublicKey(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !HashVerify(sig, []types.Message{msg}, []types.PublicKey{*pubk}) {
			b.Fatal("failed to verify")
		}
	}
}
