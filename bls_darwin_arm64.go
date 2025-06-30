//go:build darwin && arm64 && cgo && !ffi_source

package ffi

import (
	"github.com/filecoin-project/filecoin-ffi/prebuilt/darwin-arm64"
	. "github.com/filecoin-project/filecoin-ffi/types"
)

// Hash computes the digest of a message
func Hash(message Message) Digest {
	return prebuilt.Hash(message)
}

// Verify verifies that a signature is the aggregated signature of digests - pubkeys
func Verify(signature *Signature, digests []Digest, publicKeys []PublicKey) bool {
	return prebuilt.Verify(signature, digests, publicKeys)
}

// HashVerify verifies that a signature is the aggregated signature of hashed messages.
func HashVerify(signature *Signature, messages []Message, publicKeys []PublicKey) bool {
	return prebuilt.HashVerify(signature, messages, publicKeys)
}

// Aggregate aggregates signatures together into a new signature. If the
// provided signatures cannot be aggregated (due to invalid input or an
// an operational error), Aggregate will return nil.
func Aggregate(signatures []Signature) *Signature {
	return prebuilt.Aggregate(signatures)
}

// PrivateKeyGenerate generates a private key
func PrivateKeyGenerate() PrivateKey {
	return prebuilt.PrivateKeyGenerate()
}

// PrivateKeyGenerate generates a private key in a predictable manner.
func PrivateKeyGenerateWithSeed(seed PrivateKeyGenSeed) PrivateKey {

	return prebuilt.PrivateKeyGenerateWithSeed(seed)
}

// PrivateKeySign signs a message
func PrivateKeySign(privateKey PrivateKey, message Message) *Signature {
	return prebuilt.PrivateKeySign(privateKey, message)
}

// PrivateKeyPublicKey gets the public key for a private key
func PrivateKeyPublicKey(privateKey PrivateKey) *PublicKey {
	return prebuilt.PrivateKeyPublicKey(privateKey)
}

// CreateZeroSignature creates a zero signature, used as placeholder in filecoin.
func CreateZeroSignature() Signature {
	return prebuilt.CreateZeroSignature()
}
