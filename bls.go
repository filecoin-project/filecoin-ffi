//go:build cgo
// +build cgo

package ffi

// #cgo linux LDFLAGS: ${SRCDIR}/libfilcrypto.a -Wl,-unresolved-symbols=ignore-all
// #cgo darwin LDFLAGS: ${SRCDIR}/libfilcrypto.a -Wl,-undefined,dynamic_lookup
// #cgo pkg-config: ${SRCDIR}/filcrypto.pc
// #include "./filcrypto.h"
import "C"
import (
	"github.com/filecoin-project/filecoin-ffi/cgo"
)

// Hash computes the digest of a message
func Hash(message Message) Digest {
	digest := cgo.Hash(cgo.AsSliceRefUint8(message))
	if digest == nil {
		return Digest{}
	}
	return *digest
}

// Verify verifies that a signature is the aggregated signature of digests - pubkeys
func Verify(signature *Signature, digests []Digest, publicKeys []PublicKey) bool {
	// prep data
	flattenedDigests := make([]byte, DigestBytes*len(digests))
	for idx, digest := range digests {
		copy(flattenedDigests[(DigestBytes*idx):(DigestBytes*(1+idx))], digest[:])
	}

	flattenedPublicKeys := make([]byte, PublicKeyBytes*len(publicKeys))
	for idx, publicKey := range publicKeys {
		copy(flattenedPublicKeys[(PublicKeyBytes*idx):(PublicKeyBytes*(1+idx))], publicKey[:])
	}

	return cgo.Verify(
		cgo.AsSliceRefUint8(signature[:]),
		cgo.AsSliceRefUint8(flattenedDigests),
		cgo.AsSliceRefUint8(flattenedPublicKeys),
	)
}

// HashVerify verifies that a signature is the aggregated signature of hashed messages.
func HashVerify(signature *Signature, messages []Message, publicKeys []PublicKey) bool {
	var flattenedMessages []byte
	messagesSizes := make([]uint, len(messages))
	for idx := range messages {
		flattenedMessages = append(flattenedMessages, messages[idx]...)
		messagesSizes[idx] = uint(len(messages[idx]))
	}

	flattenedPublicKeys := make([]byte, PublicKeyBytes*len(publicKeys))
	for idx, publicKey := range publicKeys {
		copy(flattenedPublicKeys[(PublicKeyBytes*idx):(PublicKeyBytes*(1+idx))], publicKey[:])
	}

	return cgo.HashVerify(
		cgo.AsSliceRefUint8(signature[:]),
		cgo.AsSliceRefUint8(flattenedMessages),
		cgo.AsSliceRefUint(messagesSizes),
		cgo.AsSliceRefUint8(flattenedPublicKeys),
	)
}

// Aggregate aggregates signatures together into a new signature. If the
// provided signatures cannot be aggregated (due to invalid input or an
// an operational error), Aggregate will return nil.
func Aggregate(signatures []Signature) *Signature {
	// prep data
	flattenedSignatures := make([]byte, SignatureBytes*len(signatures))
	for idx, sig := range signatures {
		copy(flattenedSignatures[(SignatureBytes*idx):(SignatureBytes*(1+idx))], sig[:])
	}

	return cgo.Aggregate(cgo.AsSliceRefUint8(flattenedSignatures))
}

// PrivateKeyGenerate generates a private key
func PrivateKeyGenerate() PrivateKey {
	key := cgo.PrivateKeyGenerate()
	if key == nil {
		return PrivateKey{}
	}
	return *key
}

// PrivateKeyGenerate generates a private key in a predictable manner.
func PrivateKeyGenerateWithSeed(seed PrivateKeyGenSeed) PrivateKey {
	ary := cgo.AsByteArray32(seed[:])
	key := cgo.PrivateKeyGenerateWithSeed(&ary)
	if key == nil {
		return PrivateKey{}
	}
	return *key
}

// PrivateKeySign signs a message
func PrivateKeySign(privateKey PrivateKey, message Message) *Signature {
	return cgo.PrivateKeySign(cgo.AsSliceRefUint8(privateKey[:]), cgo.AsSliceRefUint8(message))
}

// PrivateKeyPublicKey gets the public key for a private key
func PrivateKeyPublicKey(privateKey PrivateKey) *PublicKey {
	return cgo.PrivateKeyPublicKey(cgo.AsSliceRefUint8(privateKey[:]))
}

// CreateZeroSignature creates a zero signature, used as placeholder in filecoin.
func CreateZeroSignature() Signature {
	signature := cgo.CreateZeroSignature()
	if signature == nil {
		return Signature{}
	}
	return *signature
}
