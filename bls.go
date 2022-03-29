//go:build cgo
// +build cgo

package ffi

// #cgo LDFLAGS: ${SRCDIR}/libfilcrypto.a
// #cgo pkg-config: ${SRCDIR}/filcrypto.pc
// #include "./filcrypto.h"
import "C"
import (
	"github.com/filecoin-project/filecoin-ffi/cgo"
)

// Hash computes the digest of a message
func Hash(message Message) *Digest {
	messageC := cgo.AsSliceRefUint8(message)
	resp := cgo.Hash(messageC)
	if resp == nil {
		return nil
	}

	defer resp.Destroy()

	var out Digest
	copy(out[:], resp.Digest())
	return &out
}

// Verify verifies that a signature is the aggregated signature of digests - pubkeys
func Verify(signature *Signature, digests []Digest, publicKeys []*PublicKey) bool {
	// prep data
	flattenedDigests := make([]byte, DigestBytes*len(digests))
	for idx, digest := range digests {
		copy(flattenedDigests[(DigestBytes*idx):(DigestBytes*(1+idx))], digest[:])
	}

	flattenedPublicKeys := make([]byte, PublicKeyBytes*len(publicKeys))
	for idx, publicKey := range publicKeys {
		copy(flattenedPublicKeys[(PublicKeyBytes*idx):(PublicKeyBytes*(1+idx))], publicKey[:])
	}

	isValid := cgo.Verify(
		cgo.AsSliceRefUint8(signature[:]),
		cgo.AsSliceRefUint8(flattenedDigests),
		cgo.AsSliceRefUint8(flattenedPublicKeys),
	)

	return isValid > 0
}

// HashVerify verifies that a signature is the aggregated signature of hashed messages.
func HashVerify(signature *Signature, messages []Message, publicKeys []*PublicKey) bool {
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

	isValid := cgo.HashVerify(
		cgo.AsSliceRefUint8(signature[:]),
		cgo.AsSliceRefUint8(flattenedMessages),
		cgo.AsSliceRefUint(messagesSizes),
		cgo.AsSliceRefUint8(flattenedPublicKeys),
	)

	return isValid > 0
}

// Aggregate aggregates signatures together into a new signature. If the
// provided signatures cannot be aggregated (due to invalid input or an
// an operational error), Aggregate will return nil.
func Aggregate(signatures []*Signature) *Signature {
	// prep data
	flattenedSignatures := make([]byte, SignatureBytes*len(signatures))
	for idx, sig := range signatures {
		copy(flattenedSignatures[(SignatureBytes*idx):(SignatureBytes*(1+idx))], sig[:])
	}

	resp := cgo.Aggregate(cgo.AsSliceRefUint8(flattenedSignatures))
	if resp == nil {
		return nil
	}

	defer resp.Destroy()

	var out Signature
	copy(out[:], resp.Signature())
	return &out
}

// PrivateKeyGenerate generates a private key
func PrivateKeyGenerate() *PrivateKey {
	resp := cgo.PrivateKeyGenerate()
	if resp == nil {
		return nil
	}

	defer resp.Destroy()

	var out PrivateKey
	copy(out[:], resp.PrivateKey())
	return &out
}

// PrivateKeyGenerate generates a private key in a predictable manner.
func PrivateKeyGenerateWithSeed(seed PrivateKeyGenSeed) *PrivateKey {
	ary := cgo.AsByteArray32(seed[:])
	resp := cgo.PrivateKeyGenerateWithSeed(&ary)
	if resp == nil {
		return nil
	}

	defer resp.Destroy()

	var out PrivateKey
	copy(out[:], resp.PrivateKey())
	return &out
}

// PrivateKeySign signs a message
func PrivateKeySign(privateKey *PrivateKey, message Message) *Signature {
	resp := cgo.PrivateKeySign(cgo.AsSliceRefUint8(privateKey[:]), cgo.AsSliceRefUint8(message))
	if resp == nil {
		return nil
	}

	defer resp.Destroy()

	var signature Signature
	copy(signature[:], resp.Signature())
	return &signature
}

// PrivateKeyPublicKey gets the public key for a private key
func PrivateKeyPublicKey(privateKey *PrivateKey) *PublicKey {
	resp := cgo.PrivateKeyPublicKey(cgo.AsSliceRefUint8(privateKey[:]))
	if resp == nil {
		return nil
	}

	defer resp.Destroy()

	var publicKey PublicKey
	copy(publicKey[:], resp.PublicKey())
	return &publicKey
}

// CreateZeroSignature creates a zero signature, used as placeholder in filecoin.
func CreateZeroSignature() *Signature {
	resp := cgo.CreateZeroSignature()
	if resp == nil {
		return nil
	}

	defer resp.Destroy()

	var sig Signature
	copy(sig[:], resp.Signature())

	return &sig
}
