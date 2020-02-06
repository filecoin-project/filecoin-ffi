package ffi

import (
	"bytes"
	"encoding/json"
	"sort"
)

// BLS

// SignatureBytes is the length of a BLS signature
const SignatureBytes = 96

// PrivateKeyBytes is the length of a BLS private key
const PrivateKeyBytes = 32

// PublicKeyBytes is the length of a BLS public key
const PublicKeyBytes = 48

// DigestBytes is the length of a BLS message hash/digest
const DigestBytes = 96

// Signature is a compressed affine
type Signature [SignatureBytes]byte

// PrivateKey is a compressed affine
type PrivateKey [PrivateKeyBytes]byte

// PublicKey is a compressed affine
type PublicKey [PublicKeyBytes]byte

// Message is a byte slice
type Message []byte

// Digest is a compressed affine
type Digest [DigestBytes]byte

// Proofs

// SortedPublicSectorInfo is a slice of PublicSectorInfo sorted
// (lexicographically, ascending) by replica commitment (CommR).
type SortedPublicSectorInfo struct {
	f []PublicSectorInfo
}

// SortedPrivateSectorInfo is a slice of PrivateSectorInfo sorted
// (lexicographically, ascending) by replica commitment (CommR).
type SortedPrivateSectorInfo struct {
	f []PrivateSectorInfo
}

func NewSortedPublicSectorInfo(sectorInfo ...PublicSectorInfo) SortedPublicSectorInfo {
	fn := func(i, j int) bool {
		return bytes.Compare(sectorInfo[i].CommR[:], sectorInfo[j].CommR[:]) == -1
	}

	sort.Slice(sectorInfo[:], fn)

	return SortedPublicSectorInfo{
		f: sectorInfo,
	}
}

// Values returns the sorted PublicSectorInfo as a slice
func (s *SortedPublicSectorInfo) Values() []PublicSectorInfo {
	return s.f
}

// MarshalJSON JSON-encodes and serializes the SortedPublicSectorInfo.
func (s SortedPublicSectorInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.f)
}

// UnmarshalJSON parses the JSON-encoded byte slice and stores the result in the
// value pointed to by s.f. Note that this method allows for construction of a
// SortedPublicSectorInfo which violates its invariant (that its PublicSectorInfo are sorted
// in some defined way). Callers should take care to never provide a byte slice
// which would violate this invariant.
func (s *SortedPublicSectorInfo) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.f)
}

// NewSortedPrivateSectorInfo returns a SortedPrivateSectorInfo
func NewSortedPrivateSectorInfo(sectorInfo ...PrivateSectorInfo) SortedPrivateSectorInfo {
	fn := func(i, j int) bool {
		return bytes.Compare(sectorInfo[i].CommR[:], sectorInfo[j].CommR[:]) == -1
	}

	sort.Slice(sectorInfo[:], fn)

	return SortedPrivateSectorInfo{
		f: sectorInfo,
	}
}

// Values returns the sorted PrivateSectorInfo as a slice
func (s *SortedPrivateSectorInfo) Values() []PrivateSectorInfo {
	return s.f
}

// MarshalJSON JSON-encodes and serializes the SortedPrivateSectorInfo.
func (s SortedPrivateSectorInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.f)
}

func (s *SortedPrivateSectorInfo) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.f)
}

// SealTicket is required for the first step of Interactive PoRep.
type SealTicket struct {
	BlockHeight uint64
	TicketBytes [32]byte
}

// SealSeed is required for the second step of Interactive PoRep.
type SealSeed struct {
	BlockHeight uint64
	TicketBytes [32]byte
}

type Candidate struct {
	SectorID             uint64
	PartialTicket        [32]byte
	Ticket               [32]byte
	SectorChallengeIndex uint64
}

type PublicSectorInfo struct {
	SectorID uint64
	CommR    [CommitmentBytesLen]byte
}

type PrivateSectorInfo struct {
	SectorID         uint64
	CommR            [CommitmentBytesLen]byte
	CacheDirPath     string
	SealedSectorPath string
}

// CommitmentBytesLen is the number of bytes in a CommR, CommD, CommP, and CommRStar.
const CommitmentBytesLen = 32

// SealPreCommitOutput is used to acquire a seed from the chain for the second
// step of Interactive PoRep.
type SealPreCommitOutput struct {
	SectorID uint64
	CommD    [CommitmentBytesLen]byte
	CommR    [CommitmentBytesLen]byte
	Pieces   []PieceMetadata
	Ticket   SealTicket
}

// RawSealPreCommitOutput is used to acquire a seed from the chain for the
// second step of Interactive PoRep.
type RawSealPreCommitOutput struct {
	CommD [CommitmentBytesLen]byte
	CommR [CommitmentBytesLen]byte
}

// SealCommitOutput is produced by the second step of Interactive PoRep.
type SealCommitOutput struct {
	SectorID uint64
	CommD    [CommitmentBytesLen]byte
	CommR    [CommitmentBytesLen]byte
	Proof    []byte
	Pieces   []PieceMetadata
	Ticket   SealTicket
	Seed     SealSeed
}

// PieceMetadata represents a piece stored by the sector builder.
type PieceMetadata struct {
	Key   string
	Size  uint64
	CommP [CommitmentBytesLen]byte
}

// PublicPieceInfo is an on-chain tuple of CommP and aligned piece-size.
type PublicPieceInfo struct {
	Size  uint64
	CommP [CommitmentBytesLen]byte
}
