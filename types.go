package ffi

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
