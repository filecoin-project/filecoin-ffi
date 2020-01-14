package sectorbuilder

import (
	"context"
	"io"

	"github.com/filecoin-project/go-address"
)

type Interface interface {
	RateLimit() func()
	AddPiece(uint64, uint64, io.Reader, []uint64) (PublicPieceInfo, error)
	SectorSize() uint64
	AcquireSectorId() (uint64, error)
	Scrub(SortedPublicSectorInfo) []*Fault

	GenerateEPostCandidates(sectorInfo SortedPublicSectorInfo, challengeSeed [CommLen]byte, faults []uint64) ([]EPostCandidate, error)
	GenerateFallbackPoSt(SortedPublicSectorInfo, [CommLen]byte, []uint64) ([]EPostCandidate, []byte, error)
	ComputeElectionPoSt(sectorInfo SortedPublicSectorInfo, challengeSeed []byte, winners []EPostCandidate) ([]byte, error)

	SealPreCommit(context.Context, uint64, SealTicket, []PublicPieceInfo) (RawSealPreCommitOutput, error)
	SealCommit(context.Context, uint64, SealTicket, SealSeed, []PublicPieceInfo, RawSealPreCommitOutput) ([]byte, error)

	ReadPieceFromSealedSector(sectorID uint64, offset uint64, size uint64, ticket []byte, commD []byte) (io.ReadCloser, error)

	GetPath(string, string) (string, error)
	WorkerStats() WorkerStats
	AddWorker(context.Context, WorkerCfg) (<-chan WorkerTask, error)
	TaskDone(context.Context, uint64, SealRes) error
}

type Verifier interface {
	VerifyElectionPost(ctx context.Context, sectorSize uint64, sectorInfo SortedPublicSectorInfo, challengeSeed []byte, proof []byte, candidates []EPostCandidate, proverID address.Address) (bool, error)
	VerifyFallbackPost(ctx context.Context, sectorSize uint64, sectorInfo SortedPublicSectorInfo, challengeSeed []byte, proof []byte, candidates []EPostCandidate, proverID address.Address, faults uint64) (bool, error)
	VerifySeal(sectorSize uint64, commR, commD []byte, proverID address.Address, ticket []byte, seed []byte, sectorID uint64, proof []byte) (bool, error)
}

var _ Verifier = ProofVerifier
var _ Interface = &SectorBuilder{}
