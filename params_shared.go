package sectorbuilder

// /////
// Proofs

// 1 / n
const SectorChallengeRatioDiv = 25

const MaxFallbackPostChallengeCount = 10

// extracted from lotus/chain/types/blockheader
func ElectionPostChallengeCount(sectors uint64, faults int) uint64 {
	if sectors == 0 {
		return 0
	}
	// ceil(sectors / SectorChallengeRatioDiv)
	return (sectors-uint64(faults)-1)/SectorChallengeRatioDiv + 1
}
