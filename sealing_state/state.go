package sealing_state

// State communicates the state of the sector with respect to sealing.
type State int

const (
	Unknown             State = iota
	AcceptingPieces           // sector is still accepting user data
	Committed                 // sector has been committed to a ticket and seed
	Committing                // sector is being committed
	CommittingPaused          // sector was committing, but now paused
	Failed                    // sector failed during pre-commit or commit
	FullyPacked               // sector is no longer accepting pieces; is fully packed
	PreCommitted              // sector has been pre-committed to a ticket
	PreCommitting             // sector is pre-committing
	PreCommittingPaused       // sector was paused during pre-commit
)

var labels = [...]string{
	"Unknown",
	"AcceptingPieces",
	"Committed",
	"Committing",
	"CommittingPaused",
	"Failed",
	"FullyPacked",
	"PreCommitted",
	"PreCommitting",
	"PreCommittingPaused",
}

func (el State) String() string {
	return labels[el]
}
