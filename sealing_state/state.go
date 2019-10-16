package sealing_state

// State communicates the state of the sector with respect to sealing.
type State int

const (
	Unknown         State = iota
	Pending               // sector is still accepting user data
	Failed                // sealing failed
	Sealing               // sector is currently being sealed
	Sealed                // sector has been sealed successfully
	Paused                // sector sealing has been paused and can be resumed
	ReadyForSealing       // staged sector is full and is ready to seal
)

var labels = [...]string{
	"Unknown",
	"Pending",
	"Failed",
	"Sealing",
	"Sealed",
	"Paused",
	"ReadyForSealing",
}

func (el State) String() string {
	return labels[el]
}
