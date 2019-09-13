package sealed_sector_health

// Health represents the healthiness of a sector managed by a
// sector builder.
type Health int

const (
	Unknown              Health = iota
	Ok                          // everything is fine
	ErrorInvalidChecksum        // sector exists, but checksum is invalid
	ErrorInvalidLength          // sector exists, but length is incorrect
	ErrorMissing                // sector no longer exists
)

var labels = [...]string{
	"Unknown",
	"Ok",
	"ErrorInvalidChecksum",
	"ErrorInvalidLength",
	"ErrorMissing",
}

func (el Health) String() string {
	return labels[el]
}
