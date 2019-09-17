package sealed_sector_health

// Health represents the healthiness of a sector managed by a
// sector builder.
type Health int

const (
	Unknown         Health = iota
	Ok                     // everything is fine
	InvalidChecksum        // sector exists, but checksum is invalid
	InvalidLength          // sector exists, but length is incorrect
	Missing                // sector no longer exists
)

var labels = [...]string{
	"Unknown",
	"Ok",
	"InvalidChecksum",
	"InvalidLength",
	"Missing",
}

func (el Health) String() string {
	return labels[el]
}
