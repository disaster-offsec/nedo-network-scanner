package fingerprint

// Fingerprint holds TCP-level parameters observed on a connection.
type Fingerprint struct {
	Window     int
	MSS        int
	WScale     bool
	SACK       bool
	Timestamps bool
	ECN        bool
}
