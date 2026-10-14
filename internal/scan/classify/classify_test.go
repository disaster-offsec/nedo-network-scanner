package classify

import (
	"testing"

	"portscanner/internal/scan/fingerprint"
)

func TestOS(t *testing.T) {
	cases := []struct {
		name string
		fp   fingerprint.Fingerprint
		want string
	}{
		{
			"linux ubuntu",
			fingerprint.Fingerprint{Window: 42500, MSS: 1460, WScale: true, SACK: true, Timestamps: true},
			"Ubuntu/Debian Linux",
		},
		{
			"windows 10",
			fingerprint.Fingerprint{Window: 65535, MSS: 1460, WScale: true, SACK: true, Timestamps: false},
			"Windows 10",
		},
		{
			"empty",
			fingerprint.Fingerprint{},
			"Unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := OS(tc.fp)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
