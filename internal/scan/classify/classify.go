package classify

import "portscanner/internal/scan/fingerprint"

func OS(fp fingerprint.Fingerprint) string {
	bestScore := 0
	bestName := "Unknown"

	for _, sig := range signatures {
		score := score(fp, sig)
		if score > bestScore {
			bestScore = score
			bestName = sig.Name
		}
	}

	if bestScore < 25 {
		return "Unknown"
	}
	return bestName
}

func score(fp fingerprint.Fingerprint, sig Signature) int {
	s := 0

	if fp.Window >= sig.WinMin && fp.Window <= sig.WinMax {
		s += 30
	} else if abs(fp.Window-(sig.WinMin+sig.WinMax)/2) <= 5000 {
		s += 10
	}

	if sig.MSS == 0 {
		s += 15
	} else if fp.MSS == sig.MSS {
		s += 15
	}

	if fp.WScale == sig.WScale {
		s += 5
	}
	if fp.SACK == sig.SACK {
		s += 5
	}
	if fp.Timestamps == sig.Timestamps {
		s += 5
	}
	if fp.ECN == sig.ECN {
		s += 5
	}

	return s * sig.Confidence / 100
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
