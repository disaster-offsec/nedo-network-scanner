package classify

type Signature struct {
	WinMin, WinMax  int
	MSS             int
	WScale          bool
	SACK            bool
	Timestamps      bool
	ECN             bool
	Name            string
	Confidence      int
}

var signatures = []Signature{
	// Linux
	{60000, 66000, 0,    true, true, true,  false, "Linux (possibly)", 80},
	{42000, 43000, 1460, true, true, true,  false, "Ubuntu/Debian Linux", 95},
	{40000, 44000, 0,    true, true, true,  false, "Linux", 90},
	{5800,  5900,  1460, false, true, false, false, "Linux 2.4-2.6", 85},

	// macOS
	{65535, 65535, 1460, true, true, true, false, "macOS", 70},

	// Windows
	{8192,  8192,  1460, true, true, false, false, "Windows 7/8/10", 85},
	{65535, 65535, 1460, true, true, false, false, "Windows 10", 80},
	{16000, 17000, 1460, true, true, false, false, "Windows Server", 75},

	// BSD
	{65000, 66000, 1460, false, false, false, false, "FreeBSD", 70},

	// Others
	{16384, 16384, 1460, false, false, false, false, "OpenBSD", 65},
	{4128,  4128,  1460, false, false, false, false, "Cisco IOS", 55},
}
