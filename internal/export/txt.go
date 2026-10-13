package export

import (
	"bytes"
	"fmt"
	"strings"
)

func ToTXT(r Report) ([]byte, error) {
	var buf bytes.Buffer
	
	buf.WriteString("=== Scan Configuration ===\n")
	fmt.Fprintf(&buf, "Target: %s\n", r.Target)
	fmt.Fprintf(&buf, "Total ports scanned: %d\n", r.TotalPorts)
	fmt.Fprintf(&buf, "Timestamp: %d\n\n", r.Timestamp.Unix())

	buf.WriteString("=== Open Ports ===\n")
	if len(r.Results) == 0 {
		buf.WriteString("No open ports found.\n")
	} else {
		replacer := strings.NewReplacer("\n", " ", "\r", "")
		for _, res := range r.Results {
			fmt.Fprintf(&buf, "Port: %d is OPEN", res.Port)
			banner := replacer.Replace(res.Banner)
			runes := []rune(banner)
			if len(runes) > 100 {
				banner = string(runes[:100]) + "..."
			}
			if banner != "" {
				fmt.Fprintf(&buf, " (banner: %s)", banner)
			}
			if len(res.OS) > 0 && res.OS != "Unknown" {
				fmt.Fprintf(&buf, " [OS: %s]", res.OS)
			}
			buf.WriteString("\n")
		}
	}
	
	fmt.Fprintf(&buf, "\nScan completed. %d/%d ports open.\n", len(r.Results), r.TotalPorts)
	return buf.Bytes(), nil
}
