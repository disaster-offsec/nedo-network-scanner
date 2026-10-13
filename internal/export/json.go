package export

import (
	"encoding/json"

	"portscanner/internal/scan"
)

type jsonScanInfo struct {
	Target     string `json:"target"`
	TotalPorts int    `json:"total_ports_scanned"`
	OpenCount  int    `json:"open_ports_count"`
	Timestamp  int64  `json:"timestamp"`
}

type jsonPort struct {
	Port   int    `json:"port"`
	IsOpen bool   `json:"is_open"`
	Banner string `json:"banner"`
	OS     string `json:"os"`
}

type jsonOutput struct {
	ScanInfo  jsonScanInfo `json:"scan_info"`
	OpenPorts []jsonPort   `json:"open_ports"`
}

func resultsToJSONPorts(results []scan.Result) []jsonPort {
	ports := make([]jsonPort, len(results))
	for i, res := range results {
		ports[i] = jsonPort{
			Port:   res.Port,
			IsOpen: res.IsOpen,
			Banner: res.Banner,
			OS:     res.OS,
		}
	}
	return ports
}

func ToJSON(r Report) ([]byte, error) {
	out := jsonOutput{
		ScanInfo: jsonScanInfo{
			Target:     r.Target,
			TotalPorts: r.TotalPorts,
			OpenCount:  len(r.Results),
			Timestamp:  r.Timestamp.Unix(),
		},
		OpenPorts: resultsToJSONPorts(r.Results),
	}
	return json.Marshal(out)
}
