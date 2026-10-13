package export

import (
	"bytes"
	"encoding/csv"
	"strconv"
	"strings"
)

func ToCSV(r Report) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"Target", "Timestamp", "TotalPorts", "Port", "Banner", "OS"})

	replacer := strings.NewReplacer("\n", " ", "\r", "")
	for _, res := range r.Results {
		row := []string{
			r.Target,
			strconv.FormatInt(r.Timestamp.Unix(), 10),
			strconv.Itoa(r.TotalPorts),
			strconv.Itoa(res.Port),
			replacer.Replace(res.Banner),
			res.OS,
		}
		w.Write(row)
	}
	w.Flush()
	
	if err := w.Error(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
