package cli

import (
	"errors"
	"sort"
	"slices"
	"strconv"
	"strings"
)

func handleToken(tok string, ports []int, warnings []string) ([]int, []string) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return ports, warnings
	}

	if strings.Contains(tok, "-") {
		parts := strings.SplitN(tok, "-", 2)
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			warnings = append(warnings, "malformed range: "+tok)
			return ports, warnings
		}
		if start < 1 || end > 65535 || start > end {
			warnings = append(warnings, "invalid range: "+tok)
			return ports, warnings
		}
		for p := start; p <= end; p++ {
			ports = append(ports, p)
		}
		return ports, warnings
	}

	p, err := strconv.Atoi(tok)
	if err != nil {
		warnings = append(warnings, "invalid port: "+tok)
		return ports, warnings
	}
	if p < 1 || p > 65535 {
		warnings = append(warnings, "port out of range: "+tok)
		return ports, warnings
	}
	ports = append(ports, p)
	return ports, warnings
}

func sortUnique(ports []int) []int {
	sort.Ints(ports)
	return slices.Compact(ports)
}

func parsePorts(spec string) ([]int, []string, error) {
	if spec == "-" {
		ports := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports, nil, nil
	}

	tokens := strings.Split(spec, ",")
	var ports []int
	var warnings []string
	for _, tok := range tokens {
		ports, warnings = handleToken(tok, ports, warnings)
	}

	ports = sortUnique(ports)
	if len(ports) == 0 {
		return nil, warnings, errors.New("no valid ports")
	}
	return ports, warnings, nil
}
