// Package analysis provides deterministic assessment metadata. Scores describe
// supplied metrics; they are never inferred from a model's severity adjective.
package analysis

import (
	"errors"
	"math"
	"strings"
)

// BaseScore implements FIRST CVSS v3.1 base equations and integer Roundup.
// Source: https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
func BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) != 9 || parts[0] != "CVSS:3.1" {
		return 0, errors.New("supply CVSS:3.1 with exactly eight base metrics")
	}
	metrics := make(map[string]string)
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok || metrics[key] != "" {
			return 0, errors.New("invalid or duplicate CVSS metric")
		}
		metrics[key] = value
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44}, "UI": {"N": 0.85, "R": 0.62},
		"PR": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0, "L": 0.22, "H": 0.56}, "I": {"N": 0, "L": 0.22, "H": 0.56}, "A": {"N": 0, "L": 0.22, "H": 0.56},
	}
	if metrics["S"] != "U" && metrics["S"] != "C" {
		return 0, errors.New("invalid CVSS scope")
	}
	values := make(map[string]float64)
	for key, choices := range weights {
		value, ok := choices[metrics[key]]
		if !ok {
			return 0, errors.New("invalid or missing CVSS metric " + key)
		}
		values[key] = value
	}
	if metrics["S"] == "C" {
		if metrics["PR"] == "L" {
			values["PR"] = 0.68
		}
		if metrics["PR"] == "H" {
			values["PR"] = 0.5
		}
	}
	impactFraction := 1 - (1-values["C"])*(1-values["I"])*(1-values["A"])
	impact := 6.42 * impactFraction
	if metrics["S"] == "C" {
		impact = 7.52*(impactFraction-0.029) - 3.25*math.Pow(impactFraction-0.02, 15)
	}
	if impact <= 0 {
		return 0, nil
	}
	value := impact + 8.22*values["AV"]*values["AC"]*values["PR"]*values["UI"]
	if metrics["S"] == "C" {
		value *= 1.08
	}
	value = min(value, 10)
	integer := int64(math.Round(value * 100000))
	if integer%10000 == 0 {
		return float64(integer) / 100000, nil
	}
	return float64(integer/10000+1) / 10, nil
}
