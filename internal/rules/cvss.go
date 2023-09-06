package rules

import (
	"fmt"
	"github.com/tidwall/gjson"
	"strings"
)

func CheckCvssV3BaseSeverity(json *string) []ValidationError {
	var errors []ValidationError
	d := gjson.Get(*json, "containers.cna.metrics.#.cvssV3*")
	d.ForEach(func(key, value gjson.Result) bool {
		score := value.Get("baseScore").Float()
		severity := strings.ToLower(value.Get("baseSeverity").String())
		correctSeverity := computeSeverity(score)
		if severity != correctSeverity {
			errors = append(errors, ValidationError{
				Text:     fmt.Sprintf(`Incorrect CVSS v3 severity: "%s" (should be "%s")`, severity, correctSeverity),
				JsonPath: value.Path(*json),
			})
		}
		return true
	})
	return errors
}

func computeSeverity(score float64) string {
	// Severity rating scale is the same for both versions of CVSS v3:
	// - https://www.first.org/cvss/v3.1/specification-document#Qualitative-Severity-Rating-Scale
	// - https://www.first.org/cvss/v3.0/specification-document#Qualitative-Severity-Rating-Scale
	if score == 0.0 {
		return "none"
	} else if score <= 3.9 {
		return "low"
	} else if score <= 6.9 {
		return "medium"
	} else if score <= 8.9 {
		return "high"
	} else {
		return "critical"
	}
}
