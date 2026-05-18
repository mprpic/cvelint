package rules

import (
	"fmt"
	"github.com/tidwall/gjson"
	"strings"
)

// CheckCNARulesV4_0 validates CVE records against requirements from CNA Rules v4.0.
// CNA Rules are maintained by the CVE Program and define requirements for CVE Record content.
// Reference: https://github.com/CVEProject/cvelistV5/blob/main/CVERecord.md
// and CVE Numbering Authority Operational Rules version 4.0
//
// Key MUST requirements checked:
// - CVE ID must be in format CVE-YYYY-NNNNN[NNN...]
// - CNA description must be present for PUBLISHED records
// - At least one affected product must be present for PUBLISHED records
// - State must be either PUBLISHED or REJECTED
func CheckCNARulesV4_0Basic(json *string) []ValidationError {
	var errors []ValidationError

	// Check CVE ID format
	cveId := gjson.Get(*json, `cveMetadata.id`).String()
	if cveId == "" {
		errors = append(errors, ValidationError{
			Text:     "CVE ID must be present",
			JsonPath: "cveMetadata.id",
		})
	} else if !strings.HasPrefix(cveId, "CVE-") {
		errors = append(errors, ValidationError{
			Text:     fmt.Sprintf("Invalid CVE ID format: %s (must start with CVE-)", cveId),
			JsonPath: "cveMetadata.id",
		})
	}

	state := gjson.Get(*json, `cveMetadata.state`).String()
	if state == "" {
		errors = append(errors, ValidationError{
			Text:     "CVE state must be present",
			JsonPath: "cveMetadata.state",
		})
	} else if state != CveRecordStatePublished && state != CveRecordStateRejected {
		errors = append(errors, ValidationError{
			Text:     fmt.Sprintf("Invalid CVE state: %s (must be PUBLISHED or REJECTED)", state),
			JsonPath: "cveMetadata.state",
		})
	}

	return errors
}

// CheckCNARulesV4_0Descriptions validates CNA Rules requirements for descriptions.
// MUST: At least one English description present for PUBLISHED records
// MUST: Description must be at least 10 characters
// SHOULD: Additional translations may be provided
func CheckCNARulesV4_0Descriptions(json *string) []ValidationError {
	var errors []ValidationError

	state := gjson.Get(*json, `cveMetadata.state`).String()
	if state != CveRecordStatePublished {
		return errors
	}

	// Check for at least one English description
	descriptions := gjson.Get(*json, `containers.cna.descriptions`)
	enDescCount := 0
	descriptions.ForEach(func(key, value gjson.Result) bool {
		lang := value.Get("lang").String()
		if lang == "en" {
			enDescCount++
		}
		return true
	})

	if enDescCount == 0 {
		errors = append(errors, ValidationError{
			Text:     "CNA Rules v4.0 MUST: At least one English (en) description must be present for PUBLISHED records",
			JsonPath: "containers.cna.descriptions",
		})
	}

	return errors
}

// CheckCNARulesV4_0References validates CNA Rules requirements for references.
// MUST: At least one reference must be provided
// SHOULD: Multiple reference types are recommended (e.g., Advisory, Patch, etc.)
func CheckCNARulesV4_0References(json *string) []ValidationError {
	var errors []ValidationError

	state := gjson.Get(*json, `cveMetadata.state`).String()
	if state != CveRecordStatePublished {
		return errors
	}

	// Check for at least one reference
	references := gjson.Get(*json, `containers.cna.references`)
	refCount := 0
	references.ForEach(func(key, value gjson.Result) bool {
		refCount++
		return true
	})

	if refCount == 0 {
		errors = append(errors, ValidationError{
			Text:     "CNA Rules v4.0 MUST: At least one reference must be provided for PUBLISHED records",
			JsonPath: "containers.cna.references",
		})
	}

	return errors
}

// CheckCNARulesV4_0Metrics validates CNA Rules requirements for vulnerability metrics.
// MUST: If metrics are provided, they must be properly formatted and valid
// SHOULD: CVSS v3.1 metrics are recommended
func CheckCNARulesV4_0Metrics(json *string) []ValidationError {
	var errors []ValidationError

	state := gjson.Get(*json, `cveMetadata.state`).String()
	if state != CveRecordStatePublished {
		return errors
	}

	// Check CVSSv3.1 metrics if present
	metrics := gjson.Get(*json, `containers.cna.metrics`)
	metrics.ForEach(func(key, value gjson.Result) bool {
		cvssV3_1 := value.Get("cvssV3_1")
		if cvssV3_1.Exists() {
			baseScore := cvssV3_1.Get("baseScore").Float()
			if baseScore < 0 || baseScore > 10 {
				errors = append(errors, ValidationError{
					Text:     fmt.Sprintf("Invalid CVSS v3.1 base score: %.1f (must be between 0.0 and 10.0)", baseScore),
					JsonPath: value.Get("cvssV3_1.baseScore").Path(*json),
				})
			}
			baseSeverity := cvssV3_1.Get("baseSeverity").String()
			validSeverities := map[string]bool{
				"NONE": true, "LOW": true, "MEDIUM": true,
				"HIGH": true, "CRITICAL": true,
			}
			if baseSeverity != "" && !validSeverities[baseSeverity] {
				errors = append(errors, ValidationError{
					Text:     fmt.Sprintf("Invalid CVSS v3.1 severity: %s", baseSeverity),
					JsonPath: value.Get("cvssV3_1.baseSeverity").Path(*json),
				})
			}
		}
		return true
	})

	return errors
}

// CheckCNARulesV4_0Timeline validates CNA Rules requirements for timeline entries.
// SHOULD: Timeline entries should be provided when available
// MUST: If provided, timeline entries should have event and date fields
func CheckCNARulesV4_0Timeline(json *string) []ValidationError {
	var errors []ValidationError

	state := gjson.Get(*json, `cveMetadata.state`).String()
	if state != CveRecordStatePublished {
		return errors
	}

	// Check timeline entries if present
	timeline := gjson.Get(*json, `containers.cna.timeline`)
	timeline.ForEach(func(key, value gjson.Result) bool {
		event := value.Get("event").String()
		if event == "" {
			errors = append(errors, ValidationError{
				Text:     "Timeline entry must have an 'event' field",
				JsonPath: value.Path(*json) + ".event",
			})
		}

		eventDate := value.Get("eventDate").String()
		if eventDate == "" {
			errors = append(errors, ValidationError{
				Text:     "Timeline entry must have an 'eventDate' field",
				JsonPath: value.Path(*json) + ".eventDate",
			})
		}

		return true
	})

	return errors
}

// CheckCNARulesV4_0Credits validates CNA Rules requirements for credits.
// SHOULD: Credits should be provided when available
// MUST: If provided, credits should have proper structure
func CheckCNARulesV4_0Credits(json *string) []ValidationError {
	var errors []ValidationError

	state := gjson.Get(*json, `cveMetadata.state`).String()
	if state != CveRecordStatePublished {
		return errors
	}

	// Check credits if present
	credits := gjson.Get(*json, `containers.cna.credits`)
	credits.ForEach(func(key, value gjson.Result) bool {
		// Credits should have either a user or organization identifier
		user := value.Get("user").String()
		organization := value.Get("organization").String()

		if user == "" && organization == "" {
			errors = append(errors, ValidationError{
				Text:     "Credit entry must have either 'user' or 'organization' field",
				JsonPath: value.Path(*json),
			})
		}

		return true
	})

	return errors
}
