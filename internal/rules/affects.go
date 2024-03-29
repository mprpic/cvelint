package rules

import (
	"fmt"
	"github.com/tidwall/gjson"
	"regexp"
	"strings"
)

func CheckAffectedProduct(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != "PUBLISHED" {
		// REJECTED records do not list affected products
		return nil
	}
	var errors []ValidationError
	// Check if a product version exists that is marked affected or unknown
	data := gjson.Get(*json, `containers.cna.affected.#.versions.#.status`)
	affectedProductFound := false
	for _, affect := range data.Array() {
		for _, status := range affect.Array() {
			status := status.String()
			if status == "affected" || status == "unknown" {
				affectedProductFound = true
				break
			}
		}
		if affectedProductFound {
			break
		}
	}
	// Check if a defaultStatus exists that is set to affected or unknown
	if !affectedProductFound {
		data := gjson.Get(*json, `containers.cna.affected.#.defaultStatus`)
		data.ForEach(func(key, value gjson.Result) bool {
			status := value.String()
			if status == "affected" || status == "unknown" {
				affectedProductFound = true
				return false // stop iterating
			}
			return true
		})
	}
	if !affectedProductFound {
		errors = append(errors, ValidationError{
			Text:     "No affected product found",
			JsonPath: "containers.cna.affected",
		})
	}
	return errors
}

// Invalid version string examples:
// - "n/a" or "unspecified"
// - anything that includes whitespace, e.g. "v12.07 and earlier"
// - special characters like "<" or ","
var validVersionRe = regexp.MustCompile(`^(\*|[a-zA-Z0-9]+[-_:\.a-zA-Z0-9]*)$`)

// CheckInvalidVersion returns an array of detected version-related ValidationError findings.
// It checks that the affected.versions sub-fields are used correctly.
func CheckInvalidVersion(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != "PUBLISHED" {
		// REJECTED records do not list affected products
		return nil
	}
	var errors []ValidationError

	versionFields := []string{
		"containers.cna.affected.#.versions.#.version",
		"containers.cna.affected.#.versions.#.lessThan",
		"containers.cna.affected.#.versions.#.lessThanOrEqual",
	}
	for _, versionField := range versionFields {
		data := gjson.Get(*json, versionField)
		for _, affectedVersions := range data.Array() {
			for _, version := range affectedVersions.Array() {
				version := version.String()
				if !validVersionRe.MatchString(version) {
					fieldName := versionField[strings.LastIndex(versionField, ".")+1:]
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid version string in \"%s\" field: \"%s\"", fieldName, version),
						JsonPath: versionField,
					})
				}
			}
		}
	}

	// "at" version strings are nested in another "changes" array
	data := gjson.Get(*json, `containers.cna.affected.#.versions.#.changes.#.at`)
	for _, affectedVersions := range data.Array() {
		for _, changes := range affectedVersions.Array() {
			for _, atVersion := range changes.Array() {
				version := atVersion.String()
				if !validVersionRe.MatchString(version) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid version string in \"at\" field: \"%s\"", version),
						JsonPath: "containers.cna.affected.#.versions.#.changes.#.at",
					})
				}
			}
		}
	}

	return errors
}
