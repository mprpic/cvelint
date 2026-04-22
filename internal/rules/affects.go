package rules

import (
	"fmt"
	"github.com/package-url/packageurl-go"
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
// - special characters like "<" or "," ("*" is allowed only in lessThan)
// Special handling below for versions that look like purls (start with a prefix of `pkg:`)
var validVersionRe = regexp.MustCompile(`^(\*|[a-zA-Z0-9]+[-*_:.a-zA-Z0-9]*)$`)

// Version type specific patterns
var (
	// Semantic versioning pattern (e.g., 1.2.3, 1.2.3-alpha, 1.2.3+build)
	semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	// Git commit hash (40 chars SHA-1 or 64 chars SHA-256)
	gitHashPattern = regexp.MustCompile(`^[a-f0-9]{40}$|^[a-f0-9]{64}$`)
	// RPM version pattern
	rpmPattern = regexp.MustCompile(`^[a-zA-Z0-9._~-]+$`)
	// Maven version pattern
	mavenPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	// Python version pattern (PEP 440)
	pythonPattern = regexp.MustCompile(`^([0-9]+!)?(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*((a|b|rc)(0|[1-9][0-9]*))?(\.post(0|[1-9][0-9]*))?(\.dev(0|[1-9][0-9]*))?$`)
)

// validateVersionByType validates a version string based on its type
func validateVersionByType(version string, versionType string) bool {
	if version == "*" {
		return false
	}

	switch versionType {
	case "semver":
		return semverPattern.MatchString(version)
	case "git":
		return gitHashPattern.MatchString(version)
	case "rpm":
		return rpmPattern.MatchString(version)
	case "maven":
		return mavenPattern.MatchString(version)
	case "python":
		return pythonPattern.MatchString(version)
	default:
		// Unknown type - fall back to basic validation
		return validVersionRe.MatchString(version)
	}
}

// CheckInvalidVersion returns an array of detected version-related ValidationError findings.
// It checks that the affected.versions sub-fields are used correctly, including:
// - Generic character validation via validVersionRe
// - Type-specific version format validation when versionType is declared
// - Ensuring "*" is only used in lessThan, not lessThanOrEqual
func CheckInvalidVersion(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != CveRecordStatePublished {
		// REJECTED records do not list affected products
		return nil
	}
	var errors []ValidationError

	// Get affected products to check versionType
	affected := gjson.Get(*json, `containers.cna.affected`)
	
	affected.ForEach(func(key, value gjson.Result) bool {
		// Check version field
		versions := value.Get("versions")
		versions.ForEach(func(vkey, vvalue gjson.Result) bool {
			versionType := vvalue.Get("versionType").String()

			// Check "version" field (single version)
			if singleVersion := vvalue.Get("version").String(); singleVersion != "" {
				if strings.HasPrefix(singleVersion, "pkg:") {
					_, err := packageurl.FromString(singleVersion)
					if err != nil {
						errors = append(errors, ValidationError{
							Text:     fmt.Sprintf("Invalid purl in package version string: %s", singleVersion),
							JsonPath: vvalue.Get("version").Path(*json),
						})
					}
				} else if !validVersionRe.MatchString(singleVersion) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid version string: \"%s\"", singleVersion),
						JsonPath: vvalue.Get("version").Path(*json),
					})
				} else if versionType != "" && !validateVersionByType(singleVersion, versionType) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Version \"%s\" does not match expected format for type \"%s\"", singleVersion, versionType),
						JsonPath: vvalue.Get("version").Path(*json),
					})
				}
			}

			// Check "lessThan" field (range start - "*" is allowed here)
			if lessThan := vvalue.Get("lessThan").String(); lessThan != "" {
				if lessThan == "*" {
					// "*" is allowed only in lessThan per schema
					// no error
				} else if strings.HasPrefix(lessThan, "pkg:") {
					_, err := packageurl.FromString(lessThan)
					if err != nil {
						errors = append(errors, ValidationError{
							Text:     fmt.Sprintf("Invalid purl in lessThan version: %s", lessThan),
							JsonPath: vvalue.Get("lessThan").Path(*json),
						})
					}
				} else if !validVersionRe.MatchString(lessThan) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid lessThan version string: \"%s\"", lessThan),
						JsonPath: vvalue.Get("lessThan").Path(*json),
					})
				} else if versionType != "" && !validateVersionByType(lessThan, versionType) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("lessThan version \"%s\" does not match expected format for type \"%s\"", lessThan, versionType),
						JsonPath: vvalue.Get("lessThan").Path(*json),
					})
				}
			}

			// Check "lessThanOrEqual" field ("*" is NOT allowed here)
			if lessThanOrEqual := vvalue.Get("lessThanOrEqual").String(); lessThanOrEqual != "" {
				if lessThanOrEqual == "*" {
					errors = append(errors, ValidationError{
						Text:     "\"*\" is only allowed in lessThan, not lessThanOrEqual",
						JsonPath: vvalue.Get("lessThanOrEqual").Path(*json),
					})
				} else if strings.HasPrefix(lessThanOrEqual, "pkg:") {
					_, err := packageurl.FromString(lessThanOrEqual)
					if err != nil {
						errors = append(errors, ValidationError{
							Text:     fmt.Sprintf("Invalid purl in lessThanOrEqual version: %s", lessThanOrEqual),
							JsonPath: vvalue.Get("lessThanOrEqual").Path(*json),
						})
					}
				} else if !validVersionRe.MatchString(lessThanOrEqual) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid lessThanOrEqual version string: \"%s\"", lessThanOrEqual),
						JsonPath: vvalue.Get("lessThanOrEqual").Path(*json),
					})
				} else if versionType != "" && !validateVersionByType(lessThanOrEqual, versionType) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("lessThanOrEqual version \"%s\" does not match expected format for type \"%s\"", lessThanOrEqual, versionType),
						JsonPath: vvalue.Get("lessThanOrEqual").Path(*json),
					})
				}
			}

			// Check "changes" array
			changes := vvalue.Get("changes")
			changes.ForEach(func(ckey, cvalue gjson.Result) bool {
				if atVersion := cvalue.Get("at").String(); atVersion != "" {
					if !validVersionRe.MatchString(atVersion) {
						errors = append(errors, ValidationError{
							Text:     fmt.Sprintf("Invalid version in changes.at: \"%s\"", atVersion),
							JsonPath: cvalue.Get("at").Path(*json),
						})
					} else if versionType != "" && !validateVersionByType(atVersion, versionType) {
						errors = append(errors, ValidationError{
							Text:     fmt.Sprintf("changes.at version \"%s\" does not match expected format for type \"%s\"", atVersion, versionType),
							JsonPath: cvalue.Get("at").Path(*json),
						})
					}
				}
				return true
			})

			return true
		})

		return true
	})

	return errors
}

func CheckCustomVersionType(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != CveRecordStatePublished {
		return nil
	}
	var errors []ValidationError
	affected := gjson.Get(*json, `containers.cna.affected`)
	affected.ForEach(func(key, value gjson.Result) bool {
		versions := value.Get("versions")
		versions.ForEach(func(vkey, vvalue gjson.Result) bool {
			if vvalue.Get("versionType").String() == "custom" {
				errors = append(errors, ValidationError{
					Text:     "Custom versionType should be avoided per CVE schema documentation",
					JsonPath: vvalue.Get("versionType").Path(*json),
				})
			}
			return true
		})
		return true
	})
	return errors
}

// Values that should be invalid when used in a field that contains some identifying information:
// - n/a
// - single special characters like "-" or "/"
// - URLs (they should go into collectionUrl)
var invalidNameRe = regexp.MustCompile(`^(-|/|n/a|https?://.*)$`)

func CheckValidVendor(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != "PUBLISHED" {
		// REJECTED records do not list affected products
		return nil
	}
	var errors []ValidationError
	data := gjson.Get(*json, `containers.cna.affected.#.vendor`)
	data.ForEach(func(key, value gjson.Result) bool {
		vendor := value.String()
		if invalidNameRe.MatchString(vendor) {
			errors = append(errors, ValidationError{
				Text:     fmt.Sprintf("Invalid vendor string: \"%s\"", vendor),
				JsonPath: "containers.cna.affected.#.vendor",
			})
		}
		return true
	})
	return errors
}

func CheckValidProduct(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != "PUBLISHED" {
		// REJECTED records do not list affected products
		return nil
	}
	var errors []ValidationError
	data := gjson.Get(*json, `containers.cna.affected.#.product`)
	data.ForEach(func(key, value gjson.Result) bool {
		product := value.String()
		if invalidNameRe.MatchString(product) {
			errors = append(errors, ValidationError{
				Text:     fmt.Sprintf("Invalid product string: \"%s\"", product),
				JsonPath: "containers.cna.affected.#.product",
			})
		}
		return true
	})
	return errors
}
