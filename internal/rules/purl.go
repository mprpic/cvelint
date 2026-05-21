package rules

import (
	"fmt"
	"github.com/package-url/packageurl-go"
	"github.com/tidwall/gjson"
	"strings"
)

// CheckPurlFormat validates that PURL (Package URL) strings in the CVE record are valid.
// This function checks PURL entries in the "components" section which may be added to CVE schema.
// PURLs should follow the Package URL specification: https://github.com/package-url/packageurl-go
func CheckPurlFormat(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != "PUBLISHED" {
		// REJECTED records do not require components
		return nil
	}

	var errors []ValidationError

	// Check PURLs in components section (if present)
	// This path is being added to CVE schema per: https://github.com/CVEProject/cve-schema/pull/407
	components := gjson.Get(*json, `containers.cna.components`)
	components.ForEach(func(key, value gjson.Result) bool {
		purl := value.Get("purl").String()
		if purl != "" {
			if !strings.HasPrefix(purl, "pkg:") {
				errors = append(errors, ValidationError{
					Text:     fmt.Sprintf("Invalid PURL format: missing 'pkg:' prefix: %s", purl),
					JsonPath: value.Get("purl").Path(*json),
				})
			} else {
				_, err := packageurl.FromString(purl)
				if err != nil {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid PURL format: %s (error: %v)", purl, err),
						JsonPath: value.Get("purl").Path(*json),
					})
				}
			}
		}
		return true
	})

	// Check PURLs in affects section (for version strings that may be PURLs)
	// PURLs in version fields are already validated in CheckInvalidVersion,
	// but we can add additional validation if needed here

	// Check PURLs in references section (if references contain PURL data)
	// Some implementations may include PURL data in reference metadata
	affected := gjson.Get(*json, `containers.cna.affected`)
	affected.ForEach(func(akey, avalue gjson.Result) bool {
		// Check for PURL in affected components
		purl := avalue.Get("purl").String()
		if purl != "" {
			if !strings.HasPrefix(purl, "pkg:") {
				errors = append(errors, ValidationError{
					Text:     fmt.Sprintf("Invalid PURL format in affected: missing 'pkg:' prefix: %s", purl),
					JsonPath: avalue.Get("purl").Path(*json),
				})
			} else {
				_, err := packageurl.FromString(purl)
				if err != nil {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid PURL format in affected: %s (error: %v)", purl, err),
						JsonPath: avalue.Get("purl").Path(*json),
					})
				}
			}
		}
		return true
	})

	return errors
}

// CheckPurlConsistency validates that PURLs are consistent with vendor/product information.
// If a PURL is provided, it should align with the vendor and product fields.
func CheckPurlConsistency(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != "PUBLISHED" {
		return nil
	}

	var errors []ValidationError

	components := gjson.Get(*json, `containers.cna.components`)
	components.ForEach(func(key, value gjson.Result) bool {
		purl := value.Get("purl").String()
		if purl != "" && strings.HasPrefix(purl, "pkg:") {
			parsedPurl, err := packageurl.FromString(purl)
			if err == nil {
				// Get the namespace and name from the component
				componentNamespace := value.Get("namespace").String()
				componentName := value.Get("name").String()

				// Validate that PURL namespace/name matches component data
				if componentNamespace != "" && parsedPurl.Namespace != componentNamespace {
					errors = append(errors, ValidationError{
						Text: fmt.Sprintf(
							"PURL namespace '%s' does not match component namespace '%s'",
							parsedPurl.Namespace,
							componentNamespace,
						),
						JsonPath: value.Get("purl").Path(*json),
					})
				}

				if componentName != "" && parsedPurl.Name != componentName {
					errors = append(errors, ValidationError{
						Text: fmt.Sprintf(
							"PURL name '%s' does not match component name '%s'",
							parsedPurl.Name,
							componentName,
						),
						JsonPath: value.Get("purl").Path(*json),
					})
				}
			}
		}
		return true
	})

	return errors
}
