package rules

import (
	"fmt"
	"github.com/tidwall/gjson"
	"regexp"
)

var refUrlRe = regexp.MustCompile(`^(ftps?|https?)://.*`)

func CheckRefProtocol(json *string) []ValidationError {
	// Based on CNA rule 8.3:
	// https://www.cve.org/ResourcesSupport/AllResources/CNARules#section_8-3_cve_record_reference_requirements
	var errors []ValidationError
	data := gjson.Get(*json, `containers.cna.references.#.url`)
	data.ForEach(func(key, value gjson.Result) bool {
		url := value.String()
		if !refUrlRe.MatchString(url) {
			errors = append(errors, ValidationError{
				Text:     fmt.Sprintf("Invalid reference URL: %s", url),
				JsonPath: value.Path(*json),
			})
		}
		return true
	})
	return errors
}

func DuplicateRefs(json *string) []ValidationError {
	var errors []ValidationError
	data := gjson.GetMany(*json, `containers.cna.references.#.url`, `containers.adp.references.#.url`)
	var urls = make(map[string]int)
	var urlPaths = make(map[string]string)
	for _, v := range data {
		v.ForEach(func(key, value gjson.Result) bool {
			urls[value.String()]++
			urlPaths[value.String()] = value.Path(*json)
			return true
		})
	}
	for url, count := range urls {
		if count > 1 {
			errors = append(errors, ValidationError{
				Text:     fmt.Sprintf("Duplicate reference URL: %s", url),
				JsonPath: urlPaths[url],
			})
		}
	}
	return errors
}

func CheckSelfReference(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != "PUBLISHED" {
		// REJECTED records do not list affected products
		return nil
	}
	// A reference in a CVE record to itself is unnecessary. If that is the only
	// reference, that also violates the CNA rules of having at least one public
	// reference that exists before the CVE record is created.
	var errors []ValidationError
	cveId := gjson.Get(*json, `cveMetadata.cveId`).String()
	data := gjson.Get(*json, `containers.cna.references.#.url`)
	validRefFound := false
	data.ForEach(func(key, value gjson.Result) bool {
		url := value.String()
		if url == "https://www.cve.org/CVERecord?id="+cveId {
			errors = append(errors, ValidationError{
				Text:     fmt.Sprintf("Unnecessary self-reference URL: %s", url),
				JsonPath: value.Path(*json),
			})
		} else {
			validRefFound = true
		}
		return true
	})
	if !validRefFound {
		errors = append(errors, ValidationError{
			Text:     "No valid reference found",
			JsonPath: "containers.cna.references",
		})
	}
	return errors
}
