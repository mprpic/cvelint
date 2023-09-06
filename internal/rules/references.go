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
	for _, v := range data {
		v.ForEach(func(key, value gjson.Result) bool {
			urls[value.String()]++
			return true
		})
	}
	for url, count := range urls {
		if count > 1 {
			errors = append(errors, ValidationError{
				Text: fmt.Sprintf("Duplicate reference URL: %s", url),
			})
		}
	}
	return errors
}
