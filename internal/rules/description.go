package rules

import (
	"fmt"
	"github.com/tidwall/gjson"
	"regexp"
	"strings"
	"unicode/utf8"
)

const minDescriptionTextLength = 10

func CheckLength(json *string) []ValidationError {
	var errors []ValidationError

	state := gjson.Get(*json, `cveMetadata.state`).String()
	var data gjson.Result
	if state == CveRecordStatePublished {
		data = gjson.Get(*json, `containers.cna.descriptions.#(lang=="en")#`)
	} else if state == CveRecordStateRejected {
		data = gjson.Get(*json, `containers.cna.rejectedReasons.#(lang=="en")#`)
	}

	enDescCount := 0
	data.ForEach(func(key, value gjson.Result) bool {
		text := value.Get("value").String()
		if utf8.RuneCountInString(text) < minDescriptionTextLength {
			errors = append(errors, ValidationError{
				Text:     fmt.Sprintf("Description too short: %s", text),
				JsonPath: value.Path(*json),
			})
		}
		enDescCount += 1
		return true
	})
	if enDescCount > 1 {
		errors = append(errors, ValidationError{
			Text:     fmt.Sprintf("More than one en-US description present"),
			JsonPath: data.Path(*json),
		})
	}
	return errors
}

func CheckLeadingTrailingSpace(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != "PUBLISHED" {
		// REJECTED records do not require a description
		return nil
	}
	var errors []ValidationError

	// Find all descriptions with lang "en"
	d := gjson.Get(*json, `containers.cna.descriptions.#.value`)
	d.ForEach(func(key, value gjson.Result) bool {
		text := value.String()
		if len(strings.TrimSpace(text)) != len(text) {
			errors = append(errors, ValidationError{
				Text:     "Trailing or leading whitespace in description",
				JsonPath: value.Path(*json),
			})
		}
		return true
	})
	return errors
}

func CheckUnicodeEscapeSequences(json *string) []ValidationError {
	var errors []ValidationError

	state := gjson.Get(*json, `cveMetadata.state`).String()
	if state != CveRecordStatePublished && state != CveRecordStateRejected {
		return errors
	}

	// Pattern to match Unicode escape sequences like \uXXXX or \uXXXXXXXX (both 4 and 8 digit variants)
	unicodeEscapePattern := regexp.MustCompile(`\\u[0-9a-fA-F]{4}(?:[0-9a-fA-F]{4})?`)

	// Check descriptions
	d := gjson.Get(*json, `containers.cna.descriptions.#.value`)
	d.ForEach(func(key, value gjson.Result) bool {
		text := value.String()
		if unicodeEscapePattern.MatchString(text) {
			errors = append(errors, ValidationError{
				Text:     fmt.Sprintf("Unicode escape sequences found in description; UTF-8 characters should be used instead"),
				JsonPath: value.Path(*json),
			})
		}
		return true
	})

	// Check rejection reasons if REJECTED
	if state == CveRecordStateRejected {
		r := gjson.Get(*json, `containers.cna.rejectedReasons.#.value`)
		r.ForEach(func(key, value gjson.Result) bool {
			text := value.String()
			if unicodeEscapePattern.MatchString(text) {
				errors = append(errors, ValidationError{
					Text:     fmt.Sprintf("Unicode escape sequences found in rejection reason; UTF-8 characters should be used instead"),
					JsonPath: value.Path(*json),
				})
			}
			return true
		})
	}

	return errors
}
