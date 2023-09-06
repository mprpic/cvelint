package rules

import (
	"github.com/tidwall/gjson"
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
