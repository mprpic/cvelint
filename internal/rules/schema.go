package rules

//
//import (
//	"fmt"
//	"github.com/tidwall/gjson"
//	"strings"
//)
//
//func CheckSchema(json *string) []ValidationError {
//	var errors []ValidationError
//	d := gjson.Get(*json, "containers.cna.metrics.#.cvssV3*")
//	d.ForEach(func(key, value gjson.Result) bool {
//		score := value.Get("baseScore").Float()
//		severity := strings.ToLower(value.Get("baseSeverity").String())
//		correctSeverity := computeSeverity(score)
//		if severity != correctSeverity {
//			errors = append(errors, ValidationError{
//				Text:     fmt.Sprintf(`Incorrect CVSS v3 severity: "%s"; should be "%s"`, severity, correctSeverity),
//				JsonPath: value.Path(*json),
//			})
//		}
//		return true
//	})
//	return errors
//}
