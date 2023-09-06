package rules

const (
	CveRecordStatePublished = "PUBLISHED"
	CveRecordStateRejected  = "REJECTED"
)

type ValidationError struct {
	Text     string
	JsonPath string
}
