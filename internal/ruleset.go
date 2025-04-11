package internal

import (
	"github.com/mprpic/cvelint/internal/rules"
)

type Rule struct {
	Code        string
	Name        string
	Description string
	CheckFunc   func(*string) []rules.ValidationError
}

var RuleSet = map[string]Rule{
	"E001": {
		Code:        "E001",
		Name:        "check-reference-url-protocol",
		Description: "Reference URLs use allowed protocols (ftp(s)/http(s))",
		CheckFunc:   rules.CheckRefProtocol,
	},
	"E002": {
		Code:        "E002",
		Name:        "check-duplicate-reference-url",
		Description: "CVE record does not contain duplicate reference URLs",
		CheckFunc:   rules.DuplicateRefs,
	},
	"E003": {
		Code:        "E003",
		Name:        "check-description-length",
		Description: "One en-US description of at least 10 characters is present in the CNA container",
		CheckFunc:   rules.CheckLength,
	},
	"E004": {
		Code:        "E004",
		Name:        "check-leading-trailing-space",
		Description: "CNA container descriptions do not have leading or trailing whitespace",
		CheckFunc:   rules.CheckLeadingTrailingSpace,
	},
	"E005": {
		Code:        "E005",
		Name:        "check-cvss3-base-severity",
		Description: "CVSSv3 base severity matches the base score",
		CheckFunc:   rules.CheckCvssV3BaseSeverity,
	},
	"E006": {
		Code:        "E006",
		Name:        "check-affected-product-present",
		Description: "One affected/unknown product is present in CNA container",
		CheckFunc:   rules.CheckAffectedProduct,
	},
	"E007": {
		Code:        "E007",
		Name:        "check-invalid-version-string",
		Description: "Version field contains invalid characters",
		CheckFunc:   rules.CheckInvalidVersion,
	},
	"E008": {
		Code:        "E008",
		Name:        "check-invalid-vendor-string",
		Description: "Vendor field contains an invalid value",
		CheckFunc:   rules.CheckValidVendor,
	},
	"E009": {
		Code:        "E009",
		Name:        "check-invalid-product-string",
		Description: "Product field contains an invalid value",
		CheckFunc:   rules.CheckValidProduct,
	},
	"E010": {
		Code:        "E010",
		Name:        "check-invalid-self-references",
		Description: "References contain an invalid self-reference value",
		CheckFunc:   rules.CheckSelfReference,
	},
}
