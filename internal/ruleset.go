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
	"E011": {
		Code:        "E011",
		Name:        "check-unicode-escape-sequences",
		Description: "Descriptions do not contain Unicode escape sequences; UTF-8 characters should be used instead",
		CheckFunc:   rules.CheckUnicodeEscapeSequences,
	},
	"E012": {
		Code:        "E012",
		Name:        "check-purl-format",
		Description: "PURL (Package URL) strings are valid and follow the specification",
		CheckFunc:   rules.CheckPurlFormat,
	},
	"E013": {
		Code:        "E013",
		Name:        "check-purl-consistency",
		Description: "PURL data is consistent with component vendor/product information",
		CheckFunc:   rules.CheckPurlConsistency,
	},
	"E014": {
		Code:        "E014",
		Name:        "check-cna-rules-v4-basic",
		Description: "CVE record meets basic CNA Rules v4.0 requirements (CVE ID format, state validity)",
		CheckFunc:   rules.CheckCNARulesV4_0Basic,
	},
	"E015": {
		Code:        "E015",
		Name:        "check-cna-rules-v4-descriptions",
		Description: "CVE record meets CNA Rules v4.0 description requirements (at least one English description)",
		CheckFunc:   rules.CheckCNARulesV4_0Descriptions,
	},
	"E016": {
		Code:        "E016",
		Name:        "check-cna-rules-v4-references",
		Description: "CVE record meets CNA Rules v4.0 reference requirements (at least one reference present)",
		CheckFunc:   rules.CheckCNARulesV4_0References,
	},
	"E017": {
		Code:        "E017",
		Name:        "check-cna-rules-v4-metrics",
		Description: "CVE record meets CNA Rules v4.0 metrics requirements (valid CVSS scores and severity)",
		CheckFunc:   rules.CheckCNARulesV4_0Metrics,
	},
	"E018": {
		Code:        "E018",
		Name:        "check-cna-rules-v4-timeline",
		Description: "CNA Rules v4.0 timeline entries have required fields (event, eventDate)",
		CheckFunc:   rules.CheckCNARulesV4_0Timeline,
	},
	"E019": {
		Code:        "E019",
		Name:        "check-cna-rules-v4-credits",
		Description: "CNA Rules v4.0 credit entries have required structure (user or organization)",
		CheckFunc:   rules.CheckCNARulesV4_0Credits,
	},
}
