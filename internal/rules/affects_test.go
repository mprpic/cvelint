package rules

import (
	"testing"
)

func TestCheckInvalidVersion(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
		errorCount   int
	}{
		{
			name: "Valid single version",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "1.0.0", "versionType": "semver", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Valid semver with pre-release",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "1.0.0-beta.1", "versionType": "semver", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Invalid version with whitespace",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "1.0.0 and earlier", "versionType": "semver", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "Asterisk allowed in lessThan",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"lessThan": "*", "versionType": "semver", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Asterisk not allowed in lessThanOrEqual",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"lessThanOrEqual": "*", "versionType": "semver", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "Valid git commit hash",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "abcd1234abcd1234abcd1234abcd1234abcd1234", "versionType": "git", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Invalid git commit hash (too short)",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "abcd1234", "versionType": "git", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "Valid version range with lessThan",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"lessThan": "2.0.0", "versionType": "semver", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "No versionType falls back to generic validation",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "1.0.0", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Rejected record should not be checked",
			json: `{
				"cveMetadata": {"state": "REJECTED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "invalid version!", "versionType": "semver", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckInvalidVersion(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v (errors: %v)", tt.expectErrors, len(errors) > 0, errors)
			}

			if len(errors) != tt.errorCount {
				t.Errorf("Expected %d errors, got %d: %v", tt.errorCount, len(errors), errors)
			}
		})
	}
}

func TestCheckCustomVersionType(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
		errorCount   int
	}{
		{
			name: "Custom versionType produces warning",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "1.0.0", "versionType": "custom", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "Non-custom versionType is fine",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "1.0.0", "versionType": "semver", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Rejected record should not be checked",
			json: `{
				"cveMetadata": {"state": "REJECTED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "1.0.0", "versionType": "custom", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckCustomVersionType(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v (errors: %v)", tt.expectErrors, len(errors) > 0, errors)
			}

			if len(errors) != tt.errorCount {
				t.Errorf("Expected %d errors, got %d: %v", tt.errorCount, len(errors), errors)
			}
		})
	}
}

func TestCheckAffectedProduct(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Valid affected product",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "product",
								"versions": [
									{"version": "1.0.0", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Missing affected product",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": []
					}
				}
			}`,
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckAffectedProduct(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}

func TestCheckValidVendor(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Valid vendor",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example_vendor",
								"product": "product",
								"versions": [
									{"version": "1.0.0", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Invalid vendor - n/a",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "n/a",
								"product": "product",
								"versions": [
									{"version": "1.0.0", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: true,
		},
		{
			name: "Invalid vendor - URL",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "https://example.com",
								"product": "product",
								"versions": [
									{"version": "1.0.0", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckValidVendor(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}

func TestCheckValidProduct(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Valid product",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "example_product",
								"versions": [
									{"version": "1.0.0", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Invalid product - n/a",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"vendor": "example",
								"product": "n/a",
								"versions": [
									{"version": "1.0.0", "status": "affected"}
								]
							}
						]
					}
				}
			}`,
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckValidProduct(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}
