package rules

import (
	"testing"
)

func TestCheckPurlFormat(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
		errorCount   int
	}{
		{
			name: "Valid PURL format",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{"purl": "pkg:npm/lodash@4.17.21"}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Valid PURL with qualifiers",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{"purl": "pkg:npm/lodash@4.17.21?arch=x86_64"}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Invalid PURL - missing pkg: prefix",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{"purl": "npm/lodash@4.17.21"}
						]
					}
				}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "Invalid PURL format",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{"purl": "pkg:!!!invalid"}
						]
					}
				}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "Empty PURL should not error",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{"name": "component", "purl": ""}
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
						"components": [
							{"purl": "invalid"}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "PURL in affected section",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"affected": [
							{
								"purl": "pkg:npm/lodash@4.17.21",
								"vendor": "lodash",
								"product": "lodash",
								"versions": [
									{"version": "4.17.20", "status": "affected"}
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
			errors := CheckPurlFormat(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v (errors: %v)", tt.expectErrors, len(errors) > 0, errors)
			}

			if len(errors) != tt.errorCount {
				t.Errorf("Expected %d errors, got %d: %v", tt.errorCount, len(errors), errors)
			}
		})
	}
}

func TestCheckPurlConsistency(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
		errorCount   int
	}{
		{
			name: "Consistent PURL and component data",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{
								"purl": "pkg:npm/@angular/core@12.0.0",
								"namespace": "@angular",
								"name": "core"
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Inconsistent PURL namespace",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{
								"purl": "pkg:npm/@angular/core@12.0.0",
								"namespace": "@react",
								"name": "core"
							}
						]
					}
				}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "Inconsistent PURL name",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{
								"purl": "pkg:npm/@angular/core@12.0.0",
								"namespace": "@angular",
								"name": "react"
							}
						]
					}
				}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "No namespace in PURL",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{
								"purl": "pkg:npm/lodash@4.17.21",
								"name": "lodash"
							}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Invalid PURL should not be checked for consistency",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"components": [
							{
								"purl": "invalid",
								"namespace": "ns",
								"name": "name"
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
			errors := CheckPurlConsistency(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v (errors: %v)", tt.expectErrors, len(errors) > 0, errors)
			}

			if len(errors) != tt.errorCount {
				t.Errorf("Expected %d errors, got %d: %v", tt.errorCount, len(errors), errors)
			}
		})
	}
}
