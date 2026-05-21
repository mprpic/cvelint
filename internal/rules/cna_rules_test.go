package rules

import (
	"testing"
)

func TestCheckCNARulesV4_0Basic(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
		errorCount   int
	}{
		{
			name: "Valid CVE ID and state",
			json: `{
				"cveMetadata": {
					"id": "CVE-2023-12345",
					"state": "PUBLISHED"
				},
				"containers": {"cna": {}}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Invalid CVE ID format",
			json: `{
				"cveMetadata": {
					"id": "2023-12345",
					"state": "PUBLISHED"
				},
				"containers": {"cna": {}}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "Invalid state",
			json: `{
				"cveMetadata": {
					"id": "CVE-2023-12345",
					"state": "DRAFT"
				},
				"containers": {"cna": {}}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
		{
			name: "Missing CVE ID",
			json: `{
				"cveMetadata": {
					"state": "PUBLISHED"
				},
				"containers": {"cna": {}}
			}`,
			expectErrors: true,
			errorCount:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckCNARulesV4_0Basic(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}

			if len(errors) != tt.errorCount {
				t.Errorf("Expected %d errors, got %d: %v", tt.errorCount, len(errors), errors)
			}
		})
	}
}

func TestCheckCNARulesV4_0Descriptions(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Valid English description",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "en", "value": "This is a valid description"}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Missing English description",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "es", "value": "Esta es una descripción"}
						]
					}
				}
			}`,
			expectErrors: true,
		},
		{
			name: "Rejected record - no description required",
			json: `{
				"cveMetadata": {"state": "REJECTED"},
				"containers": {"cna": {}}
			}`,
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckCNARulesV4_0Descriptions(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}

func TestCheckCNARulesV4_0References(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Valid references present",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"references": [
							{"url": "https://example.com/advisory"}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Missing references",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"references": []
					}
				}
			}`,
			expectErrors: true,
		},
		{
			name: "Rejected record - no references required",
			json: `{
				"cveMetadata": {"state": "REJECTED"},
				"containers": {"cna": {}}
			}`,
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckCNARulesV4_0References(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}

func TestCheckCNARulesV4_0Metrics(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Valid CVSS v3.1 metrics",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"metrics": [
							{
								"cvssV3_1": {
									"baseScore": 7.5,
									"baseSeverity": "HIGH"
								}
							}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Invalid CVSS v3.1 base score",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"metrics": [
							{
								"cvssV3_1": {
									"baseScore": 11.5,
									"baseSeverity": "HIGH"
								}
							}
						]
					}
				}
			}`,
			expectErrors: true,
		},
		{
			name: "Invalid CVSS severity",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"metrics": [
							{
								"cvssV3_1": {
									"baseScore": 7.5,
									"baseSeverity": "EXTREME"
								}
							}
						]
					}
				}
			}`,
			expectErrors: true,
		},
		{
			name: "No metrics - should not error",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {"cna": {}}
			}`,
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckCNARulesV4_0Metrics(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}

func TestCheckCNARulesV4_0Timeline(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Valid timeline entries",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"timeline": [
							{
								"event": "vendor-advisory-published",
								"eventDate": "2023-01-15T00:00:00Z"
							}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Timeline missing event",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"timeline": [
							{
								"eventDate": "2023-01-15T00:00:00Z"
							}
						]
					}
				}
			}`,
			expectErrors: true,
		},
		{
			name: "Timeline missing eventDate",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"timeline": [
							{
								"event": "vendor-advisory-published"
							}
						]
					}
				}
			}`,
			expectErrors: true,
		},
		{
			name: "No timeline - should not error",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {"cna": {}}
			}`,
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckCNARulesV4_0Timeline(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}

func TestCheckCNARulesV4_0Credits(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Valid credit with user",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"credits": [
							{
								"user": "@security_researcher",
								"type": "finder"
							}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Valid credit with organization",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"credits": [
							{
								"organization": "Security Lab",
								"type": "finder"
							}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Credit missing both user and organization",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"credits": [
							{
								"type": "finder"
							}
						]
					}
				}
			}`,
			expectErrors: true,
		},
		{
			name: "No credits - should not error",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {"cna": {}}
			}`,
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := tt.json
			errors := CheckCNARulesV4_0Credits(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}
