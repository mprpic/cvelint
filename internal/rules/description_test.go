package rules

import (
	"testing"
)

func TestCheckUnicodeEscapeSequences(t *testing.T) {
	tests := []struct {
		name          string
		json          string
		expectErrors  bool
		errorCount    int
		errorContains string
	}{
		{
			name: "Published record with Unicode escape sequences in description",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "en", "value": "This has a unicode escape \\u00e9 in it"}
						]
					}
				}
			}`,
			expectErrors:  true,
			errorCount:    1,
			errorContains: "Unicode escape sequences found in description",
		},
		{
			name: "Published record without Unicode escape sequences",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "en", "value": "This has proper UTF-8 character é in it"}
						]
					}
				}
			}`,
			expectErrors: false,
			errorCount:   0,
		},
		{
			name: "Rejected record with Unicode escape sequences in rejection reason",
			json: `{
				"cveMetadata": {"state": "REJECTED"},
				"containers": {
					"cna": {
						"rejectedReasons": [
							{"lang": "en", "value": "Rejected due to \\u00e9 character"}
						]
					}
				}
			}`,
			expectErrors:  true,
			errorCount:    1,
			errorContains: "Unicode escape sequences found in rejection reason",
		},
		{
			name: "Multiple Unicode escape sequences",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "en", "value": "First \\u00e9 and second \\u00e0 escapes"}
						]
					}
				}
			}`,
			expectErrors:  true,
			errorCount:    1,
			errorContains: "Unicode escape sequences found in description",
		},
		{
			name: "8-digit Unicode escape sequence",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "en", "value": "This has \\U0001F600 emoji escape"}
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
			errors := CheckUnicodeEscapeSequences(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}

			if len(errors) != tt.errorCount {
				t.Errorf("Expected %d errors, got %d", tt.errorCount, len(errors))
			}

			if tt.expectErrors && tt.errorContains != "" {
				found := false
				for _, err := range errors {
					if err.Text == tt.errorContains || (len(err.Text) > len(tt.errorContains) &&
						err.Text[:len(tt.errorContains)] == tt.errorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, errors)
				}
			}
		})
	}
}

func TestCheckLength(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Valid description length",
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
			name: "Description too short",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "en", "value": "short"}
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
			errors := CheckLength(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}

func TestCheckLeadingTrailingSpace(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		expectErrors bool
	}{
		{
			name: "Description without leading/trailing space",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "en", "value": "Valid description"}
						]
					}
				}
			}`,
			expectErrors: false,
		},
		{
			name: "Description with leading space",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "en", "value": " Description with leading space"}
						]
					}
				}
			}`,
			expectErrors: true,
		},
		{
			name: "Description with trailing space",
			json: `{
				"cveMetadata": {"state": "PUBLISHED"},
				"containers": {
					"cna": {
						"descriptions": [
							{"lang": "en", "value": "Description with trailing space "}
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
			errors := CheckLeadingTrailingSpace(&json)

			if (len(errors) > 0) != tt.expectErrors {
				t.Errorf("Expected errors: %v, got: %v", tt.expectErrors, len(errors) > 0)
			}
		})
	}
}
