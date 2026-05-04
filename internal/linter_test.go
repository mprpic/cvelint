package internal

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/mprpic/cvelint/internal/rules"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	oldColor := color.Output
	r, w, _ := os.Pipe()
	os.Stdout = w
	color.Output = w

	fn()

	w.Close()
	os.Stdout = old
	color.Output = oldColor
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// TestLinter_Run_Basic validates core linting functionality
func TestLinter_Run_Basic(t *testing.T) {
	// This test verifies basic linter initialization
	files := []string{}
	linter := &Linter{
		Timestamp: time.Now().UTC(),
		FileInput: &files,
	}

	// Create a mock rule that passes
	passRule := Rule{
		Code:        "TEST001",
		Name:        "test-pass",
		Description: "Test rule that always passes",
		CheckFunc: func(j *string) []rules.ValidationError {
			return []rules.ValidationError{}
		},
	}

	selectedRules := []Rule{passRule}

	// Test that Run() executes without error
	linter.Run(&selectedRules, "")

	if linter.FilesChecked != 0 {
		t.Errorf("Expected 0 files checked (empty list), got %d", linter.FilesChecked)
	}
}

// TestLinter_Run_WithCNAFilter validates CNA filtering logic
func TestLinter_Run_WithCNAFilter(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()

	// CVE with CNA "vendor1"
	cve1 := `{
		"cveMetadata": {
			"cveId": "CVE-2023-0001",
			"state": "PUBLISHED",
			"assignerShortName": "vendor1"
		},
		"containers": {"cna": {}}
	}`

	// CVE with CNA "vendor2"
	cve2 := `{
		"cveMetadata": {
			"cveId": "CVE-2023-0002",
			"state": "PUBLISHED",
			"assignerShortName": "vendor2"
		},
		"containers": {"cna": {}}
	}`

	file1 := filepath.Join(tmpDir, "CVE-2023-0001.json")
	file2 := filepath.Join(tmpDir, "CVE-2023-0002.json")

	if err := os.WriteFile(file1, []byte(cve1), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	if err := os.WriteFile(file2, []byte(cve2), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	files := []string{file1, file2}
	linter := &Linter{
		Timestamp: time.Now().UTC(),
		FileInput: &files,
	}

	dummyRule := Rule{
		Code:        "DUMMY",
		Name:        "dummy",
		Description: "Dummy rule",
		CheckFunc: func(j *string) []rules.ValidationError {
			return []rules.ValidationError{}
		},
	}

	selectedRules := []Rule{dummyRule}

	// Filter for vendor1 only
	linter.Run(&selectedRules, "vendor1")

	// Should have checked only 1 file
	if linter.FilesChecked != 1 {
		t.Errorf("Expected 1 file checked with CNA filter 'vendor1', got %d", linter.FilesChecked)
	}
}

// TestLinter_Run_ResultCollection validates error collection from rules
func TestLinter_Run_ResultCollection(t *testing.T) {
	tmpDir := t.TempDir()

	testCVE := `{
		"cveMetadata": {
			"cveId": "CVE-2023-0001",
			"state": "PUBLISHED",
			"assignerShortName": "vendor"
		},
		"containers": {"cna": {}}
	}`

	file := filepath.Join(tmpDir, "CVE-2023-0001.json")
	if err := os.WriteFile(file, []byte(testCVE), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	files := []string{file}
	linter := &Linter{
		Timestamp: time.Now().UTC(),
		FileInput: &files,
	}

	// Rule that generates 2 errors
	errorRule := Rule{
		Code:        "ERR001",
		Name:        "test-error",
		Description: "Test error rule",
		CheckFunc: func(j *string) []rules.ValidationError {
			return []rules.ValidationError{
				{Text: "Error 1", JsonPath: "path.1"},
				{Text: "Error 2", JsonPath: "path.2"},
			}
		},
	}

	selectedRules := []Rule{errorRule}
	linter.Run(&selectedRules, "")

	if len(linter.Results) != 2 {
		t.Errorf("Expected 2 errors collected, got %d", len(linter.Results))
	}
	if linter.Results[0].Error.Text != "Error 1" {
		t.Errorf("Expected error text 'Error 1', got '%s'", linter.Results[0].Error.Text)
	}
}

// TestLinter_Run_InvalidJSON validates error handling for invalid JSON
func TestLinter_Run_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()

	invalidJSON := `{ this is not valid json }`

	file := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(file, []byte(invalidJSON), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	files := []string{file}
	linter := &Linter{
		Timestamp: time.Now().UTC(),
		FileInput: &files,
	}

	dummyRule := Rule{
		Code: "DUMMY",
		CheckFunc: func(j *string) []rules.ValidationError {
			return nil
		},
	}

	selectedRules := []Rule{dummyRule}
	linter.Run(&selectedRules, "")

	if len(linter.GenericErrors) == 0 {
		t.Errorf("Expected generic error for invalid JSON, got none")
	}
	if !strings.Contains(linter.GenericErrors[0], "invalid JSON") {
		t.Errorf("Expected 'invalid JSON' error, got: %s", linter.GenericErrors[0])
	}
}

// TestLinter_Print_TextFormat validates text format output content
func TestLinter_Print_TextFormat(t *testing.T) {
	files := []string{"test.json"}
	linter := &Linter{
		Timestamp:    time.Now().UTC(),
		FileInput:    &files,
		FilesChecked: 1,
		Results: []LintResult{
			{
				File:  "test.json",
				CveId: "CVE-2023-0001",
				Cna:   "vendor",
				Error: rules.ValidationError{
					Text:     "Test error",
					JsonPath: "path.to.error",
				},
				Rule: Rule{
					Code:        "E001",
					Name:        "test-rule",
					Description: "Test",
				},
			},
		},
	}

	output := captureStdout(t, func() { linter.Print("text") })

	if !strings.Contains(output, "CVE-2023-0001") {
		t.Errorf("Text output missing CVE ID, got: %s", output)
	}
	if !strings.Contains(output, "E001") {
		t.Errorf("Text output missing error code, got: %s", output)
	}
	if !strings.Contains(output, "Test error") {
		t.Errorf("Text output missing error text, got: %s", output)
	}
	if !strings.Contains(output, "path.to.error") {
		t.Errorf("Text output missing JSON path, got: %s", output)
	}
}

// TestLinter_Print_JSONFormat validates JSON output format content
func TestLinter_Print_JSONFormat(t *testing.T) {
	files := []string{"test.json"}
	linter := &Linter{
		Timestamp:    time.Now().UTC(),
		FileInput:    &files,
		FilesChecked: 1,
		Results: []LintResult{
			{
				File:  "test.json",
				CveId: "CVE-2023-0001",
				Cna:   "vendor",
				Error: rules.ValidationError{
					Text:     "Test error",
					JsonPath: "path.to.error",
				},
				Rule: Rule{
					Code: "E001",
					Name: "test-rule",
				},
			},
		},
	}

	output := captureStdout(t, func() { linter.Print("json") })

	if !strings.Contains(output, `"cve": "CVE-2023-0001"`) {
		t.Errorf("JSON output missing CVE ID, got: %s", output)
	}
	if !strings.Contains(output, `"errorCode": "E001"`) {
		t.Errorf("JSON output missing error code, got: %s", output)
	}
	if !strings.Contains(output, `"results"`) {
		t.Errorf("JSON output missing results key, got: %s", output)
	}
}

// TestLinter_Print_CSVFormat validates CSV output format content
func TestLinter_Print_CSVFormat(t *testing.T) {
	files := []string{"test.json"}
	linter := &Linter{
		Timestamp:    time.Now().UTC(),
		FileInput:    &files,
		FilesChecked: 1,
		Results: []LintResult{
			{
				File:  "test.json",
				CveId: "CVE-2023-0001",
				Cna:   "vendor",
				Error: rules.ValidationError{
					Text:     "Test error",
					JsonPath: "path.to.error",
				},
				Rule: Rule{
					Code: "E001",
					Name: "test-rule",
				},
			},
		},
	}

	output := captureStdout(t, func() { linter.Print("csv") })

	if !strings.Contains(output, "CVE,CNA,File,RuleName,RuleCode,ErrorPath,ErrorText") {
		t.Errorf("CSV output missing header, got: %s", output)
	}
	if !strings.Contains(output, "CVE-2023-0001") {
		t.Errorf("CSV output missing CVE ID, got: %s", output)
	}
}

// TestLinter_PrintSummary_TextFormat validates summary text output content
func TestLinter_PrintSummary_TextFormat(t *testing.T) {
	files := []string{}
	linter := &Linter{
		Timestamp: time.Now().UTC(),
		FileInput: &files,
		Results: []LintResult{
			{
				CveId: "CVE-2023-0001",
				Cna:   "redhat",
				Rule:  Rule{Code: "E001", Name: "test-rule-1"},
			},
			{
				CveId: "CVE-2023-0002",
				Cna:   "redhat",
				Rule:  Rule{Code: "E001", Name: "test-rule-1"},
			},
			{
				CveId: "CVE-2023-0003",
				Cna:   "ubuntu",
				Rule:  Rule{Code: "E002", Name: "test-rule-2"},
			},
		},
	}

	output := captureStdout(t, func() { linter.PrintSummary("text") })

	if !strings.Contains(output, "redhat") {
		t.Errorf("Summary text missing CNA 'redhat', got: %s", output)
	}
	if !strings.Contains(output, "ubuntu") {
		t.Errorf("Summary text missing CNA 'ubuntu', got: %s", output)
	}
	if !strings.Contains(output, "2") {
		t.Errorf("Summary text missing count '2' for redhat E001, got: %s", output)
	}
}

// TestLinter_PrintSummary_JSONFormat validates summary JSON output content
func TestLinter_PrintSummary_JSONFormat(t *testing.T) {
	files := []string{}
	linter := &Linter{
		Timestamp: time.Now().UTC(),
		FileInput: &files,
		Results: []LintResult{
			{
				Cna:  "redhat",
				Rule: Rule{Code: "E001", Name: "test-rule"},
			},
			{
				Cna:  "redhat",
				Rule: Rule{Code: "E001", Name: "test-rule"},
			},
		},
	}

	output := captureStdout(t, func() { linter.PrintSummary("json") })

	if !strings.Contains(output, `"cna": "redhat"`) {
		t.Errorf("Summary JSON missing CNA, got: %s", output)
	}
	if !strings.Contains(output, `"errorCode": "E001"`) {
		t.Errorf("Summary JSON missing error code, got: %s", output)
	}
	if !strings.Contains(output, `"errorCount": 2`) {
		t.Errorf("Summary JSON missing error count, got: %s", output)
	}
}

// TestLinter_PrintSummary_CSVFormat validates summary CSV output content
func TestLinter_PrintSummary_CSVFormat(t *testing.T) {
	files := []string{}
	linter := &Linter{
		Timestamp: time.Now().UTC(),
		FileInput: &files,
		Results: []LintResult{
			{
				Cna:  "redhat",
				Rule: Rule{Code: "E001", Name: "test-rule-1"},
			},
			{
				Cna:  "ubuntu",
				Rule: Rule{Code: "E002", Name: "test-rule-2"},
			},
		},
	}

	output := captureStdout(t, func() { linter.PrintSummary("csv") })

	if !strings.Contains(output, "CNA,ErrorCode,ErrorName,ErrorCount") {
		t.Errorf("Summary CSV missing header, got: %s", output)
	}
	if !strings.Contains(output, "redhat,E001,test-rule-1,1") {
		t.Errorf("Summary CSV missing redhat row, got: %s", output)
	}
	if !strings.Contains(output, "ubuntu,E002,test-rule-2,1") {
		t.Errorf("Summary CSV missing ubuntu row, got: %s", output)
	}
}

// TestLinter_Run_MultipleRules validates multiple rules execute per file
func TestLinter_Run_MultipleRules(t *testing.T) {
	tmpDir := t.TempDir()

	testCVE := `{
		"cveMetadata": {
			"cveId": "CVE-2023-0001",
			"state": "PUBLISHED",
			"assignerShortName": "vendor"
		},
		"containers": {"cna": {}}
	}`

	file := filepath.Join(tmpDir, "CVE-2023-0001.json")
	if err := os.WriteFile(file, []byte(testCVE), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	files := []string{file}
	linter := &Linter{
		Timestamp: time.Now().UTC(),
		FileInput: &files,
	}

	// Create 3 rules, each generating 1 error
	rules := []Rule{
		{
			Code: "E001",
			CheckFunc: func(j *string) []rules.ValidationError {
				return []rules.ValidationError{{Text: "Error from E001", JsonPath: "path1"}}
			},
		},
		{
			Code: "E002",
			CheckFunc: func(j *string) []rules.ValidationError {
				return []rules.ValidationError{{Text: "Error from E002", JsonPath: "path2"}}
			},
		},
		{
			Code: "E003",
			CheckFunc: func(j *string) []rules.ValidationError {
				return []rules.ValidationError{{Text: "Error from E003", JsonPath: "path3"}}
			},
		},
	}

	linter.Run(&rules, "")

	if len(linter.Results) != 3 {
		t.Errorf("Expected 3 errors (1 per rule), got %d", len(linter.Results))
	}

	// Verify each rule's error is present
	found := make(map[string]bool)
	for _, result := range linter.Results {
		found[result.Rule.Code] = true
	}

	for code := range found {
		if code != "E001" && code != "E002" && code != "E003" {
			t.Errorf("Unexpected rule code: %s", code)
		}
	}
}
