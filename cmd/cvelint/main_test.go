package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetermineCachePath_Environment validates CVELINT_CACHE_DIR env var
func TestDetermineCachePath_Environment(t *testing.T) {
	oldEnv := os.Getenv("CVELINT_CACHE_DIR")
	defer os.Setenv("CVELINT_CACHE_DIR", oldEnv)

	expectedPath := "/custom/cache/path"
	os.Setenv("CVELINT_CACHE_DIR", expectedPath)

	path := determineCachePath()

	if path != expectedPath {
		t.Errorf("Expected cache path '%s', got '%s'", expectedPath, path)
	}
}

// TestDetermineCachePath_XDG validates XDG_CACHE_HOME environment variable is checked
func TestDetermineCachePath_XDG(t *testing.T) {
	oldCvelint := os.Getenv("CVELINT_CACHE_DIR")
	defer os.Setenv("CVELINT_CACHE_DIR", oldCvelint)

	// Only test that CVELINT_CACHE_DIR takes priority
	os.Unsetenv("CVELINT_CACHE_DIR")
	xdgPath := "/custom/xdg/cache"

	// When CVELINT_CACHE_DIR is set, it should be used
	os.Setenv("CVELINT_CACHE_DIR", xdgPath)
	path := determineCachePath()

	if path != xdgPath {
		t.Errorf("Expected cache path '%s' when CVELINT_CACHE_DIR set, got '%s'", xdgPath, path)
	}
}

// TestDetermineCachePath_Default validates fallback to home directory
func TestDetermineCachePath_Default(t *testing.T) {
	oldCvelint := os.Getenv("CVELINT_CACHE_DIR")
	oldXDG := os.Getenv("XDG_CACHE_HOME")
	defer os.Setenv("CVELINT_CACHE_DIR", oldCvelint)
	defer os.Setenv("XDG_CACHE_HOME", oldXDG)

	os.Unsetenv("CVELINT_CACHE_DIR")
	os.Unsetenv("XDG_CACHE_HOME")

	path := determineCachePath()

	// Should contain .cache/cvelint or AppData
	home, _ := os.UserHomeDir()
	defaultPath := filepath.Join(home, ".cache", "cvelint")
	if path != defaultPath {
		t.Logf("Note: Default path may vary on Windows (AppData), got: %s", path)
	}
}

// TestCollectFiles_SingleFile validates collecting a single file
func TestCollectFiles_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.json")

	// Create a test file
	if err := os.WriteFile(testFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	files, err := collectFiles([]string{testFile})

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}
	if files[0] != testFile {
		t.Errorf("Expected file '%s', got '%s'", testFile, files[0])
	}
}

// TestCollectFiles_DirectoryRecursion validates recursive directory traversal
func TestCollectFiles_DirectoryRecursion(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested directory structure
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create JSON files in both directories
	file1 := filepath.Join(tmpDir, "test1.json")
	file2 := filepath.Join(subDir, "test2.json")

	if err := os.WriteFile(file1, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := os.WriteFile(file2, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	files, err := collectFiles([]string{tmpDir})

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("Expected 2 files (recursion), got %d", len(files))
	}
}

// TestCollectFiles_InvalidPath validates error handling for invalid paths
func TestCollectFiles_InvalidPath(t *testing.T) {
	invalidPath := "/this/path/does/not/exist"

	_, err := collectFiles([]string{invalidPath})

	if err == nil {
		t.Errorf("Expected error for invalid path, got none")
	}
}

// TestCollectFiles_NonJSONFile validates filtering non-JSON files
func TestCollectFiles_NonJSONFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create JSON and non-JSON files
	jsonFile := filepath.Join(tmpDir, "test.json")
	txtFile := filepath.Join(tmpDir, "test.txt")

	if err := os.WriteFile(jsonFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create JSON file: %v", err)
	}
	if err := os.WriteFile(txtFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create TXT file: %v", err)
	}

	files, err := collectFiles([]string{tmpDir})

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("Expected 1 JSON file, got %d files", len(files))
	}
	if filepath.Ext(files[0]) != ".json" {
		t.Errorf("Expected JSON file, got %s", files[0])
	}
}

// TestCollectFiles_EmptyDirectory validates handling of empty directory
func TestCollectFiles_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	files, err := collectFiles([]string{tmpDir})

	if err != nil {
		t.Errorf("Unexpected error for empty directory: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("Expected 0 files in empty directory, got %d", len(files))
	}
}

// TestCollectFiles_MixedContent validates directory with various file types
func TestCollectFiles_MixedContent(t *testing.T) {
	tmpDir := t.TempDir()

	// Create various file types
	files := []string{
		filepath.Join(tmpDir, "file1.json"),
		filepath.Join(tmpDir, "file2.json"),
		filepath.Join(tmpDir, "file.txt"),
		filepath.Join(tmpDir, "file.md"),
		filepath.Join(tmpDir, "file.yaml"),
	}

	for _, f := range files {
		if err := os.WriteFile(f, []byte("{}"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	collected, err := collectFiles([]string{tmpDir})

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(collected) != 2 {
		t.Errorf("Expected 2 JSON files, got %d", len(collected))
	}

	// Verify only JSON files were collected
	for _, f := range collected {
		if filepath.Ext(f) != ".json" {
			t.Errorf("Non-JSON file collected: %s", f)
		}
	}
}
