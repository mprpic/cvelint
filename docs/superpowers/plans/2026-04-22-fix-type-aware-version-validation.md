# Fix Type-Aware Version Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix PR #18's type-aware version validation so it actually works — wire `validateVersionByType` into `CheckInvalidVersion`, fix broken semver/python validators, extract custom versionType to E011, fix `versionType` JSON path, and fix tests.

**Architecture:** The existing `CheckInvalidVersion` (E007) keeps the generic `validVersionRe` check for all versions and adds a second type-specific check via `validateVersionByType` when `versionType` is declared. Custom versionType detection moves to a new `CheckCustomVersionType` function exposed as E011, independently ignorable. `versionType` is read per-version-entry (not per-affected-entry) per CVE v5 schema.

**Tech Stack:** Go, gjson, packageurl-go, regexp

---

### Task 1: Fix `validateVersionByType` — remove broken guards

**Files:**

- Modify: `internal/rules/affects.go` (the version on branch `origin/issue/15-version-type-validation`)

The `strings.Contains` guards in the semver and python cases reject valid versions. Remove them so the regex patterns do the validation correctly.

- [ ] **Step 1: Remove semver `strings.Contains` guards**

In `validateVersionByType`, replace the semver case:

```go
	case "semver":
		// Reject if it contains pre-release or build metadata
		if strings.Contains(version, "-") || strings.Contains(version, "+") {
			return false
		}
		return semverPattern.MatchString(version)
```

With:

```go
	case "semver":
		return semverPattern.MatchString(version)
```

- [ ] **Step 2: Remove python `strings.Contains` guards**

Replace the python case:

```go
	case "python":
		// Reject if it contains pre-release or build metadata
		if strings.Contains(version, "a") || strings.Contains(version, "b") || strings.Contains(version, "rc") {
			return false
		}
		return pythonPattern.MatchString(version)
```

With:

```go
	case "python":
		return pythonPattern.MatchString(version)
```

- [ ] **Step 3: Remove the `custom` case from `validateVersionByType`**

This will move to E011. Replace:

```go
	case "custom":
		// Custom version type should be avoided per CVE schema docs
		return false
```

With nothing — delete these 3 lines entirely. The `default` case already handles unknown types with the generic regex.

- [ ] **Step 4: Verify the file compiles**

Run: `go build ./...`
Expected: clean build (no errors)

- [ ] **Step 5: Commit**

```bash
git add internal/rules/affects.go
git commit -m "fix: remove broken strings.Contains guards from version validators"
```

---

### Task 2: Wire `validateVersionByType` into `CheckInvalidVersion`

**Files:**

- Modify: `internal/rules/affects.go`

The current `CheckInvalidVersion` uses `validVersionRe` for all non-purl versions but never calls `validateVersionByType`. Wire it in: after the generic regex check passes, if a `versionType` is declared on the version entry, also run the type-specific check.

Also fix the `versionType` path: the CVE v5 schema puts `versionType` at `affected[].versions[].versionType` (per-version-entry), not `affected[].versionType` (per-affected-entry). The current PR reads it from the wrong location.

- [ ] **Step 1: Remove incorrect versionType read and custom check from the affected-level loop**

In `CheckInvalidVersion`, find this block inside the `affected.ForEach` callback:

```go
		// Get the versionType for this affected entry
		versionType := value.Get("versionType").String()

		// Check if versionType is "custom" - should be avoided
		if versionType == "custom" {
			errors = append(errors, ValidationError{
				Text:     "Custom versionType should be avoided per CVE schema documentation",
				JsonPath: value.Path(*json) + ".versionType",
			})
		}
```

Delete this entire block (versionType read + custom check). The custom check moves to E011 in Task 3.

- [ ] **Step 2: Read versionType per-version-entry and add type-specific validation**

Inside the `versions.ForEach` callback, after the existing version/lessThan/lessThanOrEqual checks for each field, add a type-specific check. Find the `versions.ForEach` callback. At the start of the callback body (just inside `versions.ForEach(func(vkey, vvalue gjson.Result) bool {`), add a line to read versionType from each version entry:

```go
			versionType := vvalue.Get("versionType").String()
```

Then, for each of the three version fields (version, lessThan, lessThanOrEqual), after the existing `validVersionRe` check passes for a non-purl version, add a type-specific check. Find each `} else if !validVersionRe.MatchString(...)` block. After its closing `}`, add an `else if` for the type-specific check.

For the `version` field, change:

```go
			} else if !validVersionRe.MatchString(singleVersion) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid version string: \"%s\"", singleVersion),
						JsonPath: vvalue.Get("version").Path(*json),
					})
				}
```

To:

```go
			} else if !validVersionRe.MatchString(singleVersion) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid version string: \"%s\"", singleVersion),
						JsonPath: vvalue.Get("version").Path(*json),
					})
				} else if versionType != "" && !validateVersionByType(singleVersion, versionType) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Version \"%s\" does not match expected format for type \"%s\"", singleVersion, versionType),
						JsonPath: vvalue.Get("version").Path(*json),
					})
				}
```

For the `lessThan` field (after the `} else if !validVersionRe.MatchString(lessThan) {` block), change:

```go
				} else if !validVersionRe.MatchString(lessThan) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid lessThan version string: \"%s\"", lessThan),
						JsonPath: vvalue.Get("lessThan").Path(*json),
					})
				}
```

To:

```go
				} else if !validVersionRe.MatchString(lessThan) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid lessThan version string: \"%s\"", lessThan),
						JsonPath: vvalue.Get("lessThan").Path(*json),
					})
				} else if versionType != "" && !validateVersionByType(lessThan, versionType) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("lessThan version \"%s\" does not match expected format for type \"%s\"", lessThan, versionType),
						JsonPath: vvalue.Get("lessThan").Path(*json),
					})
				}
```

For the `lessThanOrEqual` field, same pattern — change:

```go
				} else if !validVersionRe.MatchString(lessThanOrEqual) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid lessThanOrEqual version string: \"%s\"", lessThanOrEqual),
						JsonPath: vvalue.Get("lessThanOrEqual").Path(*json),
					})
				}
```

To:

```go
				} else if !validVersionRe.MatchString(lessThanOrEqual) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("Invalid lessThanOrEqual version string: \"%s\"", lessThanOrEqual),
						JsonPath: vvalue.Get("lessThanOrEqual").Path(*json),
					})
				} else if versionType != "" && !validateVersionByType(lessThanOrEqual, versionType) {
					errors = append(errors, ValidationError{
						Text:     fmt.Sprintf("lessThanOrEqual version \"%s\" does not match expected format for type \"%s\"", lessThanOrEqual, versionType),
						JsonPath: vvalue.Get("lessThanOrEqual").Path(*json),
					})
				}
```

- [ ] **Step 3: Update the function comment**

Replace:

```go
// CheckInvalidVersion returns an array of detected version-related ValidationError findings.
// It checks that the affected.versions sub-fields are used correctly, including:
// - Type-specific version validation
// - Ensuring "*" is only used in lessThan
// - Avoiding pre-release/build metadata in version ranges
// - Rejecting custom version types
```

With:

```go
// CheckInvalidVersion returns an array of detected version-related ValidationError findings.
// It checks that the affected.versions sub-fields are used correctly, including:
// - Generic character validation via validVersionRe
// - Type-specific version format validation when versionType is declared
// - Ensuring "*" is only used in lessThan, not lessThanOrEqual
```

- [ ] **Step 4: Verify the file compiles**

Run: `go build ./...`
Expected: clean build (no errors)

- [ ] **Step 5: Commit**

```bash
git add internal/rules/affects.go
git commit -m "feat: wire validateVersionByType into CheckInvalidVersion

Read versionType per-version-entry (not per-affected-entry) per CVE v5
schema. Run type-specific validation after generic regex passes."
```

---

### Task 3: Extract custom versionType check to E011

**Files:**

- Modify: `internal/rules/affects.go` — add `CheckCustomVersionType` function
- Modify: `internal/ruleset.go` — register E011

- [ ] **Step 1: Add `CheckCustomVersionType` function to affects.go**

Add this function at the end of `affects.go`, before the `CheckValidVendor` function:

```go
func CheckCustomVersionType(json *string) []ValidationError {
	if gjson.Get(*json, `cveMetadata.state`).String() != "PUBLISHED" {
		return nil
	}
	var errors []ValidationError
	affected := gjson.Get(*json, `containers.cna.affected`)
	affected.ForEach(func(key, value gjson.Result) bool {
		versions := value.Get("versions")
		versions.ForEach(func(vkey, vvalue gjson.Result) bool {
			if vvalue.Get("versionType").String() == "custom" {
				errors = append(errors, ValidationError{
					Text:     "Custom versionType should be avoided per CVE schema documentation",
					JsonPath: vvalue.Get("versionType").Path(*json),
				})
			}
			return true
		})
		return true
	})
	return errors
}
```

- [ ] **Step 2: Register E011 in ruleset.go**

Add to the `RuleSet` map in `internal/ruleset.go`:

```go
	"E011": {
		Code:        "E011",
		Name:        "check-custom-version-type",
		Description: "Version type is not set to 'custom' (should be avoided per schema docs)",
		CheckFunc:   rules.CheckCustomVersionType,
	},
```

- [ ] **Step 3: Verify the project compiles**

Run: `go build ./...`
Expected: clean build (no errors)

- [ ] **Step 4: Commit**

```bash
git add internal/rules/affects.go internal/ruleset.go
git commit -m "feat: extract custom versionType check to E011

Users can now independently ignore custom versionType warnings with
--ignore E011 since it is a 'should avoid' not an error per the schema."
```

---

### Task 4: Fix and expand tests

**Files:**

- Modify: `internal/rules/affects_test.go`

The existing tests need fixes: remove the "Custom versionType" test from `TestCheckInvalidVersion` (moved to E011), fix the "Invalid git hash" test expectation, add type-specific validation tests, and add `TestCheckCustomVersionType`.

- [ ] **Step 1: Write the updated `TestCheckInvalidVersion`**

Replace the entire `TestCheckInvalidVersion` function with test cases that match the actual behavior. Key changes:

- Remove the "Custom versionType should be avoided" test case (now E011)
- Fix "Invalid git commit hash" — it now correctly expects 1 error (type-specific check fires)
- Add a test for valid semver with pre-release (`1.0.0-beta.1` should pass)
- Move `versionType` into each version entry (not the affected entry)

```go
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
```

- [ ] **Step 2: Add `TestCheckCustomVersionType` for E011**

Add this function after `TestCheckInvalidVersion`:

```go
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
```

- [ ] **Step 3: Run all tests**

Run: `go test ./internal/rules/ -v`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add internal/rules/affects_test.go
git commit -m "test: fix and expand version validation tests

Move versionType to per-version-entry, remove custom versionType test
from E007 (now E011), fix git hash test expectation, add semver
pre-release and no-versionType-fallback test cases."
```

---

### Task 5: Verify full build and run

- [ ] **Step 1: Run full build**

Run: `go build ./...`
Expected: clean build

- [ ] **Step 2: Run all tests**

Run: `go test ./... -v`
Expected: all tests pass

- [ ] **Step 3: Run the linter with `--show-rules` to verify E011 appears**

Run: `go run ./cmd/cvelint --show-rules`
Expected: E011 appears in the output with name `check-custom-version-type`
