package internal

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/mprpic/cvelint/internal/rules"
	"github.com/tidwall/gjson"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Linter struct {
	Timestamp     time.Time
	FileInput     *[]string
	FilesChecked  int
	Results       []LintResult
	GenericErrors []string
}

type LintResult struct {
	File  string
	CveId string
	Cna   string
	Error rules.ValidationError
	Rule
}

func (l *Linter) Run(selectedRules *[]Rule, cna string) {
	var checkedFiles int64
	lintResultsChan := make(chan LintResult)
	genErrorChan := make(chan string)
	var wg sync.WaitGroup

	fmt.Fprintf(os.Stderr, "Processing CVE records...\r")
	for _, file := range *l.FileInput {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			cveId := strings.TrimSuffix(file[strings.LastIndex(file, "/")+1:], ".json")
			content, err := os.ReadFile(file)
			if err != nil {
				genErrorChan <- "Could not read file: " + file
				return
			}
			// Convert to string because gjson.Result.Path does not accept []byte
			jsonText := string(content)
			if !gjson.Valid(jsonText) {
				genErrorChan <- "File contains invalid JSON: " + file
				return
			}
			recordCna := gjson.Get(jsonText, "cveMetadata.assignerShortName").String()
			if recordCna == "" {
				// Not a CVE v5 JSON record, skip.
				return
			}
			if cna != "" && cna != recordCna {
				return
			}
			for _, rule := range *selectedRules {
				errors := rule.CheckFunc(&jsonText)
				for _, e := range errors {
					lintResultsChan <- LintResult{
						File:  file,
						CveId: cveId,
						Cna:   recordCna,
						Error: e,
						Rule:  rule,
					}
				}
			}
			atomic.AddInt64(&checkedFiles, 1)
		}(file)
	}

	go func() {
		wg.Wait()
		close(genErrorChan)
		close(lintResultsChan)
	}()

	// Collect errors and lint results from both channels until they are empty.
	for {
		select {
		case lintResult, ok := <-lintResultsChan:
			if !ok {
				lintResultsChan = nil
			} else {
				l.Results = append(l.Results, lintResult)
			}
		case genErr, ok := <-genErrorChan:
			if !ok {
				genErrorChan = nil
			} else {
				l.GenericErrors = append(l.GenericErrors, genErr)
			}
		}
		if lintResultsChan == nil && genErrorChan == nil {
			break
		}
	}

	sort.Slice(l.Results, func(i, j int) bool {
		// Sort results alphanumerically by CVE ID (starting from newest)
		a := strings.Split(l.Results[i].CveId, "-") // CVE-2020-0001 -> [CVE 2020 0001]
		b := strings.Split(l.Results[j].CveId, "-")
		// Compare year first
		yearA, _ := strconv.Atoi(a[1])
		yearB, _ := strconv.Atoi(b[1])
		if yearA != yearB {
			return yearA > yearB
		}
		// Compare ID second if year is the same
		i, _ = strconv.Atoi(a[2])
		j, _ = strconv.Atoi(b[2])
		return i > j
	})
	fmt.Fprintf(os.Stderr, "\r\033[K")
	l.FilesChecked = int(atomic.LoadInt64(&checkedFiles))
}

func (l *Linter) Print(format string) {
	switch format {
	case "text":
		fmt.Printf("Collected %d file", len(*l.FileInput))
		if len(*l.FileInput) != 1 {
			fmt.Print("s")
		}
		fmt.Printf("; checked %d file", l.FilesChecked)
		if l.FilesChecked != 1 {
			fmt.Println("s.")
		} else {
			fmt.Println(".")
		}

		if len(l.GenericErrors) > 0 {
			fmt.Println()
			for _, e := range l.GenericErrors {
				fmt.Printf("ERROR: %s", e)
			}
			fmt.Println()
		}

		bold := color.New(color.Bold).Add(color.Underline)
		red := color.New(color.FgRed)
		lastCve := ""
		for _, r := range l.Results {
			if lastCve != r.CveId {
				fmt.Println()
				bold.Print(r.CveId)
				fmt.Printf(" (%s) -- %s\n", r.Cna, r.File)
			}
			lastCve = r.CveId
			fmt.Print("  ")
			red.Printf("%s  ", r.Code)
			fmt.Print(r.Error.Text)
			if r.Error.JsonPath != "" {
				fmt.Printf(" (at \"%s\")\n", r.Error.JsonPath)
			} else {
				fmt.Println()
			}
		}

		fmt.Printf("\nFound %d error", len(l.Results)+len(l.GenericErrors))
		if len(l.Results) != 1 {
			fmt.Print("s.\n")
		} else {
			fmt.Print(".\n")
		}

	case "json":
		fmt.Println("{")
		fmt.Printf(`  "generatedAt": "%s",`+"\n", l.Timestamp.Format(time.RFC3339))
		fmt.Println(`  "results": [`)
		for i, r := range l.Results {
			fmt.Println("    {")
			errorJson, _ := json.Marshal(r.Error.Text)
			fmt.Printf(`      "cve": "%s",`+"\n", r.CveId)
			fmt.Printf(`      "cna": "%s",`+"\n", r.Cna)
			fmt.Printf(`      "file": "%s",`+"\n", r.File)
			fmt.Printf(`      "ruleName": "%s",`+"\n", r.Rule.Name)
			fmt.Printf(`      "errorCode": "%s",`+"\n", r.Rule.Code)
			fmt.Printf(`      "errorPath": "%s",`+"\n", r.Error.JsonPath)
			fmt.Printf(`      "errorText": %s`+"\n", errorJson)
			fmt.Print("    }")
			if i+1 != len(l.Results) {
				fmt.Print(",")
			}
			fmt.Println()
		}
		fmt.Println("  ]")
		fmt.Println("}")

	case "csv":
		if len(l.Results) == 0 {
			return
		}
		fmt.Println("CVE,CNA,File,RuleName,RuleCode,ErrorPath,ErrorText")
		for _, r := range l.Results {
			fmt.Printf("%s,%s,%s,%s,%s,%s,%s\n", r.CveId, r.Cna, r.File, r.Rule.Name, r.Rule.Code, r.Error.JsonPath, r.Error.Text)
		}

	default:
		log.Fatal("ERROR: Invalid output format, must be one of: text, json, csv")
	}
}

func (l *Linter) PrintSummary(format string) {
	// Collect error count per error code for each org
	orgSummary := make(map[string]map[string]int)
	longestErrorLen := 0
	for _, result := range l.Results {
		if _, exists := orgSummary[result.Cna]; !exists {
			orgSummary[result.Cna] = make(map[string]int)
		}
		errorStr := fmt.Sprintf("%s %s", result.Rule.Code, result.Rule.Name)
		if len(errorStr) > longestErrorLen {
			longestErrorLen = len(errorStr)
		}
		orgSummary[result.Cna][errorStr]++
	}

	// Get a sorted list of all orgs
	orgs := make([]string, 0, len(orgSummary))
	for org, _ := range orgSummary {
		orgs = append(orgs, org)
	}
	sort.Strings(orgs)

	switch format {
	case "text":
		bold := color.New(color.Bold).Add(color.Underline)
		red := color.New(color.FgRed)

		for _, org := range orgs {
			errors := orgSummary[org]

			// Get sorted error codes for consistent output
			errorCodes := make([]string, 0, len(errors))
			for code := range errors {
				errorCodes = append(errorCodes, code)
			}
			sort.Strings(errorCodes)

			// Print organization name once
			bold.Println(org)

			// Print all errors with consistent indentation
			for _, errorCode := range errorCodes {
				count := errors[errorCode]
				e := strings.Split(errorCode, " ")
				red.Printf("  %s ", e[0])
				fmt.Printf("%-*s%d\n", longestErrorLen-3, e[1], count)
			}

			// Add empty line between organizations
			fmt.Println("")
		}

	case "json":
		fmt.Println("{")
		fmt.Printf(`  "generatedAt": "%s",`+"\n", l.Timestamp.Format(time.RFC3339))
		fmt.Println(`  "results": [`)

		for i, org := range orgs {
			errors := orgSummary[org]

			// Get sorted error codes for consistent output
			errorCodes := make([]string, 0, len(errors))
			for code := range errors {
				errorCodes = append(errorCodes, code)
			}
			sort.Strings(errorCodes)

			fmt.Println("    {")
			fmt.Printf(`      "cna": "%s",`+"\n", org)
			fmt.Println(`      "errors": [`)

			for j, errorCode := range errorCodes {
				count := errors[errorCode]
				e := strings.Split(errorCode, " ")
				fmt.Printf(`        {"errorCode": "%s", "errorName": "%s", "errorCount": %d}`, e[0], e[1], count)
				if j+1 != len(errorCodes) {
					fmt.Print(",")
				}
				fmt.Println()
			}

			fmt.Println(`      ]`)
			fmt.Print(`    }`)
			if i+1 != len(orgs) {
				fmt.Print(",")
			}
			fmt.Println()
		}

		fmt.Println("  ]")
		fmt.Println("}")

	case "csv":
		if len(l.Results) == 0 {
			return
		}
		fmt.Println("CNA,ErrorCode,ErrorName,ErrorCount")
		for _, org := range orgs {
			errors := orgSummary[org]

			// Get sorted error codes for consistent output
			errorCodes := make([]string, 0, len(errors))
			for code := range errors {
				errorCodes = append(errorCodes, code)
			}
			sort.Strings(errorCodes)

			for _, errorCode := range errorCodes {
				count := errors[errorCode]
				e := strings.Split(errorCode, " ")
				fmt.Printf("%s,%s,%s,%d\n", org, e[0], e[1], count)
			}
		}

	default:
		log.Fatal("ERROR: Invalid output format, must be one of: text, json, csv")
	}
}
