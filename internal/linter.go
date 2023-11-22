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
	"time"
)

type Linter struct {
	Timestamp    time.Time
	FileInput    *[]string
	FilesChecked int
	Results      []LintResult
}

type LintResult struct {
	File  string
	CveId string
	Cna   string
	Error rules.ValidationError
	Rule
}

func (l *Linter) Run(rules *[]Rule, cna string) {
	checkedFiles := 0
	for _, file := range *l.FileInput {
		cveId := strings.TrimSuffix(file[strings.LastIndex(file, "/")+1:], ".json")
		jsonBytes, err := os.ReadFile(file)
		// Convert to string because gjson.Result.Path does not accept []byte
		json := string(jsonBytes)
		if err != nil {
			log.Fatalf("ERROR: failed to read JSON file %v", err)
		}
		if !gjson.Valid(json) {
			log.Fatalf("ERROR: invalid JSON file %s", file)
		}
		recordCna := gjson.Get(json, "cveMetadata.assignerShortName").String()
		if recordCna == "" {
			// Not a CVE v5 JSON record, skip.
			continue
		}
		if cna != "" && cna != recordCna {
			continue
		}
		for _, rule := range *rules {
			errors := rule.CheckFunc(&json)
			for _, e := range errors {
				l.Results = append(l.Results, LintResult{
					File:  file,
					CveId: cveId,
					Cna:   recordCna,
					Error: e,
					Rule:  rule,
				})
			}
		}
		checkedFiles++

		sort.Slice(l.Results, func(i, j int) bool {
			// Sort results alphanumerically by CVE ID (starting from newest)
			a := strings.Split(l.Results[i].CveId, "-") // CVE-2020-0001 -> [CVE 2020 0001]
			b := strings.Split(l.Results[j].CveId, "-")
			i, _ = strconv.Atoi(strings.Join(a[1:], "")) // 20200001
			j, _ = strconv.Atoi(strings.Join(b[1:], ""))
			return i > j
		})
	}
	l.FilesChecked = checkedFiles
}

func (l *Linter) Print(format string) {
	switch format {
	case "text":
		fmt.Printf("")
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

		fmt.Printf("\nFound %d error", len(l.Results))
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
		fmt.Println("CVE,CNA,File,RuleName,ErrorCode,ErrorText")
		for _, r := range l.Results {
			fmt.Printf("%s,%s,%s,%s,%s,%s,%s\n", r.CveId, r.Cna, r.File, r.Rule.Name, r.Rule.Code, r.Error.JsonPath, r.Error.Text)
		}

	default:
		log.Fatal("ERROR: Invalid output format, must be one of: text, json, csv")
	}
}
