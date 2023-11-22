package main

import (
	"flag"
	"fmt"
	"github.com/mprpic/cvelint/internal"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func collectFiles(args []string) ([]string, error) {
	var files []string
	var dir string
	if len(args) == 0 {
		dir = "."
	} else {
		info, err := os.Stat(args[0])
		if err != nil {
			return files, err
		}
		if info.IsDir() {
			dir = args[0]
		} else {
			if filepath.Ext(info.Name()) != ".json" {
				return files, fmt.Errorf("ERROR: \"%s\" is not a JSON file", args[0])
			}
			files = append(files, args[0])
			return files, nil
		}
	}
	err := filepath.WalkDir(dir, func(f string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(d.Name()) == ".json" {
			files = append(files, f)
		}
		return nil
	})
	return files, err
}

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprintf(w, "Usage of %s: [OPTION] [DIRECTORY|FILE]\n", os.Args[0])
		flag.PrintDefaults()
	}

	var format string
	flag.StringVar(&format, "format", "text", "Output format: text, json, csv")

	var cna string
	flag.StringVar(&cna, "cna", "", "Show results for CVE records of a specific CNA")

	var selectRules string
	flag.StringVar(&selectRules, "select", "", "Comma-separated list of rule codes to enable (default: all)")

	var ignoreRules string
	flag.StringVar(&ignoreRules, "ignore", "", "Comma-separated list of rule codes to disable (default: none)")

	var printRules bool
	flag.BoolVar(&printRules, "show-rules", false, "Print list of available validation rules")

	flag.Parse()
	args := flag.Args()

	if printRules {
		var codes []string
		for code := range internal.RuleSet {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			fmt.Printf("%s: %s\n", code, internal.RuleSet[code].Description)
		}
		os.Exit(0)
	}

	if len(args) != 1 {
		fmt.Println("ERROR: Incorrect number of arguments")
		flag.Usage()
		os.Exit(1)
	}

	files, err := collectFiles(args)
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}
	if len(files) == 0 {
		log.Fatal("ERROR: no CVE record JSON files found")
	}

	var ruleCodes = make(map[string]struct{})
	if selectRules != "" {
		// Select unique specified rule codes
		for _, ruleCode := range strings.Split(selectRules, ",") {
			ruleCodes[ruleCode] = struct{}{}
		}
	} else {
		// Select all rule codes
		for ruleCode, _ := range internal.RuleSet {
			ruleCodes[ruleCode] = struct{}{}
		}
	}
	// Remove ignored rule codes
	for _, ruleCode := range strings.Split(ignoreRules, ",") {
		delete(ruleCodes, ruleCode)
	}

	// Collect Rules from specified rule codes
	var selectedRules []internal.Rule
	for ruleCode, _ := range ruleCodes {
		rule, ok := internal.RuleSet[ruleCode]
		if !ok {
			log.Fatalf("ERROR: unknown rule selected: %s", ruleCode)
		} else {
			selectedRules = append(selectedRules, rule)
		}
	}

	linter := internal.Linter{Timestamp: time.Now().UTC(), FileInput: &files}
	linter.Run(&selectedRules, cna)
	linter.Print(format)
	if len(linter.Results) > 0 {
		os.Exit(1)
	}
}
