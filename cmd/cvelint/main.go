package main

import (
	"flag"
	"fmt"
	"github.com/mprpic/cvelint/internal"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func determineCachePath() string {
	cachePath := os.Getenv("CVELINT_CACHE_DIR")
	if cachePath != "" {
		return cachePath
	}

	xdgCachePath := os.Getenv("XDG_CACHE_HOME")
	if xdgCachePath != "" {
		cachePath = filepath.Join(xdgCachePath, "cvelint")
	}
	// Default to $HOME/.cache on Linux/macOS or %APPDATA%/ on Windows
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("ERROR: unable to determine home directory:", err)
		return ".cache" // Default to local directory
	}
	if os.PathSeparator == '\\' {
		return filepath.Join(homeDir, "AppData", "Local", "cvelint")
	} else {
		return filepath.Join(homeDir, ".cache", "cvelint")
	}
}

func cloneOrUpdateRepo(repoDir string) error {
	_, err := os.Stat(repoDir)
	pullCmd := exec.Command("git", "-C", repoDir, "pull", "--rebase")
	if os.IsNotExist(err) {
		cloneCmd := exec.Command("git", "clone", "https://github.com/CVEProject/cvelistV5.git", repoDir)
		if err := cloneCmd.Run(); err != nil {
			return fmt.Errorf("failed to clone repository: %v", err)
		}
		if err := pullCmd.Run(); err != nil {
			return fmt.Errorf("failed to update repository: %v", err)
		}
	} else {
		// This file is updated on every `git pull`/`git fetch`; we can use it to check if our cache is stale.
		fetchHeadFile := filepath.Join(repoDir, ".git", "FETCH_HEAD")
		info, err := os.Stat(fetchHeadFile)
		if os.IsNotExist(err) || time.Since(info.ModTime()) > 60*time.Minute {
			// Update repo if it hasn't been updated for more than an hour
			if err := pullCmd.Run(); err != nil {
				return fmt.Errorf("failed to update repository: %v", err)
			}
		}
	}
	return nil
}

func collectFiles(args []string) ([]string, error) {
	var files []string
	var dir string
	if len(args) == 0 {
		cachePath := determineCachePath()
		if err := os.MkdirAll(cachePath, os.ModePerm); err != nil {
			fmt.Println("ERROR: could not create cache directory:", err)
			return files, err
		}
		dir = filepath.Join(cachePath, "cvelistV5")
		// Clone or update the local cvelistV5 repository
		if err := cloneOrUpdateRepo(dir); err != nil {
			return files, err
		}
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
		fmt.Fprintf(w, "\nIf no directory or file is specified, a clone of the cvelistV5 repo is stored in\n")
		fmt.Fprintf(w, "the location pointed to in CVELINT_CACHE_DIR, or a standard OS cache location.\n\n")
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
		for ruleCode := range internal.RuleSet {
			ruleCodes[ruleCode] = struct{}{}
		}
	}
	// Remove ignored rule codes
	for _, ruleCode := range strings.Split(ignoreRules, ",") {
		delete(ruleCodes, ruleCode)
	}

	// Collect Rules from specified rule codes
	var selectedRules []internal.Rule
	for ruleCode := range ruleCodes {
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
	if len(linter.Results) > 0 || len(linter.GenericErrors) > 0 {
		os.Exit(1)
	}
}
