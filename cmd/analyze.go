package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/sambabib/dependency-checker/pkg/analyzer"
)

var analyzePath string
var format string // output format: text or json

// analyzeCmd represents the analyze subcommand
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze project dependencies",
	Long:  "Analyze the project's dependencies and report outdated or deprecated packages.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Determine project type by presence of package.json
		pkgFile := filepath.Join(analyzePath, "package.json")
		if _, err := os.Stat(pkgFile); err == nil {
			fmt.Printf("Detected npm project at %s\n", analyzePath)
			a := analyzer.NewNpmAnalyzer()
			reports, err := a.Analyze(analyzePath)
			if err != nil {
				return fmt.Errorf("npm analysis failed: %w", err)
			}
			if format == "json" {
				out, err := json.MarshalIndent(reports, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal report to JSON: %w", err)
				}
				fmt.Println(string(out))
				return nil
			}
			// Print report items (text format)
			for _, r := range reports {
				fmt.Printf("%-30s current: %-10s latest: %-10s severity: %s compatible: %v\n",
					r.Name, r.CurrentVersion, r.LatestVersion, r.Severity, r.Compatible)
			}
			return nil
		}

		// Check for .NET/NuGet project by presence of .csproj files
		// NuGetAnalyzer.Analyze will perform a deeper search for .csproj files, 
		// here we just need to detect if it's likely a .NET project.
		csprojFiles, _ := filepath.Glob(filepath.Join(analyzePath, "*.csproj"))
		if len(csprojFiles) == 0 {
			// Try to find in subdirectories as well, common for solution structures
			_ = filepath.WalkDir(analyzePath, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err // Propagate errors
				}
				if !d.IsDir() && filepath.Ext(d.Name()) == ".csproj" {
					csprojFiles = append(csprojFiles, path)
					return filepath.SkipDir // Found one, no need to go deeper in this branch for detection
				}
				return nil
			})
		}

		if len(csprojFiles) > 0 {
			fmt.Printf("Detected .NET project in %s (found .csproj files)\n", analyzePath)
			nugetAnalyzer := analyzer.NewNuGetAnalyzer()
			reports, err := nugetAnalyzer.Analyze(analyzePath)
			if err != nil {
				return fmt.Errorf("nuget analysis failed: %w", err)
			}
			if format == "json" {
				out, err := json.MarshalIndent(reports, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal report to JSON: %w", err)
				}
				fmt.Println(string(out))
				return nil
			}
			for _, r := range reports {
				fmt.Printf("%-30s current: %-10s latest: %-10s severity: %s compatible: %v\n",
					r.Name, r.CurrentVersion, r.LatestVersion, r.Severity, r.Compatible)
			}
			return nil
		}

		return fmt.Errorf("no supported manifest found in %s (checked for package.json and *.csproj files)", analyzePath)
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringVarP(&analyzePath, "path", "p", ".", "Path to project directory to analyze")
	analyzeCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
}
