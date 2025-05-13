package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

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
		var reports []analyzer.ReportItem
		var err error
		var projectType string

		// --- Detect Project Type & Run Analyzer ---
		pkgFile := filepath.Join(analyzePath, "package.json")
		if _, errStat := os.Stat(pkgFile); errStat == nil {
			projectType = "npm"
			fmt.Printf("Detected npm project at %s\n", analyzePath)
			a := analyzer.NewNpmAnalyzer()
			reports, err = a.Analyze(analyzePath)
			if err != nil {
				return fmt.Errorf("npm analysis failed: %w", err)
			}
		} else {
			// Check for .NET/NuGet project by presence of .csproj files
			// (Simplified detection; analyzer does a deeper search)
			csprojFiles, _ := filepath.Glob(filepath.Join(analyzePath, "*.csproj"))
			if len(csprojFiles) == 0 {
				_ = filepath.WalkDir(analyzePath, func(path string, d os.DirEntry, walkErr error) error {
					if walkErr != nil { return walkErr }
					if !d.IsDir() && filepath.Ext(d.Name()) == ".csproj" {
						csprojFiles = append(csprojFiles, path)
						return filepath.SkipDir
					}
					return nil
				})
			}

			if len(csprojFiles) > 0 {
				projectType = "nuget"
				fmt.Printf("Detected .NET project in %s (found .csproj files)\n", analyzePath)
				a := analyzer.NewNuGetAnalyzer()
				reports, err = a.Analyze(analyzePath)
				if err != nil {
					return fmt.Errorf("nuget analysis failed: %w", err)
				}
			} else {
				// Check for Python/Pip project by presence of requirements.txt
				var reqFiles []string
				rootReq := filepath.Join(analyzePath, "requirements.txt")
				if _, errStat := os.Stat(rootReq); errStat == nil {
					reqFiles = append(reqFiles, rootReq)
				} else {
					// Also check subdirectories, though less common for the primary file
					_ = filepath.WalkDir(analyzePath, func(path string, d os.DirEntry, walkErr error) error {
						if walkErr != nil { return walkErr }
						if !d.IsDir() && d.Name() == "requirements.txt" {
							reqFiles = append(reqFiles, path)
							// Don't SkipDir, might be multiple (though PipAnalyzer handles this)
						}
						return nil
					})
				}

				if len(reqFiles) > 0 {
					projectType = "pip"
					fmt.Printf("Detected Python project in %s (found requirements.txt)\n", analyzePath)
					a := analyzer.NewPipAnalyzer()
					reports, err = a.Analyze(analyzePath)
					if err != nil {
						return fmt.Errorf("pip analysis failed: %w", err)
					}
				} else {
					return fmt.Errorf("no supported manifest found in %s (checked for package.json, *.csproj, requirements.txt)", analyzePath)
				}
			}
		}

		// --- Output Report ---
		if format == "json" {
			out, errJson := json.MarshalIndent(reports, "", "  ")
			if errJson != nil {
				return fmt.Errorf("failed to marshal report to JSON: %w", errJson)
			}
			fmt.Println(string(out))
		} else { // Default to text format
			if len(reports) > 0 {
				printTextReport(reports)
			} else {
				fmt.Println("No dependencies found or analyzed for project type:", projectType)
			}
		}

		return nil
	},
}

// printTextReport formats and prints the dependency analysis report as a table.
func printTextReport(reports []analyzer.ReportItem) {
	const notesLimit = 60 // Max characters for notes column

	// Initialize tabwriter
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0) // minwidth, tabwidth, padding, padchar, flags

	// Print header
	fmt.Fprintln(w, "NAME\tCURRENT\tLATEST\tSEVERITY\tCOMPAT\tDEPREC\tNOTES")
	fmt.Fprintln(w, "----\t-------\t------\t--------\t------\t------\t-----")

	// Print data rows
	for _, r := range reports {
		notes := r.Notes
		if len(notes) > notesLimit {
			notes = notes[:notesLimit-3] + "..."
		}
		notes = strings.ReplaceAll(notes, "\t", " ") // Replace tabs to avoid breaking alignment

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%t\t%s\n",
			r.Name,
			r.CurrentVersion,
			r.LatestVersion,
			r.Severity,
			r.Compatible,
			r.Deprecated,
			notes,
		)
	}

	// Flush the writer to print the table
	w.Flush()
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringVarP(&analyzePath, "path", "p", ".", "Path to project directory to analyze")
	analyzeCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
}
