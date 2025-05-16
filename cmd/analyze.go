package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sambabib/dependency-checker/pkg/analyzer"
	"github.com/sambabib/dependency-checker/pkg/config"
	"github.com/sambabib/dependency-checker/pkg/logger"
	"github.com/sambabib/dependency-checker/pkg/output"
)

var (
	analyzePath  string
	outputFormat string
	outputFile   string
	configFile   string
	verbose      bool
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze project dependencies",
	Long:  `Analyze project dependencies to check for outdated, incompatible, or problematic packages.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.SetVerbose(verbose)

		if analyzePath == "" {
			return fmt.Errorf("project path must be specified with -p or --path")
		}

		// Load configuration
		var cfg *config.Config
		var configErr error
		
		if configFile != "" {
			// Use specified config file if provided
			cfg, configErr = config.LoadConfig(configFile)
			if configErr != nil {
				return fmt.Errorf("error loading configuration from %s: %w", configFile, configErr)
			}
			logger.Debugf("Loaded configuration from %s", configFile)
		} else {
			// Otherwise, try to find a config file in the project directory
			cfg, configErr = config.FindAndLoadConfig(analyzePath)
			if configErr != nil {
				return fmt.Errorf("error finding/loading configuration: %w", configErr)
			}
			logger.Debugf("Using configuration from project directory or defaults")
		}

		// Command-line flags override config file
		if outputFormat != "" {
			cfg.Output.Format = outputFormat
		}
		if outputFile != "" {
			cfg.Output.File = outputFile
		}

		var reports []analyzer.ReportItem
		var analyzeErr error
		projectType := ""

		logger.Debugf("Starting analysis for path: %s", analyzePath)

		// Check for npm project
		if _, errStat := os.Stat(filepath.Join(analyzePath, "package.json")); errStat == nil {
			projectType = "npm"
			logger.Infof("Detected npm project at %s", analyzePath)
			a := analyzer.NewNpmAnalyzer()
			reports, analyzeErr = a.Analyze(analyzePath)
			if analyzeErr != nil {
				return fmt.Errorf("npm analysis failed: %w", analyzeErr)
			}
		} else {
			// Check for .NET project
			var csprojFiles []string
			logger.Debugf("Checking for .csproj files in %s", analyzePath)
			_ = filepath.WalkDir(analyzePath, func(path string, d os.DirEntry, walkErr error) error {
				if walkErr != nil {
					logger.Debugf("Error walking directory %s: %v", path, walkErr)
					return walkErr
				}
				if !d.IsDir() && strings.HasSuffix(d.Name(), ".csproj") {
					logger.Debugf("Found .csproj file: %s", path)
					csprojFiles = append(csprojFiles, path)
					// We can stop after finding the first one if we assume one project per directory for now
					// Or collect all and decide how to handle multi-project dirs
					return filepath.SkipDir // Optimization: if we only care if *any* csproj exists in root or immediate subdirs
				}
				return nil
			})

			if len(csprojFiles) > 0 {
				projectType = "nuget"
				logger.Infof("Detected .NET project in %s (found .csproj files)", analyzePath)
				a := analyzer.NewNuGetAnalyzer()
				reports, analyzeErr = a.Analyze(analyzePath)
				if analyzeErr != nil {
					return fmt.Errorf("nuget analysis failed: %w", analyzeErr)
				}
			} else {
				// Check for Python/Pip project by presence of requirements.txt
				var reqFiles []string
				rootReq := filepath.Join(analyzePath, "requirements.txt")
				logger.Debugf("Checking for requirements.txt at %s", rootReq)
				if _, errStat := os.Stat(rootReq); errStat == nil {
					logger.Debugf("Found requirements.txt at root: %s", rootReq)
					reqFiles = append(reqFiles, rootReq)
				} else {
					logger.Debugf("Root requirements.txt not found, checking subdirectories of %s", analyzePath)
					_ = filepath.WalkDir(analyzePath, func(path string, d os.DirEntry, walkErr error) error {
						if walkErr != nil {
							logger.Debugf("Error walking directory %s: %v", path, walkErr)
							return walkErr
						}
						if !d.IsDir() && d.Name() == "requirements.txt" {
							logger.Debugf("Found requirements.txt in subdir: %s", path)
							reqFiles = append(reqFiles, path)
						}
						return nil
					})
				}

				if len(reqFiles) > 0 {
					projectType = "pip"
					logger.Infof("Detected Python project in %s (found requirements.txt)", analyzePath)
					a := analyzer.NewPipAnalyzer()
					reports, analyzeErr = a.Analyze(analyzePath)
					if analyzeErr != nil {
						return fmt.Errorf("pip analysis failed: %w", analyzeErr)
					}
				} else {
					// Check for Maven/Java project by presence of pom.xml
					var pomFiles []string
					rootPom := filepath.Join(analyzePath, "pom.xml")
					logger.Debugf("Checking for pom.xml at %s", rootPom)
					if _, errStat := os.Stat(rootPom); errStat == nil {
						logger.Debugf("Found pom.xml at root: %s", rootPom)
						pomFiles = append(pomFiles, rootPom)
					} else {
						logger.Debugf("Root pom.xml not found, checking subdirectories of %s", analyzePath)
						_ = filepath.WalkDir(analyzePath, func(path string, d os.DirEntry, walkErr error) error {
							if walkErr != nil {
								logger.Debugf("Error walking directory %s: %v", path, walkErr)
								return walkErr
							}
							if !d.IsDir() && d.Name() == "pom.xml" {
								logger.Debugf("Found pom.xml in subdir: %s", path)
								pomFiles = append(pomFiles, path)
							}
							return nil
						})
					}

					if len(pomFiles) > 0 {
						projectType = "maven"
						logger.Infof("Detected Maven project in %s (found pom.xml)", analyzePath)
						a := analyzer.NewMavenAnalyzer()
						reports, analyzeErr = a.Analyze(analyzePath)
						if analyzeErr != nil {
							return fmt.Errorf("maven analysis failed: %w", analyzeErr)
						}
					} else {
						emsg := fmt.Sprintf("no supported manifest found in %s (checked for package.json, *.csproj, requirements.txt, pom.xml)", analyzePath)
						logger.Errorf("%s", emsg)
						return fmt.Errorf("%s", emsg)
					}
				}
			}
		}

		logger.Debugf("Analysis complete. Project type: '%s'. Found %d report items.", projectType, len(reports))

		// --- Output Report ---
		var outputData []byte
		var outputErr error

		switch strings.ToLower(cfg.Output.Format) {
		case "json":
			outputData, outputErr = output.GenerateJSONReport(reports)
			if outputErr != nil {
				return fmt.Errorf("failed to generate JSON report: %w", outputErr)
			}
		case "sarif":
			outputData, outputErr = output.GenerateSarifReport(reports, analyzePath)
			if outputErr != nil {
				return fmt.Errorf("failed to generate SARIF report: %w", outputErr)
			}
		default: // "text" or any other value
			if cfg.Output.File != "" {
				return fmt.Errorf("text format can only be output to stdout")
			}
			output.PrintTextReport(reports)
			return nil
		}

		// Write output to file or stdout
		if cfg.Output.File != "" {
			if writeErr := os.WriteFile(cfg.Output.File, outputData, 0644); writeErr != nil {
				return fmt.Errorf("failed to write output to file: %w", writeErr)
			}
			logger.Infof("Report written to %s", cfg.Output.File)
		} else {
			fmt.Println(string(outputData))
		}

		return nil
	},
}



func init() {
	rootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringVarP(&analyzePath, "path", "p", "", "Path to the project directory to analyze (required)")
	analyzeCmd.Flags().StringVarP(&outputFormat, "format", "f", "", "Output format ('text', 'json', or 'sarif')")
	analyzeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (stdout if not specified)")
	analyzeCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to configuration file (.depcheck.yaml)")
	analyzeCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	_ = analyzeCmd.MarkFlagRequired("path")
}
