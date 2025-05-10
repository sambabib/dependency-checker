package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "dependency-checker",
	Short: "Checks project dependencies for updates and deprecations",
	Long:  `Dependency Checker is a CLI tool that analyzes your project's dependencies, reports outdated or deprecated packages, and checks compatibility issues.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
