package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set during build using ldflags
var Version = "dev"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "depcheck",
	Short:   "Checks project dependencies for updates and deprecations",
	Long:    `Dependency Checker is a CLI tool that analyzes your project's dependencies, reports outdated or deprecated packages, and checks compatibility issues.`,
	Version: Version,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
