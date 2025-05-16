package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the configuration for the dependency checker
type Config struct {
	// Exclude patterns for files or directories
	Exclude []string `yaml:"exclude"`

	// Custom registries for different package managers
	Registries struct {
		Npm    string `yaml:"npm"`
		NuGet  string `yaml:"nuget"`
		Maven  string `yaml:"maven"`
		PyPI   string `yaml:"pypi"`
	} `yaml:"registries"`

	// Severity thresholds for reporting
	Severity struct {
		Major  string `yaml:"major"`  // Default: error
		Minor  string `yaml:"minor"`  // Default: warning
		Patch  string `yaml:"patch"`  // Default: info
	} `yaml:"severity"`

	// Output configuration
	Output struct {
		Format string `yaml:"format"` // text, json, sarif
		File   string `yaml:"file"`   // Output file path (stdout if empty)
	} `yaml:"output"`

	// Ignore specific packages
	IgnorePackages []string `yaml:"ignorePackages"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	config := &Config{
		Exclude: []string{},
	}

	// Set default severity levels
	config.Severity.Major = "error"
	config.Severity.Minor = "warning"
	config.Severity.Patch = "info"

	// Set default output format
	config.Output.Format = "text"

	return config
}

// LoadConfig loads the configuration from the specified file path
// If no path is provided, it looks for .depcheck.yaml in the current directory
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// If no config path provided, look in current directory
	if configPath == "" {
		configPath = ".depcheck.yaml"
	}

	// Check if the file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Config file doesn't exist, return default config
		return config, nil
	}

	// Read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse the YAML
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return config, nil
}

// FindAndLoadConfig searches for a config file in the project directory and its parents
func FindAndLoadConfig(projectPath string) (*Config, error) {
	config := DefaultConfig()

	// Start from the project directory and work up to the root
	currentDir := projectPath
	for {
		configPath := filepath.Join(currentDir, ".depcheck.yaml")
		if _, err := os.Stat(configPath); err == nil {
			// Found a config file, load it
			data, err := os.ReadFile(configPath)
			if err != nil {
				return nil, fmt.Errorf("error reading config file %s: %w", configPath, err)
			}

			// Parse the YAML
			if err := yaml.Unmarshal(data, config); err != nil {
				return nil, fmt.Errorf("error parsing config file %s: %w", configPath, err)
			}

			return config, nil
		}

		// Move up to the parent directory
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			// Reached the root directory, no config file found
			break
		}
		currentDir = parentDir
	}

	// No config file found, return default config
	return config, nil
}

// IsPackageIgnored checks if a package should be ignored based on the configuration
func (c *Config) IsPackageIgnored(packageName string) bool {
	for _, ignoredPackage := range c.IgnorePackages {
		if ignoredPackage == packageName {
			return true
		}
	}
	return false
}

// GetSeverityForUpdate returns the configured severity level for the given update type
func (c *Config) GetSeverityForUpdate(updateType string) string {
	switch updateType {
	case "major":
		return c.Severity.Major
	case "minor":
		return c.Severity.Minor
	case "patch":
		return c.Severity.Patch
	default:
		return "info"
	}
}
