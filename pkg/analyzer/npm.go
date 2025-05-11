package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const defaultNpmRegistryURL = "https://registry.npmjs.org"

// NpmAnalyzer analyzes npm project dependencies
type NpmAnalyzer struct {
	RegistryURL string // Allow overriding the registry URL for testing
}

// NewNpmAnalyzer creates a new NpmAnalyzer
func NewNpmAnalyzer() *NpmAnalyzer {
	return &NpmAnalyzer{} // RegistryURL will be empty, so default will be used
}

// packageJSON represents the structure of package.json for dependencies
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// Analyze reads package.json, fetches latest versions, and returns a report
func (a *NpmAnalyzer) Analyze(path string) ([]ReportItem, error) {
	// Read package.json
	filePath := filepath.Join(path, "package.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}

	// Merge dependencies and devDependencies
	allDeps := make(map[string]string)
	for name, ver := range pkg.Dependencies {
		allDeps[name] = ver
	}
	for name, ver := range pkg.DevDependencies {
		allDeps[name] = ver
	}

	reports := []ReportItem{}
	for name, currentVersionStr := range allDeps {
		// Fetch latest version and deprecation status from npm registry
		currentSemver, errParseCurrent := semver.NewVersion(strings.TrimPrefix(currentVersionStr, "^"))
		if errParseCurrent != nil {
			// If current version is not valid semver, we can't do a proper comparison for severity.
			// We can still report latest and deprecated status.
			registryURLToUse := a.RegistryURL
			if registryURLToUse == "" {
				registryURLToUse = defaultNpmRegistryURL
			}
			resp, err := http.Get(fmt.Sprintf("%s/%s", registryURLToUse, name)) // nosemgrep: go.lang.security.audit.net.gosec.G107.G107
			if err != nil {
				reports = append(reports, ReportItem{Name: name, CurrentVersion: currentVersionStr, Severity: "error", Compatible: false, LatestVersion: "fetch error", Deprecated: false})
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				reports = append(reports, ReportItem{Name: name, CurrentVersion: currentVersionStr, Severity: "error", Compatible: false, LatestVersion: "fetch error", Deprecated: false})
				continue
			}

			var pkgInfo struct {
				DistTags struct {
					Latest string `json:"latest"`
				} `json:"dist-tags"`
				Deprecated string `json:"deprecated"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&pkgInfo); err != nil {
				reports = append(reports, ReportItem{Name: name, CurrentVersion: currentVersionStr, Severity: "error", Compatible: false, LatestVersion: "parse error", Deprecated: false})
				continue
			}
			reports = append(reports, ReportItem{
				Name:           name,
				CurrentVersion: currentVersionStr,
				LatestVersion:  pkgInfo.DistTags.Latest,
				Deprecated:     pkgInfo.Deprecated != "",
				Compatible:     false, // Can't determine without valid current semver
				Severity:       "unknown", // Or "info" if we just want to report latest
			})
			continue
		}

		registryURLToUse := a.RegistryURL
		if registryURLToUse == "" {
			registryURLToUse = defaultNpmRegistryURL
		}
		resp, err := http.Get(fmt.Sprintf("%s/%s", registryURLToUse, name)) // nosemgrep: go.lang.security.audit.net.gosec.G107.G107
		if err != nil {
			reports = append(reports, ReportItem{Name: name, CurrentVersion: currentVersionStr, Severity: "error", Compatible: false, LatestVersion: "fetch error", Deprecated: false})
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			reports = append(reports, ReportItem{Name: name, CurrentVersion: currentVersionStr, Severity: "error", Compatible: false, LatestVersion: "fetch error", Deprecated: false})
			continue
		}

		var pkgInfo struct {
			DistTags struct {
				Latest string `json:"latest"`
			} `json:"dist-tags"`
			Deprecated string `json:"deprecated"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&pkgInfo); err != nil {
			reports = append(reports, ReportItem{Name: name, CurrentVersion: currentVersionStr, Severity: "error", Compatible: false, LatestVersion: "parse error", Deprecated: false})
			continue
		}

		latestVersion, err := semver.NewVersion(pkgInfo.DistTags.Latest)
		if err != nil { // Error parsing latest version from registry
			reports = append(reports, ReportItem{Name: name, CurrentVersion: currentVersionStr, Severity: "error", Compatible: false, LatestVersion: "N/A", Deprecated: pkgInfo.Deprecated != ""})
			continue
		}

		severity, compatible := determineSeverityAndCompatibility(currentSemver, latestVersion)

		reports = append(reports, ReportItem{
			Name:           name,
			CurrentVersion: currentVersionStr, // Report the original string from package.json
			LatestVersion:  pkgInfo.DistTags.Latest,
			Deprecated:     pkgInfo.Deprecated != "",
			Compatible:     compatible,
			Severity:       severity,
		})
	}

	return reports, nil
}

// determineSeverityAndCompatibility calculates the severity and compatibility based on version differences.
func determineSeverityAndCompatibility(current, latest *semver.Version) (string, bool) {
	severity := "ok"
	compatible := true

	if latest.GreaterThan(current) {
		if latest.Major() > current.Major() {
			severity = "error" // Major version update, potentially breaking
			compatible = false
		} else if latest.Minor() > current.Minor() {
			severity = "warning" // Minor version update, new features
		} else {
			severity = "info" // Patch version update, bug fixes
		}
	}
	return severity, compatible
}
