package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/sambabib/dependency-checker/pkg/logger"
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
	logger.Debugf("NPM: Reading package.json from %s", filePath)
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
		logger.Debugf("NPM: Analyzing package: %s, version range: %s", name, currentVersionStr)
		// Fetch latest version and deprecation status from npm registry
		currentSemver, errParseCurrent := semver.NewVersion(strings.TrimPrefix(currentVersionStr, "^"))
		if errParseCurrent != nil {
			// If current version is not valid semver, we can't do a proper comparison for severity.
			// We can still report latest and deprecated status.
			registryURLToUse := a.RegistryURL
			if registryURLToUse == "" {
				registryURLToUse = defaultNpmRegistryURL
			}
			logger.Debugf("NPM: Fetching from registry: %s/%s", registryURLToUse, name)
			resp, err := http.Get(fmt.Sprintf("%s/%s", registryURLToUse, name))
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
				DistTags         struct{ Latest string `json:"latest"` } `json:"dist-tags"`
				Deprecated       string `json:"deprecated"`
				PeerDependencies map[string]string `json:"peerDependencies"`
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
		logger.Debugf("NPM: Fetching from registry: %s/%s", registryURLToUse, name)
		resp, err := http.Get(fmt.Sprintf("%s/%s", registryURLToUse, name))
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
			DistTags         struct{ Latest string `json:"latest"` } `json:"dist-tags"`
			Deprecated       string `json:"deprecated"`
			PeerDependencies map[string]string `json:"peerDependencies"`
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

		isDeprecated := pkgInfo.Deprecated != ""

		// --- BEGIN PEER DEPENDENCY CHECK ---
		if len(pkgInfo.PeerDependencies) > 0 {
			for peerName, peerVersionRange := range pkgInfo.PeerDependencies {
				projectVersionOfPeer, found := allDeps[peerName]
				if !found {
					// Peer dependency is not listed in the project's dependencies at all.
					compatible = false
					severity = "error" // Missing a required peer is a significant issue.
					// TODO: Consider adding a more specific message/field to ReportItem for peer issues.
					break // One bad peer is enough.
				}

				constraint, err := semver.NewConstraint(peerVersionRange)
				if err != nil {
					// The peer dependency range itself is invalid in the fetched package's manifest.
					// This is an issue with 'name's package.json, not directly the user's project setup for this peer.
					// Log this or decide on a policy. For now, we might make the main package 'compatible=false' with a warning.
					if severity != "error" { // Don't override a direct major incompatibility of 'name'
						severity = "warning"
					}
					compatible = false // Marking incompatible due to problematic peer requirement
					// TODO: Log: fmt.Sprintf("Package %s has invalid peer dependency range for %s: %s", name, peerName, peerVersionRange)
					break
				}

				// Try to parse the project's version of the peer dependency.
				// Trim common prefixes like ^ or ~ before parsing for better compatibility with semver.NewVersion.
				projectPeerActualVersion, err := semver.NewVersion(strings.TrimPrefix(projectVersionOfPeer, "^~<>="))
				if err != nil {
					// Project's version for this peer is not valid semver (e.g., git URL, local path, or malformed).
					// We can't validate the constraint if we can't parse the version.
					compatible = false // Cannot validate semver constraint.
					if severity != "error" {
						severity = "warning" // Indicate uncertainty or a potential issue.
					}
					// TODO: Log: fmt.Sprintf("Could not parse project version for peer %s: %s", peerName, projectVersionOfPeer)
					break
				}

				if !constraint.Check(projectPeerActualVersion) {
					// Project's version does not satisfy the peer dependency range.
					compatible = false
					if severity != "error" {
						severity = "warning"
					}
					// TODO: Log: fmt.Sprintf("Peer dependency %s@%s not met by project's %s@%s for package %s", peerName, peerVersionRange, peerName, projectVersionOfPeer, name)
					break
				}
			}
		}
		// --- END PEER DEPENDENCY CHECK ---

		reports = append(reports, ReportItem{
			Name:           name,
			CurrentVersion: currentVersionStr,
			LatestVersion:  pkgInfo.DistTags.Latest,
			Deprecated:     isDeprecated,
			Compatible:     compatible, // Reflects peer dependency checks
			Severity:       severity,   // Reflects peer dependency checks
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
