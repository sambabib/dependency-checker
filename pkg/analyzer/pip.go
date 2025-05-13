package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const (
	defaultPipRegistryURL = "https://pypi.org/pypi"
)

// PipAnalyzer analyzes Python pip project dependencies from requirements.txt
type PipAnalyzer struct {
	RegistryURL string
}

// NewPipAnalyzer creates a new PipAnalyzer.
// If registryURL is empty, it defaults to the official PyPI URL.
func NewPipAnalyzer() *PipAnalyzer {
	return &PipAnalyzer{
		RegistryURL: defaultPipRegistryURL,
	}
}

// PipPackageInfo represents the overall JSON response from PyPI for a package.
type PipPackageInfo struct {
	Info     PipInfo                         `json:"info"`
	Releases map[string][]PipReleaseFileInfo `json:"releases"` // Key is version string
	URLs     []PipReleaseFileInfo            `json:"urls"`     // List of files for the LATEST version
	// Vulnerabilities []PipVulnerability `json:"vulnerabilities"` // We might not need this for basic version checking
}

// PipInfo contains basic metadata about the package.
type PipInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"` // The latest overall version string
	Summary       string `json:"summary"`
	Yanked        bool   `json:"yanked"`         // From the top-level info, indicates if latest version is yanked
	YankedReason  string `json:"yanked_reason"`  // Reason for latest version being yanked
	// ... other fields like author, license, etc.
}

// PipReleaseFileInfo represents a specific file for a given release version.
// A single version (e.g., "1.0.0") can have multiple files (e.g., a wheel and a tar.gz).
type PipReleaseFileInfo struct {
	UploadTime   string `json:"upload_time"`
	PythonVersion string `json:"python_version"`
	Yanked       bool   `json:"yanked"`
	YankedReason string `json:"yanked_reason"`
	URL          string `json:"url"`
	Digests      struct { // Added for completeness, might not be directly used
		MD5    string `json:"md5"`
		SHA256 string `json:"sha256"`
	} `json:"digests"`
}

// PipVulnerability might be useful later.
// type PipVulnerability struct {
//  ID      string `json:"id"` // e.g., CVE or GHSA
//  Details string `json:"details"`
//  FixedIn []string `json:"fixed_in"`
// }

// ProjectPackage represents a package found in a requirements.txt file.
// Using a map for projectPackages: key is package name, value is pinned version (or empty if not pinned).
type ProjectPackage struct {
	Name    string
	Version string // Pinned version, e.g., "1.2.3". Empty if not explicitly pinned with ==.
	Line    string // Original line from requirements.txt for context
}

// Analyze processes Python dependencies specified in requirements.txt files found within the projectPath.
// It fetches package metadata from the configured PyPI-compatible registry (RegistryURL)
// to determine the latest stable versions and the status of currently pinned versions.
//
// For each dependency, it generates a ReportItem that includes:
// - The current pinned version (if any).
// - The latest available stable version.
// - Whether the current version is deprecated (e.g., yanked).
// - An assessment of compatibility and severity based on version differences.
// - Detailed notes for specific conditions, such as:
//   - Reasons for a package version being yanked.
//   - Errors encountered during HTTP requests or JSON parsing.
//   - Confirmation if a package or specific version is not found in the registry.
//   - Indication if no stable (non-prerelease, non-yanked) versions are available.
//
// The method returns a slice of ReportItem structs and an error if critical issues occur during
// file parsing or initial setup. Individual package analysis errors are typically captured within
// the Notes and Severity fields of their respective ReportItem.
func (a *PipAnalyzer) Analyze(projectPath string) ([]ReportItem, error) {
	var reports []ReportItem

	projectPackages, err := a.findAndParseRequirementsFiles(projectPath)
	if err != nil {
		return nil, fmt.Errorf("error processing requirements files: %w", err)
	}

	if len(projectPackages) == 0 {
		// Changed from error to empty report list, as it's not an analyzer error if no req files found.
		// Consumer can decide if this is an issue.
		return reports, nil 
	}

	client := &http.Client{}

	for pkgName, projectVersionStr := range projectPackages {
		apiUrl := fmt.Sprintf("%s/%s/json", a.RegistryURL, pkgName)
		req, err := http.NewRequest("GET", apiUrl, nil)
		if err != nil {
			reports = append(reports, ReportItem{
				Name: pkgName, CurrentVersion: projectVersionStr, LatestVersion: "Error",
				Severity: "error", Compatible: true, Notes: "Error creating request: " + err.Error()})
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			reports = append(reports, ReportItem{
				Name: pkgName, CurrentVersion: projectVersionStr, LatestVersion: "Error",
				Severity: "error", Compatible: true, Notes: "Error fetching package data: " + err.Error()})
			continue
		}

		var pkgInfo PipPackageInfo
		var report ReportItem

		if resp.StatusCode != http.StatusOK {
			latestVersion := "Error"
			note := fmt.Sprintf("Error: Registry returned status %s", resp.Status)
			if resp.StatusCode == http.StatusNotFound {
				latestVersion = "not-found"
				note = "Package not found in registry."
			}
			resp.Body.Close() // Close body for non-200 responses too
			reports = append(reports, ReportItem{
				Name: pkgName, CurrentVersion: projectVersionStr, LatestVersion: latestVersion,
				Severity: "error", Compatible: true, Notes: note})
			continue
		}

		if err := json.NewDecoder(resp.Body).Decode(&pkgInfo); err != nil {
			resp.Body.Close() // Close body on decode error
			reports = append(reports, ReportItem{
				Name: pkgName, CurrentVersion: projectVersionStr, LatestVersion: "Error",
				Severity: "error", Compatible: true, Notes: "Error decoding package JSON: " + err.Error()})
			continue
		}
		resp.Body.Close()

		report = ReportItem{
			Name:           pkgName,
			CurrentVersion: projectVersionStr,
			Compatible:     true, // Default to true for Pip
			Severity:       "ok",
		}

		// Find latest stable version
		latestVersionStr, err := getLatestStablePipVersion(pkgInfo.Releases)
		if err != nil {
			report.LatestVersion = "no-stable-version"
			report.Severity = "error"
			report.Notes = combineNotes(report.Notes, err.Error())
		} else {
			report.LatestVersion = latestVersionStr
		}

		// Check if pinned version exists and is yanked
		var note string
		if projectVersionStr != "" {
			note = checkPinnedVersionStatus(projectVersionStr, pkgInfo.Releases)
			if strings.Contains(note, "yanked") {
				report.Deprecated = true
				report.Severity = "error" // Yanked pinned version is an error
			}
			if strings.Contains(note, "not found") {
			    report.Severity = "error" // Pinned version not found is an error
			}
			report.Notes = combineNotes(report.Notes, note)
		}

		// Determine severity based on version comparison if not already an error
		if report.Severity != "error" {
			if projectVersionStr == "" { // Unpinned
				report.Severity = "info"
				// CurrentVersion is empty, LatestVersion is the stable one.
			} else if report.LatestVersion != "Error" && report.LatestVersion != "not-found" && report.LatestVersion != "no-stable-version" {
				// Compare pinned version with latest stable version
				projectSemver, errProj := semver.NewVersion(projectVersionStr)
				latestSemver, errLatest := semver.NewVersion(report.LatestVersion)

				if errProj == nil && errLatest == nil {
					if projectSemver.Equal(latestSemver) {
						report.Severity = "ok"
					} else if projectSemver.LessThan(latestSemver) {
						if projectSemver.Major() < latestSemver.Major() {
							report.Severity = "error"
						} else if projectSemver.Minor() < latestSemver.Minor() {
							report.Severity = "warning"
						} else { // Only patch differs
							report.Severity = "info"
						}
					} else { // projectSemver > latestSemver (e.g., using pre-release)
						report.Severity = "info"
					}
				}
			} // else: comparison not possible, retain severity from earlier checks
		}

		// Ensure Compatible is always true before appending
		report.Compatible = true
		reports = append(reports, report)
	}

	return reports, nil
}

// Helper function to check the status of a specifically pinned version
func checkPinnedVersionStatus(pinnedVersion string, releases map[string][]PipReleaseFileInfo) string {
	releaseFiles, exists := releases[pinnedVersion]
	if !exists || len(releaseFiles) == 0 {
		return "Pinned version " + pinnedVersion + " not found in registry releases or has no files."
	}

	var isYanked bool
	var yankedReason string
	for _, rf := range releaseFiles {
		if rf.Yanked {
			isYanked = true
			if rf.YankedReason != "" {
				yankedReason = rf.YankedReason
				break // Found a reason, no need to check further files for this version
			}
		}
	}

	if isYanked {
		note := "Pinned version " + pinnedVersion + " is yanked"
		if yankedReason != "" {
			note += ": " + yankedReason
		}
		return note
	}

	return "" // Pinned version exists and is not yanked
}

// Helper function to combine notes, avoiding leading/trailing separators
func combineNotes(existing, new string) string {
	if new == "" {
		return existing
	}
	if existing == "" {
		return new
	}
	return existing + "; " + new
}

// getLatestStablePipVersion iterates through releases and returns the latest non-prerelease, non-yanked version string.
func getLatestStablePipVersion(releases map[string][]PipReleaseFileInfo) (string, error) {
	var latestVersion *semver.Version
	var latestVersionStr string

	for versionStr, files := range releases {
		// Check if version is yanked or has no files
		isYanked := false
		if len(files) > 0 {
			isYanked = files[0].Yanked // Assuming yanked status is consistent for all files of a version
		} else {
			isYanked = true // Treat versions with no files as effectively unavailable/yanked
		}

		if isYanked {
			continue // Skip yanked versions
		}

		v, err := semver.NewVersion(versionStr)
		if err != nil {
			// Skip invalid semantic versions, potentially log this if needed
			continue
		}

		// Skip pre-release versions
		if v.Prerelease() != "" {
			continue
		}

		// Update latest version if this version is newer
		if latestVersion == nil || v.GreaterThan(latestVersion) {
			latestVersion = v
			latestVersionStr = versionStr
		}
	}

	if latestVersion == nil {
		return "", fmt.Errorf("no stable, non-yanked versions found")
	}

	return latestVersionStr, nil
}

// findAndParseRequirementsFiles searches for requirements.txt files and extracts package information.
func (a *PipAnalyzer) findAndParseRequirementsFiles(rootPath string) (map[string]string, error) {
	packages := make(map[string]string) // Key: packageName, Value: pinnedVersion

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), "requirements.txt") {
			file, err := os.Open(path)
			if err != nil {
				// Log error but continue walking, maybe other files are fine
				fmt.Printf("Error opening %s: %v\n", path, err) // Later, use a proper logger
				return nil
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())

				// Ignore comments and empty lines
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				// Basic parsing for 'package==version' or 'package'
				parts := strings.SplitN(line, "==", 2)
				packageName := strings.TrimSpace(parts[0])
				// Further clean package name from potential environment markers or extras
                // e.g., requests[security]==2.25.1 ; python_version < '3.8'
                // For now, just take the part before ';', '[', or other specifiers
                if strings.Contains(packageName, ";") {
                    packageName = strings.TrimSpace(strings.SplitN(packageName, ";", 2)[0])
                }
                if strings.Contains(packageName, "[") {
                    packageName = strings.TrimSpace(strings.SplitN(packageName, "[", 2)[0])
                }
                 if strings.Contains(packageName, ">") || strings.Contains(packageName, "<") || strings.Contains(packageName, "~") || strings.Contains(packageName, "!") {
                    // If it contains other version specifiers but not '==', treat as unpinned for now
                    // and just extract the name. A more robust parser would handle these.
                    nameParts := strings.FieldsFunc(packageName, func(r rune) bool {
                        return r == '>' || r == '<' || r == '=' || r == '~' || r == '!' 
                    })
                    if len(nameParts) > 0 {
                        packageName = strings.TrimSpace(nameParts[0])
                    }
                }

				if packageName == "" {
				    continue
                }

				packageVersion := ""
				if len(parts) == 2 {
					packageVersion = strings.TrimSpace(parts[1])
                    // Clean version from potential comments or hashes
                    if strings.Contains(packageVersion, "#") {
                        packageVersion = strings.TrimSpace(strings.SplitN(packageVersion, "#", 2)[0])
                    }
                     if strings.Contains(packageVersion, ";") {
                        packageVersion = strings.TrimSpace(strings.SplitN(packageVersion, ";", 2)[0])
                    }
				}

				// If multiple requirements.txt files list the same package,
				// the last one parsed with a specific version will win.
				// Or, if one is pinned and another isn't, the pinned one should ideally take precedence
				// or we should flag a conflict. For now, simple override.
				if _, ok := packages[packageName]; !ok || packageVersion != "" {
				    packages[packageName] = packageVersion
                }
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("Error scanning %s: %v\n", path, err) // Log error
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking path %s: %w", rootPath, err)
	}

	return packages, nil
}
