package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
				Severity: "error", Compatible: false, Notes: "Error creating request: " + err.Error()})
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			reports = append(reports, ReportItem{
				Name: pkgName, CurrentVersion: projectVersionStr, LatestVersion: "Error",
				Severity: "error", Compatible: false, Notes: "Error fetching package data: " + err.Error()})
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
				Severity: "error", Compatible: false, Notes: note})
			continue
		}

		if err := json.NewDecoder(resp.Body).Decode(&pkgInfo); err != nil {
			resp.Body.Close() // Close body on decode error
			reports = append(reports, ReportItem{
				Name: pkgName, CurrentVersion: projectVersionStr, LatestVersion: "Error",
				Severity: "error", Compatible: false, Notes: "Error decoding package JSON: " + err.Error()})
			continue
		}
		resp.Body.Close()

		report = ReportItem{
			Name:           pkgName,
			CurrentVersion: projectVersionStr,
			// Defaults, will be updated
			Compatible:     false, 
			Severity:       "ok",    
		}

		// Pinned Version Checks
		if projectVersionStr != "" {
			pinnedReleaseFiles, pinnedVersionExistsInReleases := pkgInfo.Releases[projectVersionStr]
			if !pinnedVersionExistsInReleases || len(pinnedReleaseFiles) == 0 { // len check for empty release array
				report.Notes = "Pinned version " + projectVersionStr + " not found in registry releases or has no files."
				report.Severity = "error"
			} else {
				var isYanked bool
				var yankedReason string
				for _, rf := range pinnedReleaseFiles {
					if rf.Yanked {
						isYanked = true
						if rf.YankedReason != "" {
							yankedReason = rf.YankedReason
							break
						}
					}
				}
				if isYanked {
					report.Deprecated = true
					note := "Pinned version " + projectVersionStr + " is yanked"
					if yankedReason != "" {
						note += ": " + yankedReason
					}
					report.Notes = note
					report.Severity = "error"
				}
			}
		}

		// Get Latest Stable Version
		latestStableVersion, errGV := getLatestStablePipVersion(pkgInfo.Releases)
		if errGV != nil {
			report.LatestVersion = "Error" // Default if error
			var noteToAdd string
			if strings.Contains(errGV.Error(), "no stable") {
				report.LatestVersion = "no-stable-version"
				noteToAdd = "No stable (non-prerelease, non-yanked) versions found."
			} else {
				noteToAdd = "Error determining latest stable version: " + errGV.Error()
			}
			if report.Notes == "" {
				report.Notes = noteToAdd
			} else {
				report.Notes += "; " + noteToAdd
			}
			if report.Severity != "error" { // Escalate severity if not already critical
				report.Severity = "error"
			}
		} else {
			report.LatestVersion = latestStableVersion
		}

		// Determine Severity & Compatibility based on versions, if not already an error
		if report.Severity != "error" {
			if projectVersionStr == "" { // Unpinned
				report.Severity = "info"
				report.Compatible = true
				// Note: For unpinned packages, current version is effectively the latest stable, so no discrepancy.
				// ReportItem's CurrentVersion will be empty, LatestVersion will be the found stable one.
			} else if report.LatestVersion != "Error" && report.LatestVersion != "not-found" && report.LatestVersion != "no-stable-version" {
				projectSemver, errP := semver.NewVersion(projectVersionStr)
				latestSemver, errL := semver.NewVersion(report.LatestVersion)

				if errP != nil || errL != nil {
					report.Severity = "error"
					noteToAdd := "Error parsing version strings for comparison."
					if report.Notes == "" { report.Notes = noteToAdd } else { report.Notes += "; " + noteToAdd }
				} else {
					if projectSemver.Equal(latestSemver) {
						report.Severity = "ok"
						report.Compatible = true
					} else if projectSemver.LessThan(latestSemver) {
						// Compatible already false by default for pinned if not equal
						if projectSemver.Major() < latestSemver.Major() {
							report.Severity = "error" // Major update
						} else if projectSemver.Minor() < latestSemver.Minor() {
							report.Severity = "warning" // Minor update
						} else {
							report.Severity = "info" // Patch update
						}
					} else { // projectVersion > latestStableVersion
						report.Severity = "warning"
						noteToAdd := "Pinned version is newer than the latest identified stable version."
						if report.Notes == "" { report.Notes = noteToAdd } else { report.Notes += "; " + noteToAdd }
					}
				}
			} else {
				// If LatestVersion is an error string, this path implies projectVersionStr was not empty.
				// The severity should already be 'error' from the latestStableVersion checks.
				if report.Severity != "error" { report.Severity = "error" } 
			}
		}

		// Final compatibility check: if already an error severity, or deprecated, it's not compatible.
		if report.Severity == "error" || report.Deprecated {
			report.Compatible = false
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// getLatestStablePipVersion iterates through releases and returns the latest non-prerelease, non-yanked version string.
func getLatestStablePipVersion(releases map[string][]PipReleaseFileInfo) (string, error) {
	var stableVersions semver.Collection

	for verStr, releaseFiles := range releases {
		v, err := semver.NewVersion(verStr)
		if err != nil {
			// Skip invalid version strings from registry
			fmt.Printf("Skipping invalid version from registry: %s (%v)\n", verStr, err)
			continue
		}

		if v.Prerelease() != "" {
			continue // Skip pre-releases
		}

		// Check if the version is yanked (all files for this version are yanked)
		yanked := true
		if len(releaseFiles) == 0 { // No files usually means it's effectively yanked or problematic
		    yanked = true
		} else {
		    for _, rf := range releaseFiles {
			    if !rf.Yanked {
				    yanked = false
				    break
			    }
		    }
        }

		if !yanked {
			stableVersions = append(stableVersions, v)
		}
	}

	if len(stableVersions) == 0 {
		return "", fmt.Errorf("no stable (non-prerelease, non-yanked) versions found")
	}

	sort.Sort(stableVersions) // Sorts oldest to newest

	return stableVersions[len(stableVersions)-1].Original(), nil
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
