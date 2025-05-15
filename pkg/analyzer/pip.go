package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/sambabib/dependency-checker/pkg/logger" // <<< ADDED logger import
)

const defaultPipRegistryURL = "https://pypi.org/pypi"

// PipAnalyzer handles Python/Pip projects
type PipAnalyzer struct {
	RegistryURL string
}

// NewPipAnalyzer creates a new PipAnalyzer.
func NewPipAnalyzer() *PipAnalyzer {
	return &PipAnalyzer{
		RegistryURL: defaultPipRegistryURL,
	}
}

// PipPackageInfo represents the structure of the JSON response from PyPI for a package.
type PipPackageInfo struct {
	Info    PipInfo                         `json:"info"`
	Releases map[string][]PipReleaseFileInfo `json:"releases"`
	URLs     []PipReleaseFileInfo            `json:"urls"` // For overall latest, though releases map is better
}

// PipInfo contains metadata about the package.
type PipInfo struct {
	Name             string `json:"name"`
	Version          string `json:"version"` // Latest overall version
	Yanked           bool   `json:"yanked"`
	YankedReason     string `json:"yanked_reason"`
	Summary          string `json:"summary"`
	HomePage         string `json:"home_page"`
	Author           string `json:"author"`
	AuthorEmail      string `json:"author_email"`
	License          string `json:"license"`
	RequiresPython   string `json:"requires_python"`
	DocsURL          string `json:"docs_url"`
	PackageURL       string `json:"package_url"`
	ReleaseURL       string `json:"release_url"`
	BugtrackURL      string `json:"bugtrack_url"`
	ProjectURL       string `json:"project_url"` // Preferred for project link
	ProjectURLs      map[string]string `json:"project_urls"` // More comprehensive links
	Platform         string `json:"platform"`
	Maintainer       string `json:"maintainer"`
	MaintainerEmail  string `json:"maintainer_email"`
	RequiresDist     []string `json:"requires_dist"` // List of dependencies
	Classifiers      []string `json:"classifiers"`
	Keywords         string `json:"keywords"`
	DownloadURL      string `json:"download_url"`
	Description      string `json:"description"`
	DescriptionContentType string `json:"description_content_type"`
}


// PipReleaseFileInfo contains information about a specific file in a release.
type PipReleaseFileInfo struct {
	Filename        string    `json:"filename"`
	Packagetype     string    `json:"packagetype"` // e.g., "sdist", "bdist_wheel"
	PythonVersion   string    `json:"python_version"`
	RequiresPython  string    `json:"requires_python"`
	Size            int       `json:"size"`
	UploadTime      time.Time `json:"upload_time"`
	URL             string    `json:"url"`
	Yanked          bool      `json:"yanked"`
	YankedReason    string    `json:"yanked_reason"`
	Digests         struct {
		MD5    string `json:"md5"`
		SHA256 string `json:"sha256"`
		Blake2b string `json:"blake2b_256"`
	} `json:"digests"`
}


// IsWheel checks if the package type is a wheel.
func (f *PipReleaseFileInfo) IsWheel() bool {
	return f.Packagetype == "bdist_wheel"
}

// IsSourceDist checks if the package type is a source distribution.
func (f *PipReleaseFileInfo) IsSourceDist() bool {
	return f.Packagetype == "sdist"
}


// Analyze parses requirements.txt and checks dependencies against PyPI.
func (a *PipAnalyzer) Analyze(projectPath string) ([]ReportItem, error) {
	requirementsPath := filepath.Join(projectPath, "requirements.txt")
	logger.Debugf("Pip: Reading requirements.txt from %s", requirementsPath) // <<< ADDED Debug log

	file, err := os.Open(requirementsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements.txt: %w", err)
	}
	defer file.Close()

	var reports []ReportItem
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		logger.Debugf("Pip: Processing line %d: '%s'", lineNum, line) // <<< ADDED Debug log

		if line == "" || strings.HasPrefix(line, "#") { // Skip empty lines and comments
			continue
		}

		name, currentVersionSpec, err := parseRequirementsLine(line)
		if err != nil {
			logger.Errorf("Pip: Error parsing requirements line %d ('%s'): %v", lineNum, line, err) // <<< ADDED Error log
			reports = append(reports, ReportItem{
				Name:           line, // Use full line as name if unparseable
				CurrentVersion: "parse error",
				Severity:       "error",
				Notes:          fmt.Sprintf("Line %d: %v", lineNum, err),
			})
			continue
		}
		
		logger.Debugf("Pip: Parsed package '%s', version spec '%s'", name, currentVersionSpec) // <<< ADDED Debug log

		// Normalize current version for comparison if it's a strict pin (e.g., "==1.2.3")
		normalizedVersion := strings.TrimPrefix(currentVersionSpec, "==")
		normalizedVersion = strings.TrimPrefix(normalizedVersion, "=") // Handle single '='

		report := ReportItem{
			Name:           name,
			CurrentVersion: normalizedVersion,
			Severity:       "ok",
			Compatible:     true, // Pip doesn't have a strong concept of peer dependency conflicts like npm
		}

		registryURL := fmt.Sprintf("%s/%s/json", a.RegistryURL, name)
		logger.Debugf("Pip: Fetching from PyPI: %s", registryURL) // <<< ADDED Debug log
		resp, err := http.Get(registryURL)
		if err != nil {
			report.LatestVersion = "fetch error"
			report.Severity = "error"
			report.Notes = fmt.Sprintf("Error fetching from PyPI: %v", err)
			reports = append(reports, report)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			report.LatestVersion = "not-found"
			report.Severity = "error"
			report.Compatible = false
			report.Notes = "Package not found in registry."
			reports = append(reports, report)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			logger.Errorf("Pip: PyPI registry error for %s: %s (status %d)", name, registryURL, resp.StatusCode) // <<< ADDED Error log
			report.LatestVersion = "Error"
			report.Severity = "error"
			report.Compatible = false
			report.Notes = fmt.Sprintf("Error: Registry returned status %s", resp.Status)
			reports = append(reports, report)
			continue
		}
		
		logger.Debugf("Pip: Successfully fetched data for %s", name) // <<< ADDED Debug log

		var pkgInfo PipPackageInfo
		if err := json.NewDecoder(resp.Body).Decode(&pkgInfo); err != nil {
			logger.Errorf("Pip: Error decoding PyPI response for %s: %v", name, err) // <<< ADDED Error log
			report.LatestVersion = "decode error"
			report.Severity = "error"
			report.Notes = fmt.Sprintf("Error decoding PyPI response: %v", err)
			reports = append(reports, report)
			continue
		}

		latestStable, notes := getLatestStablePipVersion(pkgInfo.Releases)

		// Check pinned version status first
		status, pinnedNotes := checkPinnedVersionStatus(currentVersionSpec, latestStable, pkgInfo.Releases)
		report.Severity = status
		
		// For unpinned packages, ensure Compatible is true
		if currentVersionSpec == "" || currentVersionSpec == "VCS" || currentVersionSpec == "editable" {
			report.Compatible = true
		}
		
		if pinnedNotes != "" {
			report.Notes = pinnedNotes
		}
		if latestStable == "" {
			report.LatestVersion = "no-stable-version"
			report.Compatible = false
			report.Severity = "error"
			// When there's no stable version, combine notes from both functions
			if notes != "" && !strings.Contains(report.Notes, "No stable") {
				report.Notes = combineNotes(report.Notes, "No stable (non-prerelease, non-yanked) versions found.")
			}
		} else {
			report.LatestVersion = latestStable
		}
		
		// Version comparison for severity only if we have a valid latest version
		if report.LatestVersion != "" && report.LatestVersion != "fetch error" && report.LatestVersion != "decode error" && report.LatestVersion != "no-stable-version" && report.LatestVersion != "not found" {
			status, compNotes := checkPinnedVersionStatus(currentVersionSpec, report.LatestVersion, pkgInfo.Releases)
			report.Severity = status
			
			// Set Compatible to false for any package that has an update available, except for unpinned packages
			if status != "ok" && currentVersionSpec != "" && currentVersionSpec != "VCS" && currentVersionSpec != "editable" {
				report.Compatible = false
			}
			
			if compNotes != "" {
				// Clear previous notes to avoid duplication
				if report.Notes == "" {
					report.Notes = compNotes
				} else {
					// Only add if it's not already there
					if !strings.Contains(report.Notes, compNotes) {
						report.Notes = combineNotes(report.Notes, compNotes)
					}
				}
			}
		}
		
		// Check if the current pinned version is yanked
		currentVersionForYanked := strings.TrimPrefix(currentVersionSpec, "==")
		currentVersionForYanked = strings.TrimPrefix(currentVersionForYanked, "=")
		if releaseFiles, ok := pkgInfo.Releases[currentVersionForYanked]; ok && len(releaseFiles) > 0 {
			if releaseFiles[0].Yanked {
				report.Deprecated = true
				report.Compatible = false
				report.Severity = "error"
				yankedNote := fmt.Sprintf("Pinned version %s is yanked", currentVersionForYanked)
				if releaseFiles[0].YankedReason != "" {
					yankedNote += ": " + releaseFiles[0].YankedReason
				}
				report.Notes = yankedNote
			}
		}
		
		// Also check if overall package or latest version is yanked
		if pkgInfo.Info.Yanked && !report.Deprecated {
			report.Deprecated = true
			report.Compatible = false
			note := "Package version (overall) is yanked"
			if pkgInfo.Info.YankedReason != "" {
				note += ": " + pkgInfo.Info.YankedReason
			}
			report.Notes = combineNotes(report.Notes, note)
			if report.Severity == "ok" || report.Severity == "info" {
				report.Severity = "warning"
			}
		} else if report.LatestVersion != "" && !report.Deprecated { 
			// Check if the specific latest stable version we identified is yanked
			if releaseFiles, ok := pkgInfo.Releases[report.LatestVersion]; ok && len(releaseFiles) > 0 && releaseFiles[0].Yanked {
				report.Deprecated = true
				report.Compatible = false
				yankedReason := releaseFiles[0].YankedReason
				note := fmt.Sprintf("Latest stable version %s is yanked", report.LatestVersion)
				if yankedReason != "" {
					note += ": " + yankedReason
				}
				report.Notes = combineNotes(report.Notes, note)
				if report.Severity == "ok" || report.Severity == "info" {
					report.Severity = "warning"
				}
			}
		}


		reports = append(reports, report)
	}

	if err := scanner.Err(); err != nil {
		return reports, fmt.Errorf("error reading requirements.txt: %w", err)
	}

	return reports, nil
}

var (
	// Regex for name==version, name>=version, name~=version, etc.
	// Handles extras like: name[extra1,extra2]==version
	// And markers: name==version ; python_version < '3.7'
	// Does not handle URLs or editable installs (-e) yet.
	reqPattern = regexp.MustCompile(`^([\w.-]+(?:\[[\w\s,.-]*\])?)\s*([>=<~!]=?)\s*([\w.*+-]+)(?:\s*;.*)?`)
	// Simpler pattern for just name (no version specifier)
	nameOnlyPattern = regexp.MustCompile(`^([\w.-]+(?:\[[\w\s,.-]*\])?)(?:\s*;.*)?$`)
)


func parseRequirementsLine(line string) (name, versionSpec string, err error) {
	line = strings.Split(line, "#")[0] // Remove comments
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", fmt.Errorf("empty line")
	}

	// Attempt to match versioned dependency
	matches := reqPattern.FindStringSubmatch(line)
	if len(matches) == 4 {
		// Full match: name, operator, version
		return strings.TrimSpace(matches[1]), strings.TrimSpace(matches[2] + matches[3]), nil
	}

	// Attempt to match name-only dependency
	matches = nameOnlyPattern.FindStringSubmatch(line)
	if len(matches) == 2 {
		// Name only, no version specified
		return strings.TrimSpace(matches[1]), "", nil
	}
	
	// TODO: Handle VCS URLs, file paths, editable installs
	if strings.HasPrefix(line, "git+") || strings.HasPrefix(line, "hg+") || strings.HasPrefix(line, "svn+") || strings.HasPrefix(line, "bzr+") {
		logger.Debugf("Pip: VCS URL found, treating as unversioned for now: %s", line) // <<< ADDED Debug log
		return line, "VCS", nil // Return full line as name, "VCS" as version spec
	}
	if strings.HasPrefix(line, "-e") {
		// Editable install, often git URLs or local paths
		namePart := strings.TrimSpace(strings.TrimPrefix(line, "-e"))
		logger.Debugf("Pip: Editable install found, treating as unversioned for now: %s", namePart) // <<< ADDED Debug log
		return namePart, "editable", nil
	}


	return "", "", fmt.Errorf("unsupported requirement format: %s", line)
}


func getLatestStablePipVersion(releases map[string][]PipReleaseFileInfo) (string, string) {
	var latestStableVersion *semver.Version
	var latestStableVersionStr string
	var notes []string
	var allVersions []*semver.Version

	// Handle empty releases map early
	if len(releases) == 0 {
		notes = append(notes, "No stable (non-prerelease, non-yanked) versions found.")
		return "", strings.Join(notes, "; ")
	}

	for vStr, files := range releases {
		// Check if any file in this release is yanked. If all are yanked, the release is considered yanked.
		allFilesYanked := true
		if len(files) == 0 { // A release with no files is effectively unusable/yanked for our purposes
			allFilesYanked = true
		} else {
			for _, fileInfo := range files {
				if !fileInfo.Yanked {
					allFilesYanked = false
					break
				}
			}
		}
		if allFilesYanked {
			note := fmt.Sprintf("Version %s is yanked or has no usable files.", vStr)
			if len(files) > 0 && files[0].YankedReason != "" {
				note += " Reason: " + files[0].YankedReason
			}
			notes = append(notes, note)
			logger.Debugf("Pip: Skipping yanked/empty release %s", vStr) // <<< ADDED Debug log
			continue
		}

		v, err := semver.NewVersion(vStr)
		if err != nil {
			logger.Debugf("Pip: Could not parse version '%s': %v", vStr, err) // <<< ADDED Debug log
			notes = append(notes, fmt.Sprintf("Could not parse version '%s': %v", vStr, err))
			continue
		}
		allVersions = append(allVersions, v)

		// Consider stable if not a pre-release
		if v.Prerelease() == "" {
			if latestStableVersion == nil || v.GreaterThan(latestStableVersion) {
				latestStableVersion = v
				latestStableVersionStr = vStr
			}
		}
	}

	if latestStableVersionStr == "" {
		notes = append(notes, "No stable (non-prerelease, non-yanked) versions found.")
		// Fallback: find the absolute latest version if no stable one is found and allVersions is populated
		if len(allVersions) > 0 {
			latestOverallVersion := allVersions[0]
			for _, v := range allVersions[1:] {
				if v.GreaterThan(latestOverallVersion) {
					latestOverallVersion = v
				}
			}
			notes = append(notes, fmt.Sprintf("Latest overall version (including pre-releases) is %s.", latestOverallVersion.Original()))
			// We don't return this as "latestStable" but note its existence.
		}
	}
	
	logger.Debugf("Pip: Determined latest stable for package: %s. Notes: %s", latestStableVersionStr, strings.Join(notes, "; ")) // <<< ADDED Debug log
	return latestStableVersionStr, strings.Join(notes, "; ")
}


func checkPinnedVersionStatus(currentVersionSpec, latestVersionStr string, releases map[string][]PipReleaseFileInfo) (string, string) {
	// Handle unpinned packages (no version specified)
	if currentVersionSpec == "" || currentVersionSpec == "VCS" || currentVersionSpec == "editable" { 
		// For unpinned packages, we want to match the test expectations:
		// - Compatible: true (set by caller)
		// - No notes
		return "info", ""
	}

	// Normalize current version for comparison if it's a strict pin (e.g., "==1.2.3")
	pinnedVersionStr := strings.TrimPrefix(currentVersionSpec, "==")
	pinnedVersionStr = strings.TrimPrefix(pinnedVersionStr, "=") // Handle single '='

	// First check if the pinned version exists in releases
	if _, exists := releases[pinnedVersionStr]; !exists {
		return "error", "Pinned version " + pinnedVersionStr + " not found in registry releases or has no files.";
	}

	currentV, errCurrent := semver.NewVersion(pinnedVersionStr)
	if errCurrent != nil {
		// If currentVersionSpec is a range (e.g., ">=1.2.3"), this direct comparison isn't sufficient.
		// For simplicity, if it's not a '==' pin, we'll check if latest satisfies the constraint.
		if strings.HasPrefix(currentVersionSpec, ">=") || strings.HasPrefix(currentVersionSpec, "~=") ||
			strings.HasPrefix(currentVersionSpec, "<=") || strings.HasPrefix(currentVersionSpec, "!=") ||
			strings.HasPrefix(currentVersionSpec, ">") || strings.HasPrefix(currentVersionSpec, "<") {
			
			constraint, err := semver.NewConstraint(currentVersionSpec)
			if err != nil {
				return "error", fmt.Sprintf("Invalid version constraint '%s': %v", currentVersionSpec, err)
			}
			latestV, errLatest := semver.NewVersion(latestVersionStr)
			if errLatest != nil {
				return "error", fmt.Sprintf("Invalid latest version '%s' for constraint check: %v", latestVersionStr, errLatest)
			}
			if constraint.Check(latestV) {
				if latestV.Equal(currentV) { // If currentV was parseable and latest matches it within constraint
					return "ok", ""
				}
				// Latest satisfies constraint, but might be newer than a loosely pinned version.
				// If currentV was parseable, compare.
				if currentV != nil && latestV.GreaterThan(currentV) {
					// For test compatibility, return empty notes for version updates
					if latestV.Major() > currentV.Major() { return "error", "" }
					if latestV.Minor() > currentV.Minor() { return "warning", "" }
					return "info", ""
				}
				return "ok", "" // Constraint satisfied, not necessarily equal
			}
			// Latest does not satisfy the constraint - this implies outdated
			// Determine severity based on how outdated
			if currentV != nil && latestV.GreaterThan(currentV) { // This case should ideally be caught by constraint.Check if constraint is like "==X" or "<=X"
				// For test compatibility, return empty notes for version updates
				if latestV.Major() > currentV.Major() { return "error", "" }
				if latestV.Minor() > currentV.Minor() { return "warning", "" }
				return "info", ""
			}
			return "warning", ""

		}
		return "error", fmt.Sprintf("Invalid current version format '%s': %v", currentVersionSpec, errCurrent)
	}

	latestV, errLatest := semver.NewVersion(latestVersionStr)
	if errLatest != nil {
		return "error", fmt.Sprintf("Invalid latest version format '%s': %v", latestVersionStr, errLatest)
	}

	if latestV.Equal(currentV) {
		return "ok", ""
	}
	if latestV.GreaterThan(currentV) {
		// For test compatibility, return empty notes for version updates
		if latestV.Major() > currentV.Major() {
			return "error", ""
		}
		if latestV.Minor() > currentV.Minor() {
			return "warning", ""
		}
		return "info", ""
	}
	// If latestV is less than currentV, current might be a pre-release or unyanked newer version.
	// This scenario might indicate an issue with "latest stable" logic or a specific user choice.
	return "info", ""
}

func combineNotes(existingNotes, newNote string) string {
	if newNote == "" {
		return existingNotes
	}
	if existingNotes == "" {
		return newNote
	}
	return existingNotes + "; " + newNote
}
