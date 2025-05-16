package analyzer

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/sambabib/dependency-checker/pkg/logger"
)

const defaultMavenRegistryURL = "https://repo.maven.apache.org/maven2"

// MavenAnalyzer handles Java/Maven projects
type MavenAnalyzer struct {
	registryURL string
}

// NewMavenAnalyzer creates a new Maven analyzer
func NewMavenAnalyzer() *MavenAnalyzer {
	return &MavenAnalyzer{
		registryURL: defaultMavenRegistryURL,
	}
}

// PomXML represents the structure of a Maven pom.xml file
type PomXML struct {
	XMLName     xml.Name       `xml:"project"`
	GroupID     string         `xml:"groupId"`
	ArtifactID  string         `xml:"artifactId"`
	Version     string         `xml:"version"`
	Parent      PomParent      `xml:"parent"`
	Properties  PomProperties  `xml:"properties"`
	Dependencies []PomDependency `xml:"dependencies>dependency"`
}

// PomParent represents the parent section in a pom.xml
type PomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// PomProperties represents the properties section in a pom.xml
type PomProperties struct {
	Elements []xml.Attr `xml:",any,attr"`
}

// PomDependency represents a dependency in a pom.xml
type PomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

// MavenMetadata represents the Maven metadata XML structure
type MavenMetadata struct {
	XMLName    xml.Name `xml:"metadata"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Versioning struct {
		Latest   string `xml:"latest"`
		Release  string `xml:"release"`
		Versions struct {
			Version []string `xml:"version"`
		} `xml:"versions"`
		LastUpdated string `xml:"lastUpdated"`
	} `xml:"versioning"`
}

// Analyze scans the given project path for Maven dependencies
func (a *MavenAnalyzer) Analyze(projectPath string) ([]ReportItem, error) {
	logger.Debugf("Starting Maven analysis for %s", projectPath)

	// Find all pom.xml files in the project
	pomFiles, err := a.findPomFiles(projectPath)
	if err != nil {
		return nil, fmt.Errorf("error finding pom.xml files: %w", err)
	}

	if len(pomFiles) == 0 {
		logger.Errorf("Maven: No pom.xml files found in %s", projectPath)
		return nil, fmt.Errorf("no pom.xml files found in %s", projectPath)
	}

	logger.Debugf("Found %d pom.xml files", len(pomFiles))

	var allReports []ReportItem

	// Process each pom.xml file
	for _, pomFile := range pomFiles {
		reports, err := a.analyzePomFile(pomFile)
		if err != nil {
			logger.Errorf("Maven: Error analyzing %s: %v", pomFile, err)
			continue
		}
		allReports = append(allReports, reports...)
	}

	return allReports, nil
}

// findPomFiles finds all pom.xml files in the given project path
func (a *MavenAnalyzer) findPomFiles(projectPath string) ([]string, error) {
	var pomFiles []string

	// Check for pom.xml in the root directory
	rootPom := filepath.Join(projectPath, "pom.xml")
	if _, err := os.Stat(rootPom); err == nil {
		logger.Debugf("Found pom.xml at root: %s", rootPom)
		pomFiles = append(pomFiles, rootPom)
	}

	// Walk the directory tree to find all pom.xml files
	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Debugf("Error accessing path %s: %v", path, err)
			return nil // Continue despite error
		}

		// Skip the root pom.xml since we already checked it
		if path == rootPom {
			return nil
		}

		if !info.IsDir() && filepath.Base(path) == "pom.xml" {
			logger.Debugf("Found pom.xml: %s", path)
			pomFiles = append(pomFiles, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return pomFiles, nil
}

// analyzePomFile analyzes a single pom.xml file
func (a *MavenAnalyzer) analyzePomFile(pomFile string) ([]ReportItem, error) {
	logger.Debugf("Analyzing pom.xml: %s", pomFile)

	// Read and parse the pom.xml file
	pomData, err := os.ReadFile(pomFile)
	if err != nil {
		logger.Errorf("Maven: Error reading %s: %v", pomFile, err)
		return []ReportItem{}, nil
	}

	var pom PomXML
	if err := xml.Unmarshal(pomData, &pom); err != nil {
		logger.Errorf("Maven: Error parsing %s: %v", pomFile, err)
		return []ReportItem{}, nil
	}

	var reports []ReportItem

	// Process each dependency
	for _, dep := range pom.Dependencies {
		// Skip dependencies without a version (they might be defined in parent pom)
		if dep.Version == "" {
			logger.Debugf("Maven: Skipping dependency %s:%s with no version", dep.GroupID, dep.ArtifactID)
			continue
		}

		// Skip test dependencies
		if strings.ToLower(dep.Scope) == "test" {
			logger.Debugf("Maven: Skipping test dependency %s:%s", dep.GroupID, dep.ArtifactID)
			continue
		}

		// Skip optional dependencies
		if strings.ToLower(dep.Optional) == "true" {
			logger.Debugf("Maven: Skipping optional dependency %s:%s", dep.GroupID, dep.ArtifactID)
			continue
		}

		// Resolve property references in version (e.g., ${project.version})
		resolvedVersion := a.resolveVersionProperty(dep.Version, pom)
		if resolvedVersion == "" {
			logger.Debugf("Maven: Could not resolve version property %s for %s:%s", dep.Version, dep.GroupID, dep.ArtifactID)
			continue
		}

		// Check for latest version
		report, err := a.checkDependency(dep.GroupID, dep.ArtifactID, resolvedVersion)
		if err != nil {
			logger.Errorf("Maven: Error checking dependency %s:%s: %v", dep.GroupID, dep.ArtifactID, err)
			report = ReportItem{
				Name:           fmt.Sprintf("%s:%s", dep.GroupID, dep.ArtifactID),
				CurrentVersion: resolvedVersion,
				LatestVersion:  "unknown",
				Compatible:     false,
				Severity:       "error",
				Notes:          fmt.Sprintf("Error checking dependency: %v", err),
			}
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// resolveVersionProperty resolves version properties like ${project.version} or ${some.version}
func (a *MavenAnalyzer) resolveVersionProperty(version string, pom PomXML) string {
	// If the version doesn't contain a property reference, return it as is
	if !strings.Contains(version, "${") {
		return version
	}

	// Extract the property name
	propName := strings.TrimPrefix(strings.TrimSuffix(version, "}"), "${")

	// Handle special properties
	if propName == "project.version" || propName == "pom.version" {
		if pom.Version != "" {
			return pom.Version
		} else if pom.Parent.Version != "" {
			return pom.Parent.Version
		}
	}

	// TODO: Handle more complex property resolution from the properties section
	// This would require parsing the XML properties section more thoroughly

	// If we couldn't resolve the property, return empty string
	logger.Debugf("Maven: Could not resolve property %s", propName)
	return ""
}

// checkDependency checks a single Maven dependency for updates
func (a *MavenAnalyzer) checkDependency(groupID, artifactID, currentVersion string) (ReportItem, error) {
	logger.Debugf("Maven: Checking dependency %s:%s at version %s", groupID, artifactID, currentVersion)

	report := ReportItem{
		Name:           fmt.Sprintf("%s:%s", groupID, artifactID),
		CurrentVersion: currentVersion,
		Compatible:     true, // Assume compatible by default
	}

	// Construct the Maven repository URL for the metadata
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	metadataURL := fmt.Sprintf("%s/%s/%s/maven-metadata.xml", a.registryURL, groupPath, artifactID)

	// Fetch the metadata
	resp, err := http.Get(metadataURL)
	if err != nil {
		return report, fmt.Errorf("error fetching Maven metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return report, fmt.Errorf("Maven registry returned status %d for %s", resp.StatusCode, metadataURL)
	}

	// Read and parse the metadata
	metadataBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return report, fmt.Errorf("error reading Maven metadata: %w", err)
	}

	var metadata MavenMetadata
	if err := xml.Unmarshal(metadataBytes, &metadata); err != nil {
		return report, fmt.Errorf("error parsing Maven metadata: %w", err)
	}

	// Find the latest stable version
	latestVersion, err := a.getLatestStableVersion(metadata.Versioning.Versions.Version)
	if err != nil {
		report.LatestVersion = "no stable version"
		report.Notes = err.Error()
		return report, nil
	}

	report.LatestVersion = latestVersion

	// Compare versions
	currentSemver, err := semver.NewVersion(currentVersion)
	if err != nil {
		report.Compatible = false
		report.Severity = "error"
		report.Notes = fmt.Sprintf("Current version %s is not a valid semver", currentVersion)
		return report, nil
	}

	latestSemver, err := semver.NewVersion(latestVersion)
	if err != nil {
		report.Compatible = false
		report.Severity = "error"
		report.Notes = fmt.Sprintf("Latest version %s is not a valid semver", latestVersion)
		return report, nil
	}

	// Determine severity based on version difference
	if currentSemver.LessThan(latestSemver) {
		if currentSemver.Major() < latestSemver.Major() {
			report.Severity = "error"
			report.Notes = fmt.Sprintf("Project version %s is older than latest stable %s (major update available)", currentVersion, latestVersion)
		} else if currentSemver.Minor() < latestSemver.Minor() {
			report.Severity = "warning"
			report.Notes = fmt.Sprintf("Project version %s is older than latest stable %s (minor update available)", currentVersion, latestVersion)
		} else if currentSemver.Patch() < latestSemver.Patch() {
			report.Severity = "info"
			report.Notes = fmt.Sprintf("Project version %s is older than latest stable %s (patch update available)", currentVersion, latestVersion)
		}
		report.Compatible = false
	} else {
		report.Severity = "info"
		report.Notes = "Up to date"
	}

	return report, nil
}

// getLatestStableVersion returns the latest stable version from a list of versions
func (a *MavenAnalyzer) getLatestStableVersion(versions []string) (string, error) {
	if len(versions) == 0 {
		return "", fmt.Errorf("no versions available")
	}

	var latestStable *semver.Version

	for _, versionStr := range versions {
		// Skip versions with qualifiers like -SNAPSHOT, -alpha, -beta, etc.
		if strings.Contains(versionStr, "-SNAPSHOT") ||
			strings.Contains(versionStr, "-alpha") ||
			strings.Contains(versionStr, "-beta") ||
			strings.Contains(versionStr, "-rc") ||
			strings.Contains(versionStr, "-m") {
			logger.Debugf("Maven: Skipping non-stable version: %s", versionStr)
			continue
		}

		// Try to parse as semver
		version, err := semver.NewVersion(versionStr)
		if err != nil {
			logger.Debugf("Maven: Skipping invalid semver: %s (%v)", versionStr, err)
			continue
		}

		// Update latest stable if this version is newer
		if latestStable == nil || version.GreaterThan(latestStable) {
			latestStable = version
		}
	}

	if latestStable == nil {
		return "", fmt.Errorf("no stable versions found")
	}

	return latestStable.String(), nil
}
