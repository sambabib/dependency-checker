package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"github.com/Masterminds/semver/v3"
)

// NpmAnalyzer implements Analyzer for npm (package.json)
type NpmAnalyzer struct{}

// NewNpmAnalyzer returns a new npm analyzer
func NewNpmAnalyzer() Analyzer {
	return &NpmAnalyzer{}
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
	for name, current := range allDeps {
		// Fetch latest version and deprecation info
		latest, deprecated, err := getLatestVersion(name)
		if err != nil {
			reports = append(reports, ReportItem{
				Name:           name,
				CurrentVersion: current,
				LatestVersion:  "unknown",
				Deprecated:     false,
				Compatible:     false,
				Severity:       "error",
			})
			continue
		}
		// Determine compatibility and severity
		compatible, sev := compareVersions(current, latest, deprecated)
		reports = append(reports, ReportItem{
			Name:           name,
			CurrentVersion: current,
			LatestVersion:  latest,
			Deprecated:     deprecated,
			Compatible:     compatible,
			Severity:       sev,
		})
	}

	return reports, nil
}

// getLatestVersion queries the npm registry for the latest version and deprecation info
func getLatestVersion(name string) (string, bool, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/latest", name)
	resp, err := http.Get(url)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	var result struct {
		Version    string `json:"version"`
		Deprecated string `json:"deprecated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", false, err
	}
	isDeprecated := result.Deprecated != ""
	return result.Version, isDeprecated, nil
}

// compareVersions uses semver to check compatibility and generate severity
func compareVersions(current, latest string, deprecated bool) (bool, string) {
	if deprecated {
		return false, "warning"
	}
	cv, err1 := semver.NewVersion(current)
	lv, err2 := semver.NewVersion(latest)
	if err1 != nil || err2 != nil {
		// Unable to parse versions, assume warning
		return false, "warning"
	}
	// Major version mismatch is breaking change
	if cv.Major() != lv.Major() {
		return false, "error"
	}
	// Less than latest but same major => warning
	if cv.LessThan(lv) {
		return true, "warning"
	}
	// Up to date
	return true, "ok"
}
