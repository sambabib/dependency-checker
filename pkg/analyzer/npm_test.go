package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RegistryPackageInfo is a simplified structure for mock server responses.
// It defines the fields our mock npm registry will return for a package.
type RegistryPackageInfo struct {
	DistTags   struct{ Latest string `json:"latest"` } `json:"dist-tags"`
	Deprecated string `json:"deprecated,omitempty"` // omitempty: field is omitted from JSON if empty
}

// mockRegistry simulates the npm registry for testing purposes.
// It allows defining responses for specific package requests.
func mockRegistry(t *testing.T, expectedPackages map[string]RegistryPackageInfo) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		packageName := strings.TrimPrefix(r.URL.Path, "/")
		pkgInfo, ok := expectedPackages[packageName]
		if !ok {
			t.Logf("Mock registry received request for unexpected package: %s", packageName)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "Package %s not found in mock registry", packageName)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pkgInfo)
	}))
}

func TestNpmAnalyzer_Analyze_Basic(t *testing.T) {
	// 1. Define mock package.json content
	pkgJSONContent := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"react": "^17.0.0",
			"lodash": "4.17.20"
		},
		"devDependencies": {
			"jest": "26.6.3"
		}
	}`

	// 2. Create a temporary directory for the test project
	tempDir, err := os.MkdirTemp("", "dependency-checker-test-")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir) // Clean up after the test

	// Write the mock package.json to the temp directory
	pkgFilePath := filepath.Join(tempDir, "package.json")
	err = os.WriteFile(pkgFilePath, []byte(pkgJSONContent), 0644)
	require.NoError(t, err, "Failed to write mock package.json")

	// 3. Set up mock HTTP server responses
	expectedPackages := map[string]RegistryPackageInfo{
		"react": {
			DistTags: struct{ Latest string `json:"latest"` }{Latest: "18.2.0"},
		},
		"lodash": {
			DistTags:   struct{ Latest string `json:"latest"` }{Latest: "4.17.21"},
			Deprecated: "This version of lodash is deprecated for reasons.",
		},
		"jest": {
			DistTags: struct{ Latest string `json:"latest"` }{Latest: "27.5.1"},
		},
	}
	server := mockRegistry(t, expectedPackages)
	defer server.Close()

	// 4. Instantiate NpmAnalyzer with the mock server's URL
	analyzer := NewNpmAnalyzer()
	analyzer.RegistryURL = server.URL

	// 5. Call Analyze
	reports, err := analyzer.Analyze(tempDir)
	require.NoError(t, err, "Analyze returned an unexpected error")
	require.Len(t, reports, 3, "Expected 3 reports (react, lodash, jest)")

	// 6. Assertions for each package
	// Helper to find a report by name
	findReport := func(name string) *ReportItem {
		for i := range reports {
			if reports[i].Name == name {
				return &reports[i]
			}
		}
		return nil
	}

	// React
	reactReport := findReport("react")
	require.NotNil(t, reactReport, "Report for react not found")
	assert.Equal(t, "^17.0.0", reactReport.CurrentVersion)
	assert.Equal(t, "18.2.0", reactReport.LatestVersion)
	assert.False(t, reactReport.Deprecated)
	assert.Equal(t, "error", reactReport.Severity) // Major version difference
	assert.False(t, reactReport.Compatible)

	// Lodash
	lodashReport := findReport("lodash")
	require.NotNil(t, lodashReport, "Report for lodash not found")
	assert.Equal(t, "4.17.20", lodashReport.CurrentVersion)
	assert.Equal(t, "4.17.21", lodashReport.LatestVersion)
	assert.True(t, lodashReport.Deprecated)
	assert.Equal(t, "info", lodashReport.Severity) // Patch update, but deprecated status might also influence overall assessment in future
	assert.True(t, lodashReport.Compatible)

	// Jest
	jestReport := findReport("jest")
	require.NotNil(t, jestReport, "Report for jest not found")
	assert.Equal(t, "26.6.3", jestReport.CurrentVersion)
	assert.Equal(t, "27.5.1", jestReport.LatestVersion)
	assert.False(t, jestReport.Deprecated)
	assert.Equal(t, "error", jestReport.Severity) // Major version difference
	assert.False(t, jestReport.Compatible)
}

func TestNpmAnalyzer_Analyze_InvalidPackageJson(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dependency-checker-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	pkgFilePath := filepath.Join(tempDir, "package.json")
	err = os.WriteFile(pkgFilePath, []byte("invalid json content"), 0644)
	require.NoError(t, err)

	analyzer := NewNpmAnalyzer()
	_, err = analyzer.Analyze(tempDir)
	assert.Error(t, err, "Expected an error for invalid package.json content")
}

func TestNpmAnalyzer_Analyze_PackageJsonNotFound(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dependency-checker-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	analyzer := NewNpmAnalyzer()
	_, err = analyzer.Analyze(tempDir) // No package.json in tempDir
	assert.Error(t, err, "Expected an error when package.json is not found")
	// We might want to check for a specific error type or message if NpmAnalyzer returns a distinct error
}

func TestNpmAnalyzer_Analyze_RegistryFetchError(t *testing.T) {
	pkgJSONContent := `{"dependencies": {"some-package": "1.0.0"}}`
	tempDir, _ := os.MkdirTemp("", "")
	defer os.RemoveAll(tempDir)
	os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgJSONContent), 0644)

	// Mock server that always returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	analyzer := NewNpmAnalyzer()
	analyzer.RegistryURL = server.URL

	reports, err := analyzer.Analyze(tempDir)
	require.NoError(t, err) // Analyze itself shouldn't error, but the item should reflect the fetch error
	require.Len(t, reports, 1)
	assert.Equal(t, "some-package", reports[0].Name)
	assert.Equal(t, "fetch error", reports[0].LatestVersion)
	assert.Equal(t, "error", reports[0].Severity)
}

func TestNpmAnalyzer_Analyze_NonSemverCurrentVersion(t *testing.T) {
	pkgJSONContent := `{"dependencies": {"my-lib": "git+https://github.com/user/repo.git#commit-ish"}}`
	tempDir, _ := os.MkdirTemp("", "test-non-semver-")
	defer os.RemoveAll(tempDir)
	os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgJSONContent), 0644)

	expectedPackages := map[string]RegistryPackageInfo{
		"my-lib": {
			DistTags: struct{ Latest string `json:"latest"` }{Latest: "2.0.0"},
		},
	}
	server := mockRegistry(t, expectedPackages)
	defer server.Close()

	analyzer := NewNpmAnalyzer()
	analyzer.RegistryURL = server.URL

	reports, err := analyzer.Analyze(tempDir)
	require.NoError(t, err)
	require.Len(t, reports, 1)

	assert.Equal(t, "my-lib", reports[0].Name)
	assert.Equal(t, "git+https://github.com/user/repo.git#commit-ish", reports[0].CurrentVersion)
	assert.Equal(t, "2.0.0", reports[0].LatestVersion)
	assert.False(t, reports[0].Deprecated)
	// Since current version isn't semver, compatibility is false and severity is 'unknown'
	assert.False(t, reports[0].Compatible)
	assert.Equal(t, "unknown", reports[0].Severity)
}
