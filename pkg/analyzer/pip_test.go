package analyzer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewPipAnalyzer tests the NewPipAnalyzer constructor.
func TestNewPipAnalyzer(t *testing.T) {
	analyzer := NewPipAnalyzer()
	assert.NotNil(t, analyzer, "NewPipAnalyzer() should not return nil")
	assert.Equal(t, defaultPipRegistryURL, analyzer.RegistryURL, "Default registry URL should be set")
}

// createTemporaryRequirementsFile is a helper to create a temporary requirements file for testing.
func createTemporaryRequirementsFile(t *testing.T, dir string, filename string, content string) string {
	t.Helper()
	tempFilePath := filepath.Join(dir, filename)
	err := os.WriteFile(tempFilePath, []byte(content), 0644)
	assert.NoError(t, err, "Failed to create temporary requirements file: %v", err)
	return tempFilePath
}

// TestPipAnalyzer_findAndParseRequirementsFiles tests the findAndParseRequirementsFiles method.
func TestPipAnalyzer_findAndParseRequirementsFiles(t *testing.T) {
	analyzer := NewPipAnalyzer()

	tests := []struct {
		name              string
		files             map[string]string // filename -> content
		subdirs           map[string]map[string]string // subdir -> {filename -> content}
		expectedPackages  map[string]string // package -> version (empty if unpinned)
		expectError       bool
		expectedErrorMsg  string
	}{
		{
			name: "pinned versions",
			files: map[string]string{
				"requirements.txt": "requests==2.25.1\nDjango==3.2",
			},
			expectedPackages: map[string]string{
				"requests": "2.25.1",
				"Django":   "3.2",
			},
		},
		{
			name: "unpinned versions",
			files: map[string]string{
				"requirements.txt": "flask\nnumpy",
			},
			expectedPackages: map[string]string{
				"flask": "",
				"numpy": "",
			},
		},
		{
			name: "mixed pinned and unpinned with comments and extras",
			files: map[string]string{
				"requirements.txt": "  pandas == 1.3.0 # data analysis\nscipy[extra]; python_version < '3.9'\n# matplotlib==3.4.2",
			},
			expectedPackages: map[string]string{
				"pandas": "1.3.0",
				"scipy":  "", // Extras and markers are currently ignored for version, package name is extracted
			},
		},
		{
			name: "multiple requirements files in subdirectories",
			files: map[string]string{
				"requirements.txt": "common_package==1.0",
			},
			subdirs: map[string]map[string]string{
				"subdir1": {
					"requirements.txt": "package_a==2.0\ncommon_package==1.1", // Overrides root
				},
				"subdir2": {
					"requirements.txt": "package_b==3.0",
				},
			},
			expectedPackages: map[string]string{
				"common_package": "1.1",
				"package_a":      "2.0",
				"package_b":      "3.0",
			},
		},
		{
			name: "no requirements files found",
			files: map[string]string{
				"other.txt": "some_content",
			},
			expectedPackages: map[string]string{}, // Expect empty, not an error from this func
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			for filename, content := range tt.files {
				createTemporaryRequirementsFile(t, tempDir, filename, content)
			}

			for subdirName, filesInSubdir := range tt.subdirs {
				subDirPath := filepath.Join(tempDir, subdirName)
				err := os.MkdirAll(subDirPath, 0755)
				assert.NoError(t, err, "Failed to create subdirectory")
				for filename, content := range filesInSubdir {
					createTemporaryRequirementsFile(t, subDirPath, filename, content)
				}
			}

			actualPackages, err := analyzer.findAndParseRequirementsFiles(tempDir)

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErrorMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPackages, actualPackages)
			}
		})
	}
}

// mockPipRegistry Mocks the /pypi/<package>/json endpoint.
func mockPipRegistry(t *testing.T, expectedPackages map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract package name from URL path
		path := strings.Trim(r.URL.Path, "/")
		parts := strings.Split(path, "/")
		var packageName string

		// Handle path like "/pypi/requests/json" or just "/requests/json"
		if len(parts) == 3 && parts[0] == "pypi" && parts[2] == "json" { // e.g. pypi/requests/json
			packageName = parts[1]
		} else if len(parts) == 2 && parts[1] == "json" { // e.g. requests/json (when server.URL is base)
			packageName = parts[0]
		} else {
			t.Logf("Mock server received unhandled path format: %s", r.URL.Path)
			http.Error(w, "Mock server error: Unhandled path format", http.StatusBadRequest)
			return
		}

		// Handle the special __ERROR__ case for simulating server errors
		if errorPkg, ok := expectedPackages["__ERROR__"]; ok && packageName == errorPkg {
			http.Error(w, "Internal Server Error (mocked)", http.StatusInternalServerError)
			return
		}

		if jsonData, ok := expectedPackages[packageName]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(jsonData))
		} else {
			// If package not in expectedPackages, simulate a 404 Not Found
			http.NotFound(w, r)
		}
	}))
}

// Test_getLatestStablePipVersion tests the getLatestStablePipVersion package-level function.
func Test_getLatestStablePipVersion(t *testing.T) {
	tests := []struct {
		name             string
		releases         map[string][]PipReleaseFileInfo
		expectedVersion  string
		expectError      bool
		expectedErrorMsg string
	}{
		{
			name: "basic case with stable and prerelease",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0":    {{Yanked: false}},
				"1.1.0":    {{Yanked: false}},
				"1.2.0b1":  {{Yanked: false}},
				"0.9.0":    {{Yanked: false}},
			},
			expectedVersion: "1.1.0",
		},
		{
			name: "all versions yanked",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0": {{Yanked: true}},
				"1.1.0": {{Yanked: true}},
			},
			expectError:     true,
			expectedErrorMsg: "no stable (non-prerelease, non-yanked) versions found",
		},
		{
			name: "version with no files, treated as yanked",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0": {{Yanked: false}},
				"1.1.0": {},
			},
			expectedVersion: "1.0.0",
		},
		{
			name: "only prereleases available",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0a1": {{Yanked: false}},
				"1.0.0b2": {{Yanked: false}},
			},
			expectError:     true,
			expectedErrorMsg: "no stable (non-prerelease, non-yanked) versions found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualVersion, err := getLatestStablePipVersion(tt.releases)
			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErrorMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedVersion, actualVersion)
			}
		})
	}
}

// The mockPipRegistry will be used for testing the main Analyze method.

func TestPipAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name               string
		requirementsContent string
		expectedPackages   map[string]string // packageName -> jsonResponse string
		expectedReports    []ReportItem
		expectError        bool
		expectedErrorMsg   string
	}{
		{
			name: "up-to-date package",
			requirementsContent: "requests==2.25.1",
			expectedPackages: map[string]string{
				"requests": marshalPipReleases(t, map[string][]PipReleaseFileInfo{
					"2.25.0": {{Yanked: false}},
					"2.25.1": {{Yanked: false}},
					"2.24.0": {{Yanked: false}},
				}),
			},
			expectedReports: []ReportItem{
				{Name: "requests", CurrentVersion: "2.25.1", LatestVersion: "2.25.1", Severity: "ok", Compatible: true},
			},
		},
		{
			name: "minor update available for patch",
			requirementsContent: "django==3.1.0",
			expectedPackages: map[string]string{
				"django": marshalPipReleases(t, map[string][]PipReleaseFileInfo{
					"3.1.0": {{Yanked: false}},
					"3.1.5": {{Yanked: false}},
					"3.0.0": {{Yanked: false}},
				}),
			},
			expectedReports: []ReportItem{
				{Name: "django", CurrentVersion: "3.1.0", LatestVersion: "3.1.5", Severity: "info", Compatible: false},
			},
		},
		{
			name: "minor update available for minor version",
			requirementsContent: "django==3.1.0",
			expectedPackages: map[string]string{
				"django": marshalPipReleases(t, map[string][]PipReleaseFileInfo{
					"3.1.0": {{Yanked: false}},
					"3.2.0": {{Yanked: false}},
					"3.0.0": {{Yanked: false}},
				}),
			},
			expectedReports: []ReportItem{
				{Name: "django", CurrentVersion: "3.1.0", LatestVersion: "3.2.0", Severity: "warning", Compatible: false},
			},
		},
		{
			name: "major update available",
			requirementsContent: "flask==1.1.2",
			expectedPackages: map[string]string{
				"flask": marshalPipReleases(t, map[string][]PipReleaseFileInfo{
					"1.1.2": {{Yanked: false}},
					"2.0.0": {{Yanked: false}},
				}),
			},
			expectedReports: []ReportItem{
				{Name: "flask", CurrentVersion: "1.1.2", LatestVersion: "2.0.0", Severity: "error", Compatible: false},
			},
		},
		{
			name: "unpinned package",
			requirementsContent: "numpy",
			expectedPackages: map[string]string{
				"numpy": marshalPipReleases(t, map[string][]PipReleaseFileInfo{
					"1.20.0": {{Yanked: false}},
					"1.21.0": {{Yanked: false}},
				}),
			},
			expectedReports: []ReportItem{
				{Name: "numpy", CurrentVersion: "", LatestVersion: "1.21.0", Severity: "info", Compatible: true},
			},
		},
		{
			name: "package not found (404)",
			requirementsContent: "nonexistentpackage==1.0.0",
			expectedPackages: map[string]string{
				// No entry for 'nonexistentpackage' will cause mock to 404
			},
			expectedReports: []ReportItem{
				{Name: "nonexistentpackage", CurrentVersion: "1.0.0", LatestVersion: "not-found", Severity: "error", Compatible: false, Deprecated: false, Notes: "Package not found in registry."},
			},
		},
		{
			name: "registry internal server error (500)",
			requirementsContent: "errorpackage==1.0.0",
			expectedPackages: map[string]string{
				// Special key to trigger error in mock server for 'errorpackage'
				"__ERROR__": "errorpackage",
			},
			expectedReports: []ReportItem{
				{Name: "errorpackage", CurrentVersion: "1.0.0", LatestVersion: "Error", Severity: "error", Compatible: false, Deprecated: false, Notes: "Error: Registry returned status 500 Internal Server Error"},
			},
		},
		{
			name: "pinned to a yanked version",
			requirementsContent: "yankedpkg==1.0.0",
			expectedPackages: map[string]string{
				"yankedpkg": marshalPipReleases(t, map[string][]PipReleaseFileInfo{
					"1.0.0": {{Yanked: true, YankedReason: "Critical vulnerability"}},
					"1.0.1": {{Yanked: false}},
					"0.9.0": {{Yanked: false}},
				}),
			},
			expectedReports: []ReportItem{
				{Name: "yankedpkg", CurrentVersion: "1.0.0", LatestVersion: "1.0.1", Severity: "error", Compatible: false, Deprecated: true, Notes: "Pinned version 1.0.0 is yanked: Critical vulnerability"},
			},
		},
		{
			name: "pinned to a non-existent version",
			requirementsContent: "somepkg==1.2.3-nonexistent",
			expectedPackages: map[string]string{
				"somepkg": marshalPipReleases(t, map[string][]PipReleaseFileInfo{
					"1.0.0": {{Yanked: false}},
					"1.1.0": {{Yanked: false}},
				}),
			},
			expectedReports: []ReportItem{
				// Current behavior: reports latest available, version mismatch implies 'error'
				// If the pinned version isn't in releases, it's treated as a severe mismatch.
				{Name: "somepkg", CurrentVersion: "1.2.3-nonexistent", LatestVersion: "1.1.0", Severity: "error", Compatible: false, Notes: "Pinned version 1.2.3-nonexistent not found in registry releases or has no files."},
			},
		},
		{
			name: "package with no stable versions available (all pre-release or yanked)",
			requirementsContent: "nostablepkg==0.5.0", // Pinned or unpinned, result should be similar
			expectedPackages: map[string]string{
				"nostablepkg": marshalPipReleases(t, map[string][]PipReleaseFileInfo{
					"0.5.0rc1": {{Yanked: false}},
					"0.4.0":    {{Yanked: true}},
				}),
			},
			expectedReports: []ReportItem{
				{Name: "nostablepkg", CurrentVersion: "0.5.0", LatestVersion: "no-stable-version", Severity: "error", Compatible: false, Notes: "Pinned version 0.5.0 not found in registry releases or has no files.; No stable (non-prerelease, non-yanked) versions found."},
			},
		},
		// TODO: Add more scenarios: invalid project version format in requirements.txt (parsing error)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := mockPipRegistry(t, tt.expectedPackages)
			defer server.Close()

			tempDir, err := os.MkdirTemp("", "pip-test-")
			assert.NoError(t, err)
			defer os.RemoveAll(tempDir)

			// Call the helper, it asserts errors internally.
			// The returned path is not needed here as Analyze uses the tempDir.
			createTemporaryRequirementsFile(t, tempDir, "requirements.txt", tt.requirementsContent)

			analyzer := NewPipAnalyzer()
			analyzer.RegistryURL = server.URL // Override with mock server URL

			reports, err := analyzer.Analyze(tempDir)

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErrorMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.ElementsMatch(t, tt.expectedReports, reports)
			}
		})
	}
}

// helper to marshal PipPackageInfo for mock server responses
func marshalPipReleases(t *testing.T, releases map[string][]PipReleaseFileInfo) string {
	t.Helper()
	pkgInfo := PipPackageInfo{Releases: releases}
	jsonData, err := json.Marshal(pkgInfo)
	assert.NoError(t, err)
	return string(jsonData)
}
