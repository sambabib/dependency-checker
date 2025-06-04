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

// TestPipAnalyzer_findAndParseRequirementsFiles was removed as the target method was integrated into Analyze.

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
		name            string
		releases        map[string][]PipReleaseFileInfo
		expectedVersion string
		expectedNotes   string // Can be a substring to check for flexibility
	}{
		{
			name: "basic case with stable and prerelease",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0":   {{Yanked: false}},
				"1.1.0":   {{Yanked: false}},
				"1.2.0b1": {{Yanked: false}},
				"0.9.0":   {{Yanked: false}},
			},
			expectedVersion: "1.1.0",
			expectedNotes:   "", // No specific notes expected if a version is found cleanly
		},
		{
			name: "all versions yanked, one with reason",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0": {{Yanked: true, YankedReason: "Critical bug"}},
				"1.1.0": {{Yanked: true, YankedReason: ""}},
			},
			expectedVersion: "", // No stable version found
			expectedNotes:   "Version 1.0.0 is yanked or has no usable files. Reason: Critical bug; Version 1.1.0 is yanked or has no usable files.; No stable (non-prerelease, non-yanked) versions found.",
		},
		{
			name: "one version stable, another yanked",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0": {{Yanked: true, YankedReason: "Security issue"}},
				"1.1.0": {{Yanked: false}},
			},
			expectedVersion: "1.1.0",
			expectedNotes:   "Version 1.0.0 is yanked or has no usable files. Reason: Security issue",
		},
		{
			name: "version with no files (treated as yanked)",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0": {{Yanked: false}},
				"1.1.0": {}, // No files, implies yanked for our logic
			},
			expectedVersion: "1.0.0",
			expectedNotes:   "Version 1.1.0 is yanked or has no usable files.",
		},
		{
			name: "all files for a specific version are yanked",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0": {{Yanked: false}},
				"1.1.0": {{Yanked: true, YankedReason: "File 1 bad"}, {Yanked: true, YankedReason: "File 2 bad"}},
			},
			expectedVersion: "1.0.0",
			expectedNotes:   "Version 1.1.0 is yanked or has no usable files. Reason: File 1 bad", // Note might pick up first reason
		},
		{
			name: "some files yanked, but one is not for a version",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0": {{Yanked: true}},
				"1.1.0": {{Yanked: true}, {Yanked: false}}, // This version should be considered stable
			},
			expectedVersion: "1.1.0",
			expectedNotes:   "Version 1.0.0 is yanked or has no usable files.",
		},
		{
			name: "only prereleases available",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0a1": {{Yanked: false}},
				"1.0.0b2": {{Yanked: false}},
				"0.9.0rc1":{{Yanked: false}},
			},
			expectedVersion: "",
			expectedNotes:   "Could not parse version '0.9.0rc1': Invalid Semantic Version; Could not parse version '1.0.0a1': Invalid Semantic Version; Could not parse version '1.0.0b2': Invalid Semantic Version; No stable (non-prerelease, non-yanked) versions found.",
		},
		{
			name: "invalid version string mixed with valid ones",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0":       {{Yanked: false}},
				"invalid-ver": {{Yanked: false}},
				"1.2.0":       {{Yanked: false}},
			},
			expectedVersion: "1.2.0",
			expectedNotes:   "Could not parse version 'invalid-ver': Invalid Semantic Version",
		},
		{
			name:            "no versions available",
			releases:        map[string][]PipReleaseFileInfo{},
			expectedVersion: "",
			expectedNotes:   "No stable (non-prerelease, non-yanked) versions found.",
		},
		{
			name: "stable version is older than a yanked newer version",
			releases: map[string][]PipReleaseFileInfo{
				"1.0.0":    {{Yanked: false}},
				"1.1.0":    {{Yanked: true, YankedReason: "Too new and broken"}},
			},
			expectedVersion: "1.0.0",
			expectedNotes:   "Version 1.1.0 is yanked or has no usable files. Reason: Too new and broken",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualVersion, actualNotes := getLatestStablePipVersion(tt.releases)
			assert.Equal(t, tt.expectedVersion, actualVersion, "Expected version mismatch")
			if tt.expectedNotes != "" {
				expectedNoteParts := strings.Split(tt.expectedNotes, "; ")
				actualNoteParts := strings.Split(actualNotes, "; ")

				// Convert actualNoteParts to a map for efficient lookup
				actualNotesMap := make(map[string]bool)
				for _, part := range actualNoteParts {
					actualNotesMap[strings.TrimSpace(part)] = true
				}

				for _, expectedPart := range expectedNoteParts {
					trimmedExpectedPart := strings.TrimSpace(expectedPart)
					assert.True(t, actualNotesMap[trimmedExpectedPart], "Expected note component '%s' not found in actual notes. Actual notes: '%s'", trimmedExpectedPart, actualNotes)
				}
			} else if actualNotes != "" {
				// If no specific notes are expected, but notes are generated, check if they are only parse errors
				actualNoteParts := strings.Split(actualNotes, "; ")
				for _, part := range actualNoteParts {
					trimmedPart := strings.TrimSpace(part)
					if trimmedPart != "" && !strings.HasPrefix(trimmedPart, "Could not parse version") {
						assert.Fail(t, "Unexpected notes generated when none were expected (and not a parse error): "+actualNotes)
						break
					}
				}
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
