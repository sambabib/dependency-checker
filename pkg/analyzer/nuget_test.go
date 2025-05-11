package analyzer

import (
	"testing"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"encoding/json"

	"github.com/stretchr/testify/assert"
)

func TestNewNuGetAnalyzer(t *testing.T) {
	analyzer := NewNuGetAnalyzer()
	assert.NotNil(t, analyzer, "NewNuGetAnalyzer() should not return nil")
	assert.Equal(t, "", analyzer.RegistryURL, "Default RegistryURL should be empty")
}

// MockNugetPackageInfo holds the data for a package in our mock registry.
type MockNugetPackageInfo struct {
	ID          string
	Versions    []MockNugetVersion // All versions available in the mock registry
	ShouldError bool               // If true, mock API returns an error for this package
	NotFound    bool               // If true, mock API returns 404 for this package
}

// MockNugetVersion represents a specific version of a package in the mock registry.
type MockNugetVersion struct {
	Version     string
	Listed      bool
	Deprecation *NuGetDeprecation // Use the same struct from nuget.go
}

// defaultMockServiceIndexResponse is a basic service index response for tests.
const defaultMockServiceIndexResponseFmt = `{
	"version": "3.0.0",
	"resources": [
		{
			"@id": "%s/v3/registrations/", 
			"@type": "RegistrationsBaseUrl/3.6.0",
			"comment": "Base URL of Azure Storage for Registration GZipped CURs"
		}
	]
}`

// mockNuGetRegistry starts a test HTTP server to simulate the NuGet API.
// expectedPackages maps packageID (lowercase) to its mock data.
func mockNuGetRegistry(t *testing.T, expectedPackages map[string]MockNugetPackageInfo) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Service Index request
		if r.URL.Path == "/v3/index.json" || r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			// The mock server URL is not known until it starts, so we format the response here.
			// To get the base URL of the current server for the @id field:
			baseURL := "http://" + r.Host // This gives http://ip:port
			fmt.Fprintf(w, defaultMockServiceIndexResponseFmt, baseURL)
			return
		}

		// Package Registration request: /v3/registrations/{package_id}/index.json
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 4 && parts[0] == "v3" && parts[1] == "registrations" && parts[3] == "index.json" {
			packageID := strings.ToLower(parts[2])
			pkgInfo, ok := expectedPackages[packageID]
			if !ok || pkgInfo.NotFound {
				http.NotFound(w, r)
				return
			}
			if pkgInfo.ShouldError {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			// Construct NuGetRegistrationIndex from MockNugetPackageInfo
			registrationItems := []NuGetRegistrationLeaf{}
			for _, v := range pkgInfo.Versions {
				listed := v.Listed // capture loop variable
				registrationItems = append(registrationItems, NuGetRegistrationLeaf{
					CatalogEntry: NuGetCatalogEntry{
						ID:          pkgInfo.ID,
						Version:     v.Version,
						Listed:      &listed,
						Deprecation: v.Deprecation,
					},
					Listed: &listed, // Some schemas have it directly on the leaf
				})
			}
			respData := NuGetRegistrationIndex{
				Items: []NuGetRegistrationPage{
					{Items: registrationItems, Count: len(registrationItems)},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(respData)
			return
		}

		http.Error(w, fmt.Sprintf("unexpected request to mock NuGet server: %s", r.URL.Path), http.StatusBadRequest)
	}))
	return server
}

// helper function to create a temporary .csproj file
func createTempCsproj(t *testing.T, dir string, filename string, content string) string {
	t.Helper()
	tempFilePath := filepath.Join(dir, filename)
	err := os.WriteFile(tempFilePath, []byte(content), 0644)
	assert.NoError(t, err, "Failed to write temp .csproj file")
	return tempFilePath
}

func TestNuGetAnalyzer_Analyze_BasicScenario(t *testing.T) {
	mockPackages := map[string]MockNugetPackageInfo{
		"newtonsoft.json": {
			ID: "Newtonsoft.Json",
			Versions: []MockNugetVersion{
				{Version: "12.0.1", Listed: true},
				{Version: "13.0.1", Listed: true}, // Latest stable
				{Version: "13.0.2-beta", Listed: true}, // Prerelease
			},
		},
		"microsoft.extensions.logging": {
			ID: "Microsoft.Extensions.Logging",
			Versions: []MockNugetVersion{
				{Version: "5.0.0", Listed: true}, // Current, but outdated
				{Version: "6.0.0", Listed: true}, // Latest stable
			},
		},
		"nodepackage": {
			ID: "NodePackage", // A node package to ensure it's ignored by NuGet analyzer
		},
		"leftpad.core": {
			ID: "LeftPad.Core",
			Versions: []MockNugetVersion{
				{Version: "1.0.0", Listed: true, Deprecation: &NuGetDeprecation{Message: "This package is legen-wait for it-dary!"}},
			},
		},
		"nonexistent.package": {
			ID: "NonExistent.Package",
			NotFound: true,
		},
	}

	server := mockNuGetRegistry(t, mockPackages)
	defer server.Close()

	analyzer := NewNuGetAnalyzer()
	analyzer.RegistryURL = server.URL + "/v3/index.json" // Point to our mock service index

	tempDir := t.TempDir()
	_ = createTempCsproj(t, tempDir, "projectA.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <ItemGroup>
	    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" /> <!-- Up to date -->
	    <PackageReference Include="Microsoft.Extensions.Logging" Version="5.0.0" /> <!-- Outdated -->
		<PackageReference Include="NonExistent.Package" Version="1.0.0" /> <!-- Not in registry -->
		<PackageReference Include="LeftPad.Core" Version="1.0.0" /> <!-- Deprecated -->
	  </ItemGroup>
	</Project>
	`)

	reports, err := analyzer.Analyze(tempDir)
	assert.NoError(t, err)
	assert.Len(t, reports, 3, "Expected 3 reports (package not found is currently skipped)")

	expectedReports := map[string]ReportItem{
		"Newtonsoft.Json":              {Name: "Newtonsoft.Json", CurrentVersion: "13.0.1", LatestVersion: "13.0.1", Deprecated: false, Compatible: true, Severity: "ok"},
		"Microsoft.Extensions.Logging": {Name: "Microsoft.Extensions.Logging", CurrentVersion: "5.0.0", LatestVersion: "6.0.0", Deprecated: false, Compatible: false, Severity: "error"},
		// NonExistent.Package will be handled by a TODO in nuget.go - currently logs and skips item creation
		// For now, we expect it not to be in the reports. This needs to be adjusted when error reporting is complete.
		"LeftPad.Core":                 {Name: "LeftPad.Core", CurrentVersion: "1.0.0", LatestVersion: "1.0.0", Deprecated: true, Compatible: false, Severity: "error"},
	}

	for _, r := range reports {
		expected, ok := expectedReports[r.Name]
		// Skip NonExistent.Package for now, as it's not added to reports yet by main code
		if r.Name == "NonExistent.Package" { // This condition will be removed later
			continue
		}
		assert.True(t, ok, "Unexpected package in report: %s", r.Name)
		assert.Equal(t, expected.CurrentVersion, r.CurrentVersion)
		assert.Equal(t, expected.LatestVersion, r.LatestVersion)
		assert.Equal(t, expected.Deprecated, r.Deprecated)
		assert.Equal(t, expected.Compatible, r.Compatible)
		assert.Equal(t, expected.Severity, r.Severity)
	}

	// Specific check for NonExistent.Package (once it's handled)
	// Need to update nuget.go to add these types of errors as ReportItems with appropriate severity.
	// For now, we'll assert that the count is 3, excluding NonExistent.Package
	actualReportCount := 0
	for _, r := range reports {
		if r.Name != "NonExistent.Package" {
			actualReportCount++
		}
	}
	assert.Equal(t, 3, actualReportCount, "Expected 3 reports after filtering NonExistent.Package")
}

func TestNuGetAnalyzer_Analyze_PackageNotFound(t *testing.T) {
	mockPackages := map[string]MockNugetPackageInfo{
		"actual.package": {
			ID: "Actual.Package",
			Versions: []MockNugetVersion{
				{Version: "1.0.0", Listed: true},
			},
		},
		"definitely.not.found": {
			ID:       "Definitely.Not.Found",
			NotFound: true,
		},
	}

	server := mockNuGetRegistry(t, mockPackages)
	defer server.Close()

	analyzer := NewNuGetAnalyzer()
	analyzer.RegistryURL = server.URL + "/v3/index.json"

	tempDir := t.TempDir()
	_ = createTempCsproj(t, tempDir, "projectB.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <ItemGroup>
	    <PackageReference Include="Actual.Package" Version="1.0.0" />
	    <PackageReference Include="Definitely.Not.Found" Version="1.2.3" />
	  </ItemGroup>
	</Project>
	`)

	reports, err := analyzer.Analyze(tempDir)
	assert.NoError(t, err, "Analyze should not return an error if a package is not found, it should log internally")
	assert.Len(t, reports, 1, "Expected 1 report for the actual package")

	if len(reports) == 1 {
		assert.Equal(t, "Actual.Package", reports[0].Name)
		assert.Equal(t, "1.0.0", reports[0].CurrentVersion)
		assert.Equal(t, "1.0.0", reports[0].LatestVersion)
		assert.Equal(t, "ok", reports[0].Severity)
	}
}

func TestNuGetAnalyzer_Analyze_NoCsprojFiles(t *testing.T) {
	analyzer := NewNuGetAnalyzer()
	// No server needed as it should fail before trying to access the registry

	tempDir := t.TempDir() // An empty directory

	reports, err := analyzer.Analyze(tempDir)
	assert.Error(t, err, "Expected an error when no .csproj files are found")
	if err != nil { // Check error message if an error is returned
		assert.Contains(t, err.Error(), "no .csproj files found")
	}
	assert.Nil(t, reports, "Reports should be nil when an error occurs due to no .csproj files")
}

func TestNuGetAnalyzer_Analyze_RegistryError_ServiceIndex(t *testing.T) {
	// Mock server that always fails for the service index
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/index.json" || r.URL.Path == "/" {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		// Other paths shouldn't be hit if service index fails
		http.Error(w, "unexpected request", http.StatusBadRequest)
	}))
	defer server.Close()

	analyzer := NewNuGetAnalyzer()
	analyzer.RegistryURL = server.URL + "/v3/index.json"

	tempDir := t.TempDir()
	_ = createTempCsproj(t, tempDir, "projectC.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <ItemGroup>
	    <PackageReference Include="Any.Package" Version="1.0.0" />
	  </ItemGroup>
	</Project>
	`)

	reports, err := analyzer.Analyze(tempDir)
	assert.Error(t, err, "Expected an error when service index fetch fails")
	assert.Contains(t, err.Error(), "failed to fetch NuGet service index") 
	assert.Nil(t, reports, "Reports should be nil when service index fetch fails")
}

func TestNuGetAnalyzer_Analyze_RegistryError_PackageRegistration(t *testing.T) {
	mockPackages := map[string]MockNugetPackageInfo{
		"good.package": {
			ID: "Good.Package",
			Versions: []MockNugetVersion{
				{Version: "1.0.0", Listed: true},
			},
		},
		"error.package": {
			ID: "Error.Package",
			ShouldError: true, // This package's registration lookup will fail
		},
	}

	server := mockNuGetRegistry(t, mockPackages)
	defer server.Close()

	analyzer := NewNuGetAnalyzer()
	analyzer.RegistryURL = server.URL + "/v3/index.json"

	tempDir := t.TempDir()
	_ = createTempCsproj(t, tempDir, "projectD.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <ItemGroup>
	    <PackageReference Include="Good.Package" Version="1.0.0" />
	    <PackageReference Include="Error.Package" Version="1.2.3" />
	  </ItemGroup>
	</Project>
	`)

	reports, err := analyzer.Analyze(tempDir)
	assert.NoError(t, err, "Analyze should not return a top-level error if only one package registration fails")
	assert.Len(t, reports, 1, "Expected 1 report for the good package")

	if len(reports) == 1 {
		assert.Equal(t, "Good.Package", reports[0].Name)
		assert.Equal(t, "1.0.0", reports[0].CurrentVersion)
	}
}

func TestNuGetAnalyzer_Analyze_EmptyCsproj(t *testing.T) {
	// Mock server, not strictly needed as no packages to look up, but good for consistency
	server := mockNuGetRegistry(t, map[string]MockNugetPackageInfo{})
	defer server.Close()

	analyzer := NewNuGetAnalyzer()
	analyzer.RegistryURL = server.URL + "/v3/index.json"

	tempDir := t.TempDir()
	_ = createTempCsproj(t, tempDir, "empty.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <!-- No ItemGroup with PackageReference -->
	</Project>
	`)
	_ = createTempCsproj(t, tempDir, "emptyItemGroup.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <ItemGroup>
	    <!-- Empty ItemGroup -->
	  </ItemGroup>
	</Project>
	`)

	reports, err := analyzer.Analyze(tempDir)
	assert.NoError(t, err, "Analyze should not error on .csproj with no PackageReferences")
	assert.Len(t, reports, 0, "Expected 0 reports for empty .csproj")
}

func TestNuGetAnalyzer_Analyze_Csproj_InvalidVersionFormat(t *testing.T) {
	mockPackages := map[string]MockNugetPackageInfo{
		"valid.package": {
			ID: "Valid.Package",
			Versions: []MockNugetVersion{{Version: "1.0.0", Listed: true}},
		},
	}
	server := mockNuGetRegistry(t, mockPackages)
	defer server.Close()

	analyzer := NewNuGetAnalyzer()
	analyzer.RegistryURL = server.URL + "/v3/index.json"

	tempDir := t.TempDir()
	_ = createTempCsproj(t, tempDir, "invalidVersion.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <ItemGroup>
	    <PackageReference Include="Invalid.Version.Package" Version="not-a-semver" />
	    <PackageReference Include="Valid.Package" Version="1.0.0" />
	  </ItemGroup>
	</Project>
	`)

	reports, err := analyzer.Analyze(tempDir)
	assert.NoError(t, err, "Analyze should not error out completely for one invalid version string")
	assert.Len(t, reports, 1, "Expected 1 report for the valid package")
	if len(reports) == 1 {
		assert.Equal(t, "Valid.Package", reports[0].Name)
	}
}

func TestNuGetAnalyzer_Analyze_Outdated_MinorPatch(t *testing.T) {
	mockPackages := map[string]MockNugetPackageInfo{
		"minor.update.pkg": {
			ID: "Minor.Update.Pkg",
			Versions: []MockNugetVersion{
				{Version: "1.0.0", Listed: true},
				{Version: "1.1.0", Listed: true}, // Latest stable
			},
		},
		"patch.update.pkg": {
			ID: "Patch.Update.Pkg",
			Versions: []MockNugetVersion{
				{Version: "2.0.0", Listed: true},
				{Version: "2.0.1", Listed: true}, // Latest stable
			},
		},
	}
	server := mockNuGetRegistry(t, mockPackages)
	defer server.Close()

	analyzer := NewNuGetAnalyzer()
	analyzer.RegistryURL = server.URL + "/v3/index.json"

	tempDir := t.TempDir()
	_ = createTempCsproj(t, tempDir, "updates.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <ItemGroup>
	    <PackageReference Include="Minor.Update.Pkg" Version="1.0.0" />
	    <PackageReference Include="Patch.Update.Pkg" Version="2.0.0" />
	  </ItemGroup>
	</Project>
	`)

	reports, err := analyzer.Analyze(tempDir)
	assert.NoError(t, err)
	assert.Len(t, reports, 2)

	expected := map[string]ReportItem{
		"Minor.Update.Pkg": {Name: "Minor.Update.Pkg", CurrentVersion: "1.0.0", LatestVersion: "1.1.0", Severity: "warning", Compatible: true},
		"Patch.Update.Pkg": {Name: "Patch.Update.Pkg", CurrentVersion: "2.0.0", LatestVersion: "2.0.1", Severity: "warning", Compatible: true},
	}

	for _, r := range reports {
		assert.Equal(t, expected[r.Name].LatestVersion, r.LatestVersion)
		assert.Equal(t, expected[r.Name].Severity, r.Severity)
		assert.Equal(t, expected[r.Name].Compatible, r.Compatible)
	}
}

func TestNuGetAnalyzer_Analyze_Version_NewerThanStable(t *testing.T) {
	mockPackages := map[string]MockNugetPackageInfo{
		"beta.user.pkg": {
			ID: "Beta.User.Pkg",
			Versions: []MockNugetVersion{
				{Version: "1.0.0", Listed: true}, // Latest stable
				{Version: "1.0.1-beta", Listed: true},
			},
		},
	}
	server := mockNuGetRegistry(t, mockPackages)
	defer server.Close()

	analyzer := NewNuGetAnalyzer()
	analyzer.RegistryURL = server.URL + "/v3/index.json"

	tempDir := t.TempDir()
	_ = createTempCsproj(t, tempDir, "beta.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <ItemGroup>
	    <PackageReference Include="Beta.User.Pkg" Version="1.0.1-beta" />
	  </ItemGroup>
	</Project>
	`)

	reports, err := analyzer.Analyze(tempDir)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)

	if len(reports) == 1 {
		assert.Equal(t, "Beta.User.Pkg", reports[0].Name)
		assert.Equal(t, "1.0.1-beta", reports[0].CurrentVersion)
		assert.Equal(t, "1.0.0", reports[0].LatestVersion) // Latest stable from registry
		assert.Equal(t, "info", reports[0].Severity) // Using newer than stable is 'info'
		assert.True(t, reports[0].Compatible) // Still considered compatible
	}
}

func TestNuGetAnalyzer_Analyze_NoStableVersionInRegistry(t *testing.T) {
	mockPackages := map[string]MockNugetPackageInfo{
		"prerelease.only.pkg": {
			ID: "Prerelease.Only.Pkg",
			Versions: []MockNugetVersion{
				{Version: "1.0.0-alpha", Listed: true},
				{Version: "1.0.0-beta", Listed: true},
			},
		},
	}
	server := mockNuGetRegistry(t, mockPackages)
	defer server.Close()

	analyzer := NewNuGetAnalyzer()
	analyzer.RegistryURL = server.URL + "/v3/index.json"

	tempDir := t.TempDir()
	_ = createTempCsproj(t, tempDir, "prereleaseonly.csproj", `
	<Project Sdk="Microsoft.NET.Sdk">
	  <ItemGroup>
	    <PackageReference Include="Prerelease.Only.Pkg" Version="1.0.0-alpha" />
	  </ItemGroup>
	</Project>
	`)

	reports, err := analyzer.Analyze(tempDir)
	assert.NoError(t, err, "Analyze should not error out if a package has no stable versions, it logs internally")
	// Expect 0 reports because getLatestStableVersion currently only looks for non-prerelease versions.
	// If none are found, it returns an error, and Analyze skips the package.
	assert.Len(t, reports, 0, "Expected 0 reports when only prerelease versions exist in registry")
}

// TODO: Add more tests as NuGetAnalyzer.Analyze is implemented:
// - TestAnalyze_Basic (happy path, up-to-date, outdated, deprecated)
// - TestAnalyze_CsprojNotFound
// - TestAnalyze_InvalidCsprojFormat
// - TestAnalyze_PackageNotFoundInRegistry
// - TestAnalyze_RegistryFetchError
