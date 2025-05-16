package analyzer

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMavenAnalyzer(t *testing.T) {
	analyzer := NewMavenAnalyzer()
	assert.NotNil(t, analyzer)
	assert.Equal(t, defaultMavenRegistryURL, analyzer.registryURL)
}

func TestMavenAnalyzer_Analyze_BasicScenario(t *testing.T) {
	// Create a test server to mock Maven repository responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/com/example/library/maven-metadata.xml":
			// Return metadata for a library with multiple versions
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>library</artifactId>
  <versioning>
    <latest>2.0.0</latest>
    <release>2.0.0</release>
    <versions>
      <version>1.0.0</version>
      <version>1.1.0</version>
      <version>1.1.1</version>
      <version>2.0.0</version>
      <version>2.0.1-SNAPSHOT</version>
    </versions>
    <lastUpdated>20250101000000</lastUpdated>
  </versioning>
</metadata>`))
		case "/org/example/framework/maven-metadata.xml":
			// Return metadata for an up-to-date dependency
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.example</groupId>
  <artifactId>framework</artifactId>
  <versioning>
    <latest>3.2.1</latest>
    <release>3.2.1</release>
    <versions>
      <version>3.0.0</version>
      <version>3.1.0</version>
      <version>3.2.0</version>
      <version>3.2.1</version>
    </versions>
    <lastUpdated>20250101000000</lastUpdated>
  </versioning>
</metadata>`))
		case "/org/nonexistent/package/maven-metadata.xml":
			// Return 404 for non-existent package
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "TestMavenAnalyzer_Analyze_BasicScenario")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a pom.xml file with test dependencies
	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.test</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <!-- Outdated dependency -->
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>library</artifactId>
            <version>1.0.0</version>
        </dependency>
        <!-- Up-to-date dependency -->
        <dependency>
            <groupId>org.example</groupId>
            <artifactId>framework</artifactId>
            <version>3.2.1</version>
        </dependency>
        <!-- Non-existent dependency -->
        <dependency>
            <groupId>org.nonexistent</groupId>
            <artifactId>package</artifactId>
            <version>1.0.0</version>
        </dependency>
        <!-- Test dependency (should be skipped) -->
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.12</version>
            <scope>test</scope>
        </dependency>
        <!-- Optional dependency (should be skipped) -->
        <dependency>
            <groupId>org.optional</groupId>
            <artifactId>package</artifactId>
            <version>1.0.0</version>
            <optional>true</optional>
        </dependency>
    </dependencies>
</project>`

	pomPath := filepath.Join(tempDir, "pom.xml")
	if err := os.WriteFile(pomPath, []byte(pomContent), 0644); err != nil {
		t.Fatalf("Failed to write pom.xml: %v", err)
	}

	// Create the analyzer with custom registry URL
	analyzer := &MavenAnalyzer{
		registryURL: server.URL,
	}

	// Run the analysis
	reports, err := analyzer.Analyze(tempDir)
	assert.NoError(t, err)
	assert.Len(t, reports, 3) // 3 non-test, non-optional dependencies

	// Check the outdated dependency
	outdatedReport := findReportByName(reports, "com.example:library")
	assert.NotNil(t, outdatedReport)
	assert.Equal(t, "1.0.0", outdatedReport.CurrentVersion)
	assert.Equal(t, "2.0.0", outdatedReport.LatestVersion)
	assert.Equal(t, "error", outdatedReport.Severity) // Major version update
	assert.False(t, outdatedReport.Compatible)

	// Check the up-to-date dependency
	uptodateReport := findReportByName(reports, "org.example:framework")
	assert.NotNil(t, uptodateReport)
	assert.Equal(t, "3.2.1", uptodateReport.CurrentVersion)
	assert.Equal(t, "3.2.1", uptodateReport.LatestVersion)
	assert.Equal(t, "info", uptodateReport.Severity)
	assert.True(t, uptodateReport.Compatible)

	// Check the non-existent dependency
	nonexistentReport := findReportByName(reports, "org.nonexistent:package")
	assert.NotNil(t, nonexistentReport)
	assert.Equal(t, "1.0.0", nonexistentReport.CurrentVersion)
	assert.Equal(t, "unknown", nonexistentReport.LatestVersion)
	assert.Equal(t, "error", nonexistentReport.Severity)
	assert.False(t, nonexistentReport.Compatible)
}

func TestMavenAnalyzer_Analyze_NoPomFiles(t *testing.T) {
	// Create a temporary directory with no pom.xml files
	tempDir, err := os.MkdirTemp("", "TestMavenAnalyzer_Analyze_NoPomFiles")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	analyzer := NewMavenAnalyzer()
	reports, err := analyzer.Analyze(tempDir)
	assert.Error(t, err)
	assert.Nil(t, reports)
	assert.Contains(t, err.Error(), "no pom.xml files found")
}

func TestMavenAnalyzer_Analyze_InvalidPomXml(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "TestMavenAnalyzer_Analyze_InvalidPomXml")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create an invalid pom.xml file
	invalidPomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <this-is-invalid>
</project>`

	pomPath := filepath.Join(tempDir, "pom.xml")
	if err := os.WriteFile(pomPath, []byte(invalidPomContent), 0644); err != nil {
		t.Fatalf("Failed to write pom.xml: %v", err)
	}

	analyzer := NewMavenAnalyzer()
	// We expect the analysis to complete but with error messages in the logs
	// The actual behavior is that it logs the error and continues
	reports, err := analyzer.Analyze(tempDir)
	// The error should be nil because the analyzer handles the error internally
	assert.NoError(t, err)
	// But we should get an empty report list
	assert.Empty(t, reports)
}

func TestMavenAnalyzer_resolveVersionProperty(t *testing.T) {
	analyzer := NewMavenAnalyzer()

	// Test with a pom.xml that has project version
	pom := PomXML{
		Version: "1.2.3",
	}

	// Test resolving project.version
	resolved := analyzer.resolveVersionProperty("${project.version}", pom)
	assert.Equal(t, "1.2.3", resolved)

	// Test resolving pom.version
	resolved = analyzer.resolveVersionProperty("${pom.version}", pom)
	assert.Equal(t, "1.2.3", resolved)

	// Test with a pom.xml that has parent version but no project version
	pom = PomXML{
		Parent: PomParent{
			Version: "2.3.4",
		},
	}

	// Test resolving project.version from parent
	resolved = analyzer.resolveVersionProperty("${project.version}", pom)
	assert.Equal(t, "2.3.4", resolved)

	// Test with a regular version (no property)
	resolved = analyzer.resolveVersionProperty("3.4.5", pom)
	assert.Equal(t, "3.4.5", resolved)

	// Test with an unknown property
	resolved = analyzer.resolveVersionProperty("${unknown.property}", pom)
	assert.Equal(t, "", resolved)
}

func TestMavenAnalyzer_getLatestStableVersion(t *testing.T) {
	analyzer := NewMavenAnalyzer()

	// Test with a mix of stable and unstable versions
	versions := []string{
		"1.0.0",
		"1.1.0",
		"1.2.0-SNAPSHOT",
		"1.2.0-alpha",
		"1.2.0-beta",
		"1.2.0-rc1",
		"1.2.0",
		"1.3.0-m1",
	}

	latest, err := analyzer.getLatestStableVersion(versions)
	assert.NoError(t, err)
	assert.Equal(t, "1.2.0", latest)

	// Test with only unstable versions
	unstableVersions := []string{
		"1.0.0-SNAPSHOT",
		"1.1.0-alpha",
		"1.2.0-beta",
	}

	latest, err = analyzer.getLatestStableVersion(unstableVersions)
	assert.Error(t, err)
	assert.Equal(t, "", latest)
	assert.Contains(t, err.Error(), "no stable versions found")

	// Test with empty list
	latest, err = analyzer.getLatestStableVersion([]string{})
	assert.Error(t, err)
	assert.Equal(t, "", latest)
	assert.Contains(t, err.Error(), "no versions available")

	// Test with invalid semver
	invalidVersions := []string{
		"not-a-version",
		"also-not-a-version",
	}

	latest, err = analyzer.getLatestStableVersion(invalidVersions)
	assert.Error(t, err)
	assert.Equal(t, "", latest)
	assert.Contains(t, err.Error(), "no stable versions found")
}

// Helper function to find a report by name
func findReportByName(reports []ReportItem, name string) *ReportItem {
	for _, report := range reports {
		if report.Name == name {
			return &report
		}
	}
	return nil
}
