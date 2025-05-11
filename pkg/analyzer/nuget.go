package analyzer

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const defaultNuGetRegistryURL = "https://api.nuget.org/v3/index.json" // Service Index

// NuGetAnalyzer handles the analysis of .NET dependencies.
// It parses .csproj files to find PackageReference items and queries the NuGet API.
type NuGetAnalyzer struct {
	RegistryURL string // Allows overriding the NuGet API URL for testing
}

// NewNuGetAnalyzer creates a new NuGetAnalyzer.
func NewNuGetAnalyzer() *NuGetAnalyzer {
	return &NuGetAnalyzer{}
}

// CsprojProject represents the root of a .csproj file.
type CsprojProject struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []ItemGroup `xml:"ItemGroup"`
}

// ItemGroup contains a list of PackageReferences.
type ItemGroup struct {
	XMLName           xml.Name           `xml:"ItemGroup"`
	PackageReferences []PackageReference `xml:"PackageReference"`
	Condition         string             `xml:"Condition,attr"`
}

// PackageReference represents a NuGet package dependency.
type PackageReference struct {
	XMLName        xml.Name `xml:"PackageReference"`
	Include        string   `xml:"Include,attr"` // Package ID
	Version        string   `xml:"Version,attr"` // Version string from attribute
	VersionElement string   `xml:"Version"`      // Version string from child <Version> element
}

// extractedPackage holds the raw data extracted from a .csproj file.
type extractedPackage struct {
	ID      string
	Version string
	SourceFile string // The .csproj file it came from
}

// NuGetServiceIndex is for parsing the /v3/index.json response
type NuGetServiceIndex struct {
	Resources []NuGetResource `json:"resources"`
}

// NuGetResource represents a resource in the service index.
type NuGetResource struct {
	ID      string `json:"@id"`
	Type    string `json:"@type"` // We're looking for types like "RegistrationsBaseUrl/3.6.0"
	Comment string `json:"comment"`
}

// NuGetRegistrationIndex is for the response from /v3/registrationX-semverX/{package_id}/index.json
type NuGetRegistrationIndex struct {
	Items []NuGetRegistrationPage `json:"items"` // Pages of registration items; typically one for non-paged results
}

// NuGetRegistrationPage contains a list of actual package versions (leaves) or further pages.
type NuGetRegistrationPage struct {
	Items         []NuGetRegistrationLeaf `json:"items,omitempty"` // Use omitempty as sometimes items are at the root of RegistrationIndex
	Lower         string                  `json:"lower,omitempty"`
	Upper         string                  `json:"upper,omitempty"`
	Count         int                     `json:"count,omitempty"`
}

// NuGetRegistrationLeaf represents a specific version of a package.
type NuGetRegistrationLeaf struct {
	CatalogEntry NuGetCatalogEntry `json:"catalogEntry"`
	Listed       *bool             `json:"listed,omitempty"` // Pointer to handle missing 'listed' which implies true if parent page is listed
}

// NuGetCatalogEntry contains details like version and deprecation.
type NuGetCatalogEntry struct {
	ID           string              `json:"id"`
	Version      string              `json:"version"`
	Deprecation  *NuGetDeprecation   `json:"deprecation,omitempty"`
	Listed       *bool               `json:"listed,omitempty"` // Ensure this is correctly parsed; sometimes absent means true
	Published    string              `json:"published"`
}

// NuGetDeprecation holds information about package deprecation.
type NuGetDeprecation struct {
	Reasons          []string          `json:"reasons"`
	Message          string            `json:"message,omitempty"`
	AlternatePackage *AlternatePackage `json:"alternatePackage,omitempty"`
}

// AlternatePackage provides info if a package is deprecated in favor of another.
type AlternatePackage struct {
	ID    string `json:"id"`
	Range string `json:"range,omitempty"`
}

// Analyze looks for .csproj files in the given path, parses them,
// and checks dependencies against the NuGet registry.
func (a *NuGetAnalyzer) Analyze(path string) ([]ReportItem, error) {
	csprojFiles := []string{}
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(p) == ".csproj" {
			csprojFiles = append(csprojFiles, p)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %w", path, err)
	}

	if len(csprojFiles) == 0 {
		return nil, fmt.Errorf("no .csproj files found in %s", path)
	}

	extractedPackages := []extractedPackage{}
	for _, csprojPath := range csprojFiles {
		content, err := os.ReadFile(csprojPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read .csproj file %s: %w", csprojPath, err)
		}

		var project CsprojProject
		if err := xml.Unmarshal(content, &project); err != nil {
			return nil, fmt.Errorf("failed to unmarshal .csproj file %s: %w", csprojPath, err)
		}

		for _, itemGroup := range project.ItemGroups {
			// TODO: Potentially evaluate ItemGroup.Condition if it's relevant for dependency inclusion
			for _, pkgRef := range itemGroup.PackageReferences {
				pkgVersion := pkgRef.Version
				if pkgVersion == "" {
					pkgVersion = pkgRef.VersionElement
				}
				if pkgRef.Include != "" && pkgVersion != "" {
					extractedPackages = append(extractedPackages, extractedPackage{
						ID:      pkgRef.Include,
						Version: pkgVersion,
						SourceFile: csprojPath,
					})
				}
			}
		}
	}

	if len(extractedPackages) == 0 {
		// This could be valid if .csproj files exist but have no PackageReferences
		return []ReportItem{}, nil
	}

	registryURLToUse := defaultNuGetRegistryURL
	if a.RegistryURL != "" {
		registryURLToUse = a.RegistryURL
	}

	// 1. Fetch Service Index to find RegistrationsBaseUrl
	resp, err := http.Get(registryURLToUse) // nosemgrep: go.lang.security.audit.net.gosec.G107.G107
	if err != nil {
		return nil, fmt.Errorf("failed to fetch NuGet service index from %s: %w", registryURLToUse, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch NuGet service index: status %s", resp.Status)
	}

	var serviceIndex NuGetServiceIndex
	if err := json.NewDecoder(resp.Body).Decode(&serviceIndex); err != nil {
		return nil, fmt.Errorf("failed to decode NuGet service index: %w", err)
	}

	var registrationsBaseURL string
	for _, resource := range serviceIndex.Resources {
		// Common types: "RegistrationsBaseUrl", "RegistrationsBaseUrl/3.6.0", "PackageBaseAddress/3.0.0"
		if strings.HasPrefix(resource.Type, "RegistrationsBaseUrl") {
			registrationsBaseURL = resource.ID
			break
		}
	}

	if registrationsBaseURL == "" {
		return nil, fmt.Errorf("could not find RegistrationsBaseUrl in NuGet service index at %s", registryURLToUse)
	}
	// fmt.Printf("Using NuGet RegistrationsBaseUrl: %s\n", registrationsBaseURL) // For debugging

	reportItems := []ReportItem{}

	for _, pkg := range extractedPackages {
		packageID := strings.ToLower(pkg.ID) // NuGet package IDs are case-insensitive in the registry
		packageURL := fmt.Sprintf("%s%s/index.json", registrationsBaseURL, packageID)

		pkgResp, err := http.Get(packageURL) // nosemgrep: go.lang.security.audit.net.gosec.G107.G107
		if err != nil {
			// TODO: Handle this more gracefully, maybe add to report as an error
			fmt.Printf("Error fetching package %s: %v\n", packageID, err)
			continue
		}
		defer pkgResp.Body.Close()

		if pkgResp.StatusCode == http.StatusNotFound {
			fmt.Printf("Package %s not found in registry at %s\n", packageID, packageURL)
			// TODO: Add to report as 'package not found'
			continue
		}
		if pkgResp.StatusCode != http.StatusOK {
			fmt.Printf("Error fetching package %s: status %s\n", packageID, pkgResp.Status)
			// TODO: Add to report as 'registry error'
			continue
		}

		var regIndex NuGetRegistrationIndex
		if err := json.NewDecoder(pkgResp.Body).Decode(&regIndex); err != nil {
			fmt.Printf("Error decoding package registration for %s: %v\n", packageID, err)
			// TODO: Add to report as 'decode error'
			continue
		}

		var latestStableVersion *semver.Version
		var latestStableCatalogEntry *NuGetCatalogEntry

		for _, page := range regIndex.Items {
			for _, leaf := range page.Items {
				// Check if listed (true if Listed is nil or *Listed is true)
				isListed := leaf.CatalogEntry.Listed == nil || *leaf.CatalogEntry.Listed
				if leaf.Listed != nil && !*leaf.Listed { // Some schemas have Listed on the leaf itself
					isListed = false
				}
				if !isListed {
					continue
				}

				v, err := semver.NewVersion(leaf.CatalogEntry.Version)
				if err != nil {
					// Skip invalid versions
					continue
				}

				if v.Prerelease() != "" {
					// Skip pre-releases
					continue
				}

				if latestStableVersion == nil || v.GreaterThan(latestStableVersion) {
					latestStableVersion = v
					entryCopy := leaf.CatalogEntry // Make a copy to avoid pointer issues with the loop variable
					latestStableCatalogEntry = &entryCopy
				}
			}
		}

		if latestStableVersion == nil {
			fmt.Printf("No stable, listed version found for package %s\n", packageID)
			// TODO: Add to report as 'no stable version found'
			continue
		}

		fmt.Printf("Package: %s, ProjectVersion: %s, LatestStable: %s\n", pkg.ID, pkg.Version, latestStableVersion.String())
		if latestStableCatalogEntry.Deprecation != nil {
			fmt.Printf("  DEPRECATED: %s\n", latestStableCatalogEntry.Deprecation.Message)
			if latestStableCatalogEntry.Deprecation.AlternatePackage != nil {
				fmt.Printf("  Alternate: %s (Range: %s)\n", 
					latestStableCatalogEntry.Deprecation.AlternatePackage.ID, 
					latestStableCatalogEntry.Deprecation.AlternatePackage.Range)
			}
		}

		// --- Comparison and ReportItem population ---
		item := ReportItem{
			Name:          pkg.ID,
			CurrentVersion: pkg.Version,
			LatestVersion: latestStableVersion.String(),
			Compatible:    true, // Assume compatible unless determined otherwise
			Severity:      "ok",
		}

		var issues []string

		if latestStableCatalogEntry.Deprecation != nil {
			item.Deprecated = true
			message := fmt.Sprintf("Deprecated: %s", latestStableCatalogEntry.Deprecation.Message)
			if latestStableCatalogEntry.Deprecation.AlternatePackage != nil {
				message += fmt.Sprintf(". Consider %s (Range: %s)", 
					latestStableCatalogEntry.Deprecation.AlternatePackage.ID, 
					latestStableCatalogEntry.Deprecation.AlternatePackage.Range) 
			}
			issues = append(issues, message)
			item.Severity = "error"
			item.Compatible = false // Generally, deprecated means incompatible with future/best practices
		}

		currentSemVer, err := semver.NewVersion(pkg.Version)
		if err != nil {
			issues = append(issues, fmt.Sprintf("Could not parse project version '%s': %v", pkg.Version, err))
			item.Severity = "warning"
			item.Compatible = false
		} else {
			if currentSemVer.LessThan(latestStableVersion) {
				issues = append(issues, fmt.Sprintf("Project version %s is older than latest stable %s", currentSemVer.String(), latestStableVersion.String()))
				if item.Severity == "ok" || item.Severity == "info" { 
					item.Severity = "warning" 
				}
				if currentSemVer.Major() < latestStableVersion.Major() && item.Severity != "error" {
					item.Severity = "error" 
					item.Compatible = false // Major version diff often implies incompatibility
				}
			} else if currentSemVer.GreaterThan(latestStableVersion) && !item.Deprecated {
				issues = append(issues, fmt.Sprintf("Project version %s is newer than latest known stable %s", currentSemVer.String(), latestStableVersion.String()))
				if item.Severity == "ok" {
					item.Severity = "info" 
				}
			}
		}

		// TODO: Add specific ReportItems for 'package not found', 'no stable version', 'registry error', 'decode error'
		// These would be created in the 'continue' blocks above and appended directly.
		// For now, if there are issues, they are logged above and the item.Severity/Compatible reflects them.
		// We could add a Message field to ReportItem if we want to pass these detailed strings.

		reportItems = append(reportItems, item)
	}

	return reportItems, nil
}

// Helper to parse .csproj content (example)
// func parseCsproj(filePath string) (map[string]string, error) { ... }

// Helper to query NuGet API (example)
// func queryNuGetAPI(packageID, registryBaseURL string) (latestVersion string, deprecated bool, err error) { ... }
