package output

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sambabib/dependency-checker/pkg/analyzer"
)

// SARIF format specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// SarifReport represents the top-level SARIF report structure
type SarifReport struct {
	Schema  string        `json:"$schema"`
	Version string        `json:"version"`
	Runs    []SarifRun    `json:"runs"`
}

// SarifRun represents a single run of the analysis tool
type SarifRun struct {
	Tool        SarifTool        `json:"tool"`
	Results     []SarifResult    `json:"results"`
	Invocations []SarifInvocation `json:"invocations"`
}

// SarifTool represents the tool that performed the analysis
type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

// SarifDriver represents the driver of the tool
type SarifDriver struct {
	Name            string           `json:"name"`
	Version         string           `json:"version"`
	InformationURI  string           `json:"informationUri"`
	Rules           []SarifRule      `json:"rules"`
}

// SarifRule represents a rule that was evaluated during the analysis
type SarifRule struct {
	ID               string            `json:"id"`
	ShortDescription SarifMessage      `json:"shortDescription"`
	FullDescription  SarifMessage      `json:"fullDescription"`
	Help             SarifMessage      `json:"help"`
	Properties       map[string]string `json:"properties,omitempty"`
}

// SarifResult represents a result of the analysis
type SarifResult struct {
	RuleID    string        `json:"ruleId"`
	Level     string        `json:"level"`
	Message   SarifMessage  `json:"message"`
	Locations []SarifLocation `json:"locations"`
}

// SarifMessage represents a message in the SARIF report
type SarifMessage struct {
	Text string `json:"text"`
}

// SarifLocation represents a location in the code
type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

// SarifPhysicalLocation represents a physical location in the code
type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region,omitempty"`
}

// SarifArtifactLocation represents the location of an artifact
type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

// SarifRegion represents a region in the code
type SarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// SarifInvocation represents an invocation of the tool
type SarifInvocation struct {
	ExecutionSuccessful bool      `json:"executionSuccessful"`
	StartTimeUtc        string    `json:"startTimeUtc"`
	EndTimeUtc          string    `json:"endTimeUtc"`
}

// GenerateSarifReport converts analyzer report items to SARIF format
func GenerateSarifReport(reports []analyzer.ReportItem, projectPath string) ([]byte, error) {
	// Define rules
	rules := []SarifRule{
		{
			ID: "outdated-major",
			ShortDescription: SarifMessage{Text: "Major version update available"},
			FullDescription: SarifMessage{Text: "A major version update is available for this dependency, which may include breaking changes."},
			Help: SarifMessage{Text: "Consider updating with caution and review the changelog for breaking changes."},
		},
		{
			ID: "outdated-minor",
			ShortDescription: SarifMessage{Text: "Minor version update available"},
			FullDescription: SarifMessage{Text: "A minor version update is available for this dependency, which may include new features."},
			Help: SarifMessage{Text: "Consider updating to get new features."},
		},
		{
			ID: "outdated-patch",
			ShortDescription: SarifMessage{Text: "Patch update available"},
			FullDescription: SarifMessage{Text: "A patch update is available for this dependency, which may include bug fixes."},
			Help: SarifMessage{Text: "Consider updating to get bug fixes."},
		},
		{
			ID: "deprecated",
			ShortDescription: SarifMessage{Text: "Deprecated dependency"},
			FullDescription: SarifMessage{Text: "This dependency is marked as deprecated by its maintainers."},
			Help: SarifMessage{Text: "Consider finding an alternative or replacement package."},
		},
		{
			ID: "incompatible",
			ShortDescription: SarifMessage{Text: "Incompatible dependency"},
			FullDescription: SarifMessage{Text: "This dependency is incompatible with other dependencies in the project."},
			Help: SarifMessage{Text: "Consider updating to a compatible version."},
		},
	}

	// Convert report items to SARIF results
	results := make([]SarifResult, 0, len(reports))
	for _, report := range reports {
		// Determine rule ID and level based on severity and status
		ruleID := "outdated-patch"
		level := "note"

		if report.Deprecated {
			ruleID = "deprecated"
			level = "warning"
		} else if !report.Compatible {
			ruleID = "incompatible"
			level = "error"
		} else if report.Severity == "error" {
			ruleID = "outdated-major"
			level = "warning"
		} else if report.Severity == "warning" {
			ruleID = "outdated-minor"
			level = "note"
		}

		// Create message text
		messageText := fmt.Sprintf("%s: current version %s, latest version %s", 
			report.Name, report.CurrentVersion, report.LatestVersion)
		
		if report.Notes != "" {
			messageText += fmt.Sprintf(" (%s)", report.Notes)
		}

		// Create SARIF result
		result := SarifResult{
			RuleID: ruleID,
			Level:  level,
			Message: SarifMessage{
				Text: messageText,
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI: projectPath,
						},
					},
				},
			},
		}

		results = append(results, result)
	}

	// Create SARIF report
	now := time.Now().UTC()
	sarifReport := SarifReport{
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "Dependency Checker",
						Version:        "1.0.0", // TODO: Get actual version
						InformationURI: "https://github.com/sambabib/dependency-checker",
						Rules:          rules,
					},
				},
				Results: results,
				Invocations: []SarifInvocation{
					{
						ExecutionSuccessful: true,
						StartTimeUtc:        now.Add(-time.Second).Format(time.RFC3339),
						EndTimeUtc:          now.Format(time.RFC3339),
					},
				},
			},
		},
	}

	// Marshal to JSON
	return json.MarshalIndent(sarifReport, "", "  ")
}
