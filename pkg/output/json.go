package output

import (
	"encoding/json"

	"github.com/sambabib/dependency-checker/pkg/analyzer"
)

// GenerateJSONReport converts analyzer report items to JSON format
func GenerateJSONReport(reports []analyzer.ReportItem) ([]byte, error) {
	return json.MarshalIndent(reports, "", "  ")
}
