package analyzer

// ReportItem represents the status of a single dependency
type ReportItem struct {
	Name           string `json:"name"` // package name
	CurrentVersion string `json:"current_version"` // version installed in the project
	LatestVersion  string `json:"latest_version"` // latest version available in the registry
	Deprecated     bool   `json:"deprecated"` // whether the package is deprecated
	Compatible     bool   `json:"compatible"` // whether the installed version satisfies peer dependency requirements
	Severity       string `json:"severity"` // e.g., "ok", "info", "warning", "error"
	// Notes provides additional context or details about the dependency's status,
	// such as reasons for a package being yanked, errors encountered during analysis (e.g., HTTP errors),
	// or messages indicating why no stable version was found or if a pinned version was not found in the registry.
	Notes          string `json:"notes,omitempty"`
}

// Analyzer defines the interface for dependency analyzers (npm, NuGet, etc.)
type Analyzer interface {
	// Analyze scans the given project path and returns a report for each dependency
	Analyze(path string) ([]ReportItem, error)
}
