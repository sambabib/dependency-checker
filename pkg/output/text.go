package output

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/sambabib/dependency-checker/pkg/analyzer"
)

// PrintTextReport prints the report items in a tabular text format
func PrintTextReport(reports []analyzer.ReportItem) {
	const notesLimit = 60 // Max characters for notes column

	// Initialize tabwriter
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0) // minwidth, tabwidth, padding, padchar, flags

	// Print header
	fmt.Fprintln(w, "NAME\tCURRENT\tLATEST\tSEVERITY\tCOMPAT\tDEPREC\tNOTES")
	fmt.Fprintln(w, "----\t-------\t------\t--------\t------\t------\t-----")

	// Print data rows
	for _, r := range reports {
		notes := r.Notes
		if len(notes) > notesLimit {
			notes = notes[:notesLimit-3] + "..."
		}
		notes = strings.ReplaceAll(notes, "\t", " ") // Replace tabs to avoid breaking alignment

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%t\t%s\n",
			r.Name,
			r.CurrentVersion,
			r.LatestVersion,
			r.Severity,
			r.Compatible,
			r.Deprecated,
			notes,
		)
	}

	// Flush the writer to print the table
	w.Flush()
}
