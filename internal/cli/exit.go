package cli

// Exit codes.
const (
	ExitClean   = 0 // no findings
	ExitFindings = 1 // one or more findings
	ExitError   = 2 // runtime or config error
	ExitPartial = 3 // completed but some streams failed
)
