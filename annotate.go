package agentbox

import "strings"

// annotateStderrWithViolations appends sandbox violation information to stderr output.
// This helps users understand why a command failed due to sandbox restrictions.
// If there are no violations, the original stderr string is returned unchanged.
func annotateStderrWithViolations(stderr string, violations []string) string {
	if len(violations) == 0 {
		return stderr
	}
	var b strings.Builder
	b.WriteString(stderr)
	b.WriteString("\n<sandbox_violations>\n")
	for _, v := range violations {
		b.WriteString(v)
		b.WriteString("\n")
	}
	b.WriteString("</sandbox_violations>")
	return b.String()
}
