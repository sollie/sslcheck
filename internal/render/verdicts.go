package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/sollie/sslcheck/internal/verify"
)

func writeVerdicts(w io.Writer, p palette, verdicts []verify.Verdict) {
	if len(verdicts) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", p.heading.Sprint("Verdicts"))
	for _, v := range verdicts {
		status := p.ok.Sprint("pass")
		if !v.Pass {
			status = p.bad.Sprintf("fail (%s)", strings.Join(v.Reasons, ", "))
		}
		match := "no"
		if v.HostnameMatch {
			match = "yes"
		}
		_, _ = fmt.Fprintf(w, "  %s %s  hostname match: %s (%s)\n", p.label.Sprintf("%-8s", v.Store+":"), status, match, v.Name)
		if len(v.Path) > 0 {
			_, _ = fmt.Fprintf(w, "    path:   %s\n", strings.Join(v.Path, " -> "))
			_, _ = fmt.Fprintf(w, "    anchor: %s\n", v.Anchor)
		}
		for _, f := range v.Findings {
			c := p.bad
			if f.Severity == verify.Warning {
				c = p.warn
			}
			_, _ = fmt.Fprintf(w, "    %s %s\n", c.Sprint(f.Severity+":"), f.Message)
		}
	}
}
