package rtk

import (
	"fmt"
	"regexp"
	"strings"
)

// Port of filters/buildOutput.js — compresses build tool output (npm,
// cargo, pip, maven, gradle): keeps errors, warnings and the final
// summary; strips progress/download noise.

var (
	reCargoErrCont   = regexp.MustCompile(`^\s*(-->|\||\d+\s*\||=)`)
	reNpmErr         = regexp.MustCompile(`(?i)^npm (ERR!|error)`)
	reYarnErr        = regexp.MustCompile(`(?i)^yarn error`)
	reNpmDeprecated  = regexp.MustCompile(`(?i)^npm warn deprecated`)
	reNpmWarn        = regexp.MustCompile(`(?i)^npm warn`)
	reYarnWarn       = regexp.MustCompile(`(?i)^yarn warn`)
	reCargoError     = regexp.MustCompile(`(?i)^error(\[|:)`)
	reCargoWarning   = regexp.MustCompile(`(?i)^warning(\[|:)`)
	reErrorColon     = regexp.MustCompile(`(?i)^ERROR:`)
	reBracketError   = regexp.MustCompile(`(?i)^\[ERROR\]`)
	reBuildFailed    = regexp.MustCompile(`(?i)^BUILD FAILED`)
	reBracketWarning = regexp.MustCompile(`(?i)^\[WARNING\]`)
	reCompiling      = regexp.MustCompile(`(?i)^\s*Compiling\s+\S+`)
	reDownloading    = regexp.MustCompile(`(?i)^\s*Downloading\s+\S+`)
	reFetching       = regexp.MustCompile(`^Fetching\s+`)
	reSummaryPkg     = regexp.MustCompile(`(?i)^(added|removed|changed|audited|installed)\s+\d+\s+package`)
	reSummaryFinish  = regexp.MustCompile(`(?i)^\s*Finished\s+`)
	reSummaryBuildOK = regexp.MustCompile(`(?i)^BUILD SUCCESS`)
	reSummaryCounts  = regexp.MustCompile(`^\d+\s+(vulnerabilities|packages?|warnings?|errors?)`)
	reSummarySuccess = regexp.MustCompile(`^Successfully (installed|built)`)
	reSummaryAddress = regexp.MustCompile(`^To address .* issues`)
	reSummaryRunNpm  = regexp.MustCompile("^Run `npm (audit|fund)`")
	reSummaryFunding = regexp.MustCompile(`packages are looking for funding`)
)

const deprecationKeep = 3 // DEPRECATION_KEEP in buildOutput.js

func BuildOutput(input string) string {
	lines := strings.Split(input, "\n")
	if len(lines) == 0 {
		return input
	}

	var errors, warnings, deprecations []string
	summary := ""
	hasSummary := false
	compilingCount, downloadingCount := 0, 0
	inCargoError := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Continuation of a cargo error block: keep verbatim.
		if inCargoError {
			if trimmed == "" {
				inCargoError = false
				continue
			}
			if reCargoErrCont.MatchString(line) {
				errors = append(errors, line)
				continue
			}
			inCargoError = false
		}

		if trimmed == "" {
			continue
		}

		switch {
		case reNpmErr.MatchString(trimmed) || reYarnErr.MatchString(trimmed):
			errors = append(errors, line)
		case reNpmDeprecated.MatchString(trimmed):
			deprecations = append(deprecations, line)
		case reNpmWarn.MatchString(trimmed) || reYarnWarn.MatchString(trimmed):
			warnings = append(warnings, line)
		case reCargoError.MatchString(trimmed) || strings.HasPrefix(trimmed, "error -->"):
			errors = append(errors, line)
			inCargoError = true
		case reCargoWarning.MatchString(trimmed) || strings.HasPrefix(trimmed, "warning -->"):
			warnings = append(warnings, line)
			inCargoError = true
		case reErrorColon.MatchString(trimmed):
			errors = append(errors, line)
		case reBracketError.MatchString(trimmed) || reBuildFailed.MatchString(trimmed):
			errors = append(errors, line)
		case reBracketWarning.MatchString(trimmed):
			warnings = append(warnings, line)
		case reCompiling.MatchString(trimmed):
			compilingCount++
		case reDownloading.MatchString(trimmed) || reFetching.MatchString(trimmed):
			downloadingCount++
		case reSummaryPkg.MatchString(trimmed) || reSummaryFinish.MatchString(trimmed) ||
			reSummaryBuildOK.MatchString(trimmed) || reSummaryCounts.MatchString(trimmed) ||
			reSummarySuccess.MatchString(trimmed) || reSummaryAddress.MatchString(trimmed) ||
			reSummaryRunNpm.MatchString(trimmed) || reSummaryFunding.MatchString(trimmed):
			if hasSummary {
				summary += "\n" + line
			} else {
				summary = line
				hasSummary = true
			}
		}
	}

	var out strings.Builder
	keepDep := deprecations
	if len(keepDep) > deprecationKeep {
		keepDep = keepDep[:deprecationKeep]
	}
	for _, d := range keepDep {
		out.WriteString(d + "\n")
	}
	if len(deprecations) > deprecationKeep {
		fmt.Fprintf(&out, "... +%d more deprecated packages\n", len(deprecations)-deprecationKeep)
	}
	if compilingCount > 0 {
		fmt.Fprintf(&out, "Compiled %d packages\n", compilingCount)
	}
	if downloadingCount > 0 {
		fmt.Fprintf(&out, "Downloaded %d packages\n", downloadingCount)
	}
	for _, e := range errors {
		out.WriteString(e + "\n")
	}
	keepWarnings := warnings
	if len(keepWarnings) > 5 {
		keepWarnings = keepWarnings[:5]
	}
	for _, w := range keepWarnings {
		out.WriteString(w + "\n")
	}
	if len(warnings) > 5 {
		fmt.Fprintf(&out, "... +%d more warnings\n", len(warnings)-5)
	}
	if hasSummary {
		out.WriteString(summary + "\n")
	}

	result := strings.TrimRight(out.String(), "\n")
	if result == "" {
		return input
	}
	return result
}
