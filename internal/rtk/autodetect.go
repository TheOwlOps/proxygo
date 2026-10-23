package rtk

import (
	"regexp"
	"strings"
)

// Port of open-sse/rtk/autodetect.js — detection order is significant:
// git-log → git-diff → git-status → build-output → grep → find → tree →
// ls → search-list → read-numbered → dedup-log → smart-truncate → none.

var (
	reGitDiff       = regexp.MustCompile(`(?m)^diff --git `)
	reGitDiffHunk   = regexp.MustCompile(`(?m)^@@ `)
	reGitStatus     = regexp.MustCompile(`(?m)(^On branch |^nothing to commit|^Changes (not |to be )|^Untracked files:)`)
	reGitLog        = regexp.MustCompile(`(?m)^[*|/\\ ]*commit [0-9a-f]{7,40}$`)
	rePorcelain     = regexp.MustCompile(`^[ MADRCU?!][ MADRCU?!] \S`)
	reBuildOutput   = regexp.MustCompile(`(?im)^(npm (warn|error|ERR!)|yarn (warn|error)|\s*Compiling\s+\S+|\s*Downloading\s+\S+|added \d+ package|\[ERROR\]|BUILD (SUCCESS|FAILED)|\s*Finished\s+|Successfully (installed|built)|ERROR:)`)
	reTreeGlyph     = regexp.MustCompile(`[├└]──|│  `)
	reLSRow         = regexp.MustCompile(`^[-dlbcps][rwx-]{9}`)
	reLSTotal       = regexp.MustCompile(`(?m)^total \d+$`)
	reDigitsOnly    = regexp.MustCompile(`^\d+$`)
	reWindowsDrive  = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	reNumberedLine  = regexp.MustCompile(`^\s*\d+\|`) // READ_NUMBERED_LINE_RE
	reSearchListHdr = regexp.MustCompile(`^Result of search in '[^']*' \(total (\d+) files?\):`)
)

// AutoDetectFilter mirrors autoDetectFilter: it peeks at the first
// DetectWindow characters and returns the filter to apply (nil = none).
func AutoDetectFilter(text string) (FilterFunc, string) {
	head := headOf(text)

	if reGitLog.MatchString(head) {
		return GitLog, FilterGitLog
	}
	if reGitDiff.MatchString(head) || reGitDiffHunk.MatchString(head) {
		return GitDiff, FilterGitDiff
	}
	if reGitStatus.MatchString(head) {
		return GitStatus, FilterGitStatus
	}

	// Build output BEFORE the porcelain check: prevents cargo
	// "Compiling" output being misdetected as git-status.
	if reBuildOutput.MatchString(head) {
		return BuildOutput, FilterBuildOutput
	}

	if isMostlyPorcelain(head) {
		return GitStatus, FilterGitStatus
	}

	lines := strings.Split(head, "\n")
	var nonEmpty []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			nonEmpty = append(nonEmpty, l)
		}
	}

	// Grep: first 5 non-empty lines, ANY matches "file:number:content".
	first5 := nonEmpty
	if len(first5) > 5 {
		first5 = first5[:5]
	}
	for _, l := range first5 {
		if isGrepLine(l) {
			return Grep, FilterGrep
		}
	}

	// Find: ALL non-empty lines path-like (no ':'), >= 3 lines.
	if len(nonEmpty) >= 3 {
		allPaths := true
		for _, l := range nonEmpty {
			if !isPathLike(l) {
				allPaths = false
				break
			}
		}
		if allPaths {
			return Find, FilterFind
		}
	}

	// Tree: box-drawing glyphs typical of `tree`.
	if reTreeGlyph.MatchString(head) {
		return Tree, FilterTree
	}

	// ls -la: "total N" header or >= 3 permission rows.
	if reLSTotal.MatchString(head) || countLSRows(head) >= 3 {
		return LS, FilterLS
	}

	// Cursor Glob search list header.
	if reSearchListHdr.MatchString(head) {
		return SearchList, FilterSearchList
	}

	// Line-numbered dump — only if many lines match "N|content".
	if len(lines) >= TruncateMinLines && isLineNumbered(lines) {
		return ReadNumbered, FilterReadNumbered
	}

	// Fallback: dedup for generic multi-line noise with duplicates.
	if len(nonEmpty) >= 5 {
		return DedupLog, FilterDedupLog
	}

	// Last resort: big unstructured blob — smart truncate.
	if len(strings.Split(text, "\n")) >= TruncateMinLines {
		return SmartTruncate, FilterSmartTruncate
	}

	return nil, ""
}

// isGrepLine mirrors isGrepLine: split on the first two colons, the
// middle segment must be all digits.
func isGrepLine(line string) bool {
	first := strings.Index(line, ":")
	if first == -1 {
		return false
	}
	rest := line[first+1:]
	second := strings.Index(rest, ":")
	if second == -1 {
		return false
	}
	return reDigitsOnly.MatchString(rest[:second])
}

// isPathLike mirrors isPathLike.
func isPathLike(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	// Drive-letter prefix marks a Windows absolute path.
	if reWindowsDrive.MatchString(t) {
		return true
	}
	if strings.Contains(t, ":") {
		return false
	}
	return strings.HasPrefix(t, ".") || strings.HasPrefix(t, "/") || strings.Contains(t, "/")
}

// isMostlyPorcelain mirrors isMostlyPorcelain (>= 60% porcelain rows).
func isMostlyPorcelain(head string) bool {
	var lines []string
	for _, l := range strings.Split(head, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) < 3 {
		return false
	}
	hits := 0
	for _, l := range lines {
		if rePorcelain.MatchString(l) {
			hits++
		}
	}
	return float64(hits)/float64(len(lines)) >= 0.6
}

// isLineNumbered mirrors isLineNumbered (samples the first 100 lines).
func isLineNumbered(lines []string) bool {
	hits, nonEmpty := 0, 0
	sample := lines
	if len(sample) > 100 {
		sample = sample[:100]
	}
	for _, l := range sample {
		if l == "" {
			continue
		}
		nonEmpty++
		if reNumberedLine.MatchString(l) {
			hits++
		}
	}
	if nonEmpty < 5 {
		return false
	}
	return float64(hits)/float64(nonEmpty) >= ReadNumberedMin
}

// countLSRows counts lines starting with an ls permission string.
func countLSRows(head string) int {
	n := 0
	for _, l := range strings.Split(head, "\n") {
		if reLSRow.MatchString(l) {
			n++
		}
	}
	return n
}
