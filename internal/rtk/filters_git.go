package rtk

import (
	"fmt"
	"regexp"
	"strings"
)

// Port of filters/gitDiff.js — compacts a unified diff: file headers,
// per-hunk truncation at GitDiffHunkMax lines, +/- counting.
func GitDiff(diff string) string {
	return gitDiff(diff, 500)
}

func gitDiff(diff string, maxLines int) string {
	var result []string
	currentFile := ""
	added, removed := 0, 0
	inHunk := false
	hunkShown, hunkSkipped := 0, 0
	wasTruncated := false

outer:
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git"):
			if hunkSkipped > 0 {
				result = append(result, fmt.Sprintf("  ... (%d lines truncated)", hunkSkipped))
				wasTruncated = true
				hunkSkipped = 0
			}
			if currentFile != "" && (added > 0 || removed > 0) {
				result = append(result, fmt.Sprintf("  +%d -%d", added, removed))
			}
			if idx := strings.Index(line, " b/"); idx >= 0 {
				currentFile = line[idx+len(" b/"):]
			} else {
				currentFile = "unknown"
			}
			result = append(result, "\n"+currentFile)
			added, removed = 0, 0
			inHunk = false
			hunkShown = 0
		case strings.HasPrefix(line, "@@"):
			if hunkSkipped > 0 {
				result = append(result, fmt.Sprintf("  ... (%d lines truncated)", hunkSkipped))
				wasTruncated = true
				hunkSkipped = 0
			}
			inHunk = true
			hunkShown = 0
			result = append(result, "  "+line)
		case inHunk:
			switch {
			case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
				added++
				if hunkShown < GitDiffHunkMax {
					result = append(result, "  "+line)
					hunkShown++
				} else {
					hunkSkipped++
				}
			case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
				removed++
				if hunkShown < GitDiffHunkMax {
					result = append(result, "  "+line)
					hunkShown++
				} else {
					hunkSkipped++
				}
			case hunkShown < GitDiffHunkMax && !strings.HasPrefix(line, "\\"):
				if hunkShown > 0 {
					result = append(result, "  "+line)
					hunkShown++
				}
			}
		}

		if len(result) >= maxLines {
			result = append(result, "\n... (more changes truncated)")
			wasTruncated = true
			break outer
		}
	}

	if hunkSkipped > 0 {
		result = append(result, fmt.Sprintf("  ... (%d lines truncated)", hunkSkipped))
		wasTruncated = true
	}
	if currentFile != "" && (added > 0 || removed > 0) {
		result = append(result, fmt.Sprintf("  +%d -%d", added, removed))
	}
	if wasTruncated {
		result = append(result, "[full diff: rtk git diff --no-compact]")
	}
	return strings.Join(result, "\n")
}

var (
	reStatusBranchLong = regexp.MustCompile(`^On branch (\S+)`)
	reStatusLongForm   = regexp.MustCompile(`^\s*(modified|new file|deleted|renamed|both modified):\s+(.+)$`)
	reStatusPorcelain  = regexp.MustCompile(`^[ MADRCU?!][ MADRCU?!] `)
)

// Port of filters/gitStatus.js — formats `git status` (long or porcelain)
// into branch + Staged/Modified/Untracked/Conflicts summaries.
func GitStatus(input string) string {
	lines := strings.Split(input, "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return "Clean working tree"
	}

	branch := ""
	var stagedFiles, modifiedFiles, untrackedFiles []string
	staged, modified, untracked, conflicts := 0, 0, 0, 0

	for _, raw := range lines {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if m := reStatusBranchLong.FindStringSubmatch(raw); m != nil {
			branch = m[1]
			continue
		}
		if strings.HasPrefix(raw, "##") {
			branch = strings.TrimLeft(raw[2:], " \t")
			continue
		}
		if len(raw) >= 3 && reStatusPorcelain.MatchString(raw) {
			x, y := raw[0], raw[1]
			file := raw[3:]
			if raw[:2] == "??" {
				untracked++
				untrackedFiles = append(untrackedFiles, file)
				continue
			}
			if strings.ContainsRune("MADRC", rune(x)) {
				staged++
				stagedFiles = append(stagedFiles, file)
			} else if x == 'U' {
				conflicts++
			}
			if y == 'M' || y == 'D' {
				modified++
				modifiedFiles = append(modifiedFiles, file)
			}
			continue
		}
		if m := reStatusLongForm.FindStringSubmatch(raw); m != nil {
			kind, path := m[1], strings.TrimSpace(m[2])
			switch kind {
			case "both modified":
				conflicts++
			case "modified", "deleted":
				modified++
				modifiedFiles = append(modifiedFiles, path)
			case "new file", "renamed":
				staged++
				stagedFiles = append(stagedFiles, path)
			}
			continue
		}
		// Bare paths after "Untracked files:" are skipped (safer, as in JS).
	}

	var out strings.Builder
	if branch != "" {
		fmt.Fprintf(&out, "* %s\n", branch)
	}
	writeSection := func(marker string, label string, count int, files []string, max int) {
		if count == 0 {
			return
		}
		fmt.Fprintf(&out, "%s %s: %d files\n", marker, label, count)
		show := files
		if len(show) > max {
			show = show[:max]
		}
		for _, f := range show {
			fmt.Fprintf(&out, "   %s\n", f)
		}
		if len(files) > max {
			fmt.Fprintf(&out, "   ... +%d more\n", len(files)-max)
		}
	}
	writeSection("+", "Staged", staged, stagedFiles, StatusMaxFiles)
	writeSection("~", "Modified", modified, modifiedFiles, StatusMaxFiles)
	writeSection("?", "Untracked", untracked, untrackedFiles, StatusMaxUntrack)
	if conflicts > 0 {
		fmt.Fprintf(&out, "conflicts: %d files\n", conflicts)
	}
	if staged == 0 && modified == 0 && untracked == 0 && conflicts == 0 {
		out.WriteString("clean — nothing to commit\n")
	}
	return strings.TrimRight(out.String(), "\n")
}

var (
	reLogCommitHdr  = regexp.MustCompile(`(?i)^commit [0-9a-f]{7,40}$`)
	reLogCommitDec  = regexp.MustCompile(`(?i)^[*|/\\ ]+commit [0-9a-f]{7,40}`)
	reLogAuthorDate = regexp.MustCompile(`(?i)^[*|/\\ ]*(Author|Date):`)
	reLogSubject    = regexp.MustCompile(`^[*|/\\ ]*    \S`)
	reLogStat       = regexp.MustCompile(`^\d+ file\w* changed`)
	reLogGraphLine  = regexp.MustCompile(`(?i)^[*|/\\ ]+([0-9a-f]{7,40}\s+.+)`)
	reLogOneline    = regexp.MustCompile(`^[0-9a-f]{7,40}\s+`)
	reLogDecoration = regexp.MustCompile(`^[*|/\\ ]+$`)
)

// Port of filters/gitLog.js — keeps commit headers, Author/Date, the
// subject and stat summaries; drops bodies and embedded diffs.
func GitLog(text string) string {
	return gitLog(text, GitLogMaxLines)
}

func gitLog(text string, maxLines int) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	var out []string
	skipped := 0
	inCommit := false
	subjectSeen := false

	pushLine := func(l string) bool {
		if len(out) < maxLines {
			out = append(out, l)
			return true
		}
		skipped++
		return false
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)

		if reLogCommitHdr.MatchString(trimmed) || reLogCommitDec.MatchString(trimmed) {
			inCommit = true
			subjectSeen = false
			pushLine(line)
			continue
		}

		if inCommit {
			if reLogAuthorDate.MatchString(trimmed) {
				pushLine(trimmed)
				continue
			}
			if trimmed == "" {
				continue
			}
			if !subjectSeen && reLogSubject.MatchString(line) {
				pushLine("  Subject: " + trimmed)
				subjectSeen = true
				continue
			}
			if reLogStat.MatchString(trimmed) {
				pushLine("  " + trimmed)
				continue
			}
			if strings.HasPrefix(trimmed, "diff --git ") {
				pushLine("  ... diff body omitted")
				continue
			}
			continue // everything else in the commit body is dropped
		}

		// Outside a commit block (--oneline / --graph modes).
		if m := reLogGraphLine.FindStringSubmatch(trimmed); m != nil {
			pushLine(m[1])
			continue
		}
		if reLogOneline.MatchString(trimmed) {
			pushLine(trimmed)
			continue
		}
		if reLogDecoration.MatchString(trimmed) && strings.ContainsAny(trimmed, "*|/\\") {
			continue
		}
		pushLine(trimmed)
	}

	if skipped > 0 {
		out = append(out, fmt.Sprintf("... (%d more lines)", skipped))
	}
	result := strings.Join(out, "\n")
	if result == "" && text != "" {
		return text
	}
	if jsLen(result) > jsLen(text) {
		return text
	}
	return result
}
