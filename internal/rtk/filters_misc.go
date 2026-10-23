package rtk

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Port of filters/grep.js — groups "file:lineno:content" lines per file
// (sorted), capped at GrepPerFileMax matches per file.
func Grep(input string) string {
	byFile := map[string][][2]string{}
	var order []string
	total := 0

	for _, line := range strings.Split(input, "\n") {
		first := strings.Index(line, ":")
		if first == -1 {
			continue
		}
		rest := line[first+1:]
		second := strings.Index(rest, ":")
		if second == -1 {
			continue
		}
		file := line[:first]
		lineNumStr := rest[:second]
		content := rest[second+1:]
		if !reDigitsOnly.MatchString(lineNumStr) {
			continue
		}
		total++
		if _, ok := byFile[file]; !ok {
			order = append(order, file)
		}
		byFile[file] = append(byFile[file], [2]string{lineNumStr, content})
	}

	if total == 0 {
		return input
	}

	files := append([]string(nil), order...)
	sort.Strings(files)
	var out strings.Builder
	fmt.Fprintf(&out, "%d matches in %dF:\n\n", total, len(files))
	for _, file := range files {
		matches := byFile[file]
		fmt.Fprintf(&out, "[file] %s (%d):\n", file, len(matches))
		show := matches
		if len(show) > GrepPerFileMax {
			show = show[:GrepPerFileMax]
		}
		for _, m := range show {
			fmt.Fprintf(&out, "  %s: %s\n", padStart(m[0], 4), strings.TrimSpace(m[1]))
		}
		if len(matches) > GrepPerFileMax {
			fmt.Fprintf(&out, "  +%d\n", len(matches)-GrepPerFileMax)
		}
		out.WriteString("\n")
	}
	return out.String()
}

// padStart mirrors JS String.padStart with spaces.
func padStart(s string, width int) string {
	for jsLen(s) < width {
		s = " " + s
	}
	return s
}

// groupByDir is the shared find/search-list grouping: parent dir → basenames,
// preserving input order inside each dir.
func groupByDir(paths []string, windowsSeps bool) (map[string][]string, []string) {
	byDir := map[string][]string{}
	var order []string
	for _, path := range paths {
		lastSep := strings.LastIndex(path, "/")
		if windowsSeps {
			if bs := strings.LastIndex(path, "\\"); bs > lastSep {
				lastSep = bs
			}
		}
		var dir, basename string
		if lastSep == -1 {
			dir, basename = ".", path
		} else {
			dir = path[:lastSep]
			if dir == "" {
				dir = "/"
			}
			basename = path[lastSep+1:]
		}
		if _, ok := byDir[dir]; !ok {
			order = append(order, dir)
		}
		byDir[dir] = append(byDir[dir], basename)
	}
	return byDir, order
}

// Port of filters/find.js — groups file paths by parent dir (sorted),
// capped per-dir and in total dirs.
func Find(input string) string {
	var lines []string
	for _, l := range strings.Split(input, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return input
	}

	byDir, order := groupByDir(lines, true)
	dirs := append([]string(nil), order...)
	sort.Strings(dirs)

	var out strings.Builder
	fmt.Fprintf(&out, "%d files in %d dirs:\n\n", len(lines), len(dirs))
	showDirs := dirs
	if len(showDirs) > FindTotalDirMax {
		showDirs = showDirs[:FindTotalDirMax]
	}
	for _, dir := range showDirs {
		files := byDir[dir]
		dirLabel := strings.ReplaceAll(dir, "\\", "/")
		fmt.Fprintf(&out, "%s/  (%d)\n", dirLabel, len(files))
		show := files
		if len(show) > FindPerDirMax {
			show = show[:FindPerDirMax]
		}
		for _, f := range show {
			fmt.Fprintf(&out, "  %s\n", f)
		}
		if len(files) > FindPerDirMax {
			fmt.Fprintf(&out, "  +%d\n", len(files)-FindPerDirMax)
		}
	}
	if len(dirs) > FindTotalDirMax {
		fmt.Fprintf(&out, "\n+%d more dirs\n", len(dirs)-FindTotalDirMax)
	}
	return out.String()
}

// Port of filters/dedupLog.js — collapses consecutive duplicate lines and
// repeated blank lines, with a hard line cap.
func DedupLog(input string) string {
	lines := strings.Split(input, "\n")
	var out []string
	var prev *string
	runCount := 0
	blankStreak := 0

	flushRun := func() {
		if prev != nil && runCount > 1 {
			out = append(out, fmt.Sprintf("  ... (%d duplicate lines)", runCount-1))
		}
	}

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			if blankStreak < 1 {
				out = append(out, line)
			}
			blankStreak++
			flushRun()
			prev = nil
			runCount = 0
			continue
		}
		blankStreak = 0
		if prev != nil && line == *prev {
			runCount++
			continue
		}
		flushRun()
		out = append(out, line)
		l := line
		prev = &l
		runCount = 1
		if len(out) >= DedupLineMax {
			out = append(out, fmt.Sprintf("... (truncated at %d lines)", DedupLineMax))
			return strings.Join(out, "\n")
		}
	}
	flushRun()
	return strings.Join(out, "\n")
}

// lsNoiseDirs mirrors LS_NOISE_DIRS in constants.js.
var lsNoiseDirs = map[string]bool{
	"node_modules": true, ".git": true, "target": true, "__pycache__": true,
	".next": true, "dist": true, "build": true, ".cache": true, ".turbo": true,
	".vercel": true, ".pytest_cache": true, ".mypy_cache": true, ".tox": true,
	".venv": true, "venv": true, "env": true, "coverage": true,
	".nyc_output": true, ".DS_Store": true, "Thumbs.db": true,
	".idea": true, ".vscode": true, ".vs": true, "*.egg-info": true, ".eggs": true,
}

var reLSDate = regexp.MustCompile(`\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+(\d{4}|\d{2}:\d{2})\s+`)

type lsEntry struct {
	fileType byte
	size     int64
	name     string
}

// parseLsLine mirrors parseLsLine in filters/ls.js.
func parseLsLine(line string) *lsEntry {
	loc := reLSDate.FindStringIndex(line)
	if loc == nil {
		return nil
	}
	name := line[loc[1]:]
	beforeParts := strings.Fields(line[:loc[0]])
	if len(beforeParts) < 4 {
		return nil
	}
	entry := &lsEntry{fileType: beforeParts[0][0], name: name}
	// size = rightmost parseable integer before the date.
	for i := len(beforeParts) - 1; i >= 0; i-- {
		if n, err := strconv.ParseInt(beforeParts[i], 10, 64); err == nil && strconv.FormatInt(n, 10) == beforeParts[i] {
			entry.size = n
			break
		}
	}
	return entry
}

func humanSize(bytes int64) string {
	if bytes >= 1_048_576 {
		return fmt.Sprintf("%.1fM", float64(bytes)/1_048_576)
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%.1fK", float64(bytes)/1024)
	}
	return fmt.Sprintf("%dB", bytes)
}

// Port of filters/ls.js — compact `ls -la` output: dirs first, then
// "name  size" rows, plus an extension summary.
func LS(input string) string {
	var dirs []string
	type fileRow struct{ name, size string }
	var files []fileRow
	type extCount struct {
		ext string
		n   int
	}
	var extOrder []extCount
	extIdx := map[string]int{}

	for _, line := range strings.Split(input, "\n") {
		if strings.HasPrefix(line, "total ") || line == "" {
			continue
		}
		parsed := parseLsLine(line)
		if parsed == nil || parsed.name == "." || parsed.name == ".." {
			continue
		}
		if lsNoiseDirs[parsed.name] {
			continue
		}
		switch parsed.fileType {
		case 'd':
			dirs = append(dirs, parsed.name)
		case '-', 'l':
			ext := "no ext"
			if dot := strings.LastIndex(parsed.name, "."); dot > 0 {
				ext = parsed.name[dot:]
			}
			if i, ok := extIdx[ext]; ok {
				extOrder[i].n++
			} else {
				extIdx[ext] = len(extOrder)
				extOrder = append(extOrder, extCount{ext, 1})
			}
			files = append(files, fileRow{parsed.name, humanSize(parsed.size)})
		}
	}

	if len(dirs) == 0 && len(files) == 0 {
		return input
	}

	var out strings.Builder
	for _, d := range dirs {
		fmt.Fprintf(&out, "%s/\n", d)
	}
	for _, f := range files {
		fmt.Fprintf(&out, "%s  %s\n", f.name, f.size)
	}
	summary := fmt.Sprintf("\nSummary: %d files, %d dirs", len(files), len(dirs))
	if len(extOrder) > 0 {
		sorted := append([]extCount(nil), extOrder...)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].n > sorted[j].n })
		var parts []string
		for _, e := range sorted {
			if len(parts) >= LSExtSummaryTop {
				break
			}
			parts = append(parts, fmt.Sprintf("%d %s", e.n, e.ext))
		}
		summary += " (" + strings.Join(parts, ", ")
		if len(sorted) > LSExtSummaryTop {
			summary += fmt.Sprintf(", +%d more", len(sorted)-LSExtSummaryTop)
		}
		summary += ")"
	}
	return out.String() + summary
}

// Port of filters/tree.js — drops the "N directories, M files" summary
// and leading/trailing blanks; caps long trees.
func Tree(input string) string {
	lines := strings.Split(input, "\n")
	if len(lines) == 0 {
		return input
	}
	var filtered []string
	for _, line := range lines {
		if strings.Contains(line, "director") && strings.Contains(line, "file") {
			continue
		}
		if strings.TrimSpace(line) == "" && len(filtered) == 0 {
			continue
		}
		filtered = append(filtered, line)
	}
	for len(filtered) > 0 && strings.TrimSpace(filtered[len(filtered)-1]) == "" {
		filtered = filtered[:len(filtered)-1]
	}
	if len(filtered) > TreeMaxLines {
		cut := len(filtered) - TreeMaxLines
		return strings.Join(filtered[:TreeMaxLines], "\n") + fmt.Sprintf("\n... +%d more lines", cut)
	}
	return strings.Join(filtered, "\n")
}

// truncateHeadTail is the shared smart-truncate body (filters/smartTruncate.js
// and filters/readNumbered.js differ only in the marker text).
func truncateHeadTail(input, marker string) string {
	lines := strings.Split(input, "\n")
	if len(lines) < TruncateMinLines {
		return input
	}
	head := lines[:TruncateHead]
	tail := lines[len(lines)-TruncateTail:]
	cut := len(lines) - len(head) - len(tail)
	out := append(append([]string{}, head...), fmt.Sprintf(marker, cut))
	out = append(out, tail...)
	return strings.Join(out, "\n")
}

// SmartTruncate ports filters/smartTruncate.js.
func SmartTruncate(input string) string {
	return truncateHeadTail(input, "... +%d lines truncated")
}

// ReadNumbered ports filters/readNumbered.js (numbered file dumps keep
// head+tail, like smart-truncate, with a different marker).
func ReadNumbered(input string) string {
	return truncateHeadTail(input, "... +%d lines truncated (file continues)")
}

// Port of filters/searchList.js — compacts Cursor Glob output
// ("Result of search in '...' (total N files):" + "- path" lines),
// grouping by parent dir like Find.
func SearchList(input string) string {
	lines := strings.Split(input, "\n")
	if len(lines) == 0 {
		return input
	}
	header := lines[0]
	var paths []string
	for _, raw := range lines[1:] {
		t := strings.TrimSpace(raw)
		if strings.HasPrefix(t, "- ") {
			paths = append(paths, t[2:])
		}
	}
	if len(paths) == 0 {
		return input
	}

	byDir, order := groupByDir(paths, false)
	dirs := append([]string(nil), order...)
	sort.Strings(dirs)

	var out strings.Builder
	fmt.Fprintf(&out, "%s\n%d files in %d dirs:\n\n", header, len(paths), len(dirs))
	showDirs := dirs
	if len(showDirs) > SearchTotalDirs {
		showDirs = showDirs[:SearchTotalDirs]
	}
	for _, dir := range showDirs {
		names := byDir[dir]
		fmt.Fprintf(&out, "%s/ (%d):\n", dir, len(names))
		show := names
		if len(show) > SearchPerDirMax {
			show = show[:SearchPerDirMax]
		}
		for _, n := range show {
			fmt.Fprintf(&out, "  %s\n", n)
		}
		if len(names) > SearchPerDirMax {
			fmt.Fprintf(&out, "  +%d\n", len(names)-SearchPerDirMax)
		}
		out.WriteString("\n")
	}
	if len(dirs) > SearchTotalDirs {
		fmt.Fprintf(&out, "+%d more dirs\n", len(dirs)-SearchTotalDirs)
	}
	return strings.TrimRight(out.String(), "\n")
}
