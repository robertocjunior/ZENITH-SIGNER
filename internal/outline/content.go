package outline

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// NormalizeContent prepares document markdown for fingerprinting:
//   - unifies line endings and strips trailing spaces;
//   - removes lines that reference the signer widget (the embed itself), so
//     inserting or moving the embed does not count as a content change;
//   - collapses runs of blank lines and trims the result.
func NormalizeContent(text string, widgetMarkers ...string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	var out []string
	blank := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, " \t")
		if isWidgetLine(line, widgetMarkers) {
			continue
		}
		if line == "" {
			blank++
			if blank > 1 {
				continue
			}
		} else {
			blank = 0
		}
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func isWidgetLine(line string, markers []string) bool {
	l := unescapeHref(line)
	for _, m := range markers {
		if m != "" && strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// ContentHash returns the hex SHA-256 of normalised content.
func ContentHash(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// EmbedMarkdown returns the markdown Outline uses to serialise an embed of
// widgetURL: a link whose text is the URL itself, on its own paragraph
// (underscores escaped as Outline does).
func EmbedMarkdown(widgetURL string) string {
	href := strings.ReplaceAll(widgetURL, "_", "%5F")
	return "[" + href + "](" + href + ")\n\n"
}
