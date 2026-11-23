package models

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxDocIDLength is the maximum number of characters accepted in a document identifier.
const MaxDocIDLength = 200

var (
	ErrDocIDEmpty   = errors.New("document identifier cannot be empty")
	ErrDocIDTooLong = errors.New("document identifier is too long")
	ErrDocIDInvalid = errors.New("document identifier contains invalid characters")
)

// NormalizeDocID trims and validates a document identifier.
//
// Identifiers end up in e-mail headers, URLs, logs and exports, so control
// characters (CR, LF, TAB, NUL...) and invisible format characters (such as
// bidirectional overrides) are rejected to prevent header injection and
// visual spoofing. Letters with accents, spaces and punctuation are allowed.
func NormalizeDocID(raw string) (string, error) {
	doc := strings.TrimSpace(raw)
	if doc == "" {
		return "", ErrDocIDEmpty
	}
	if !utf8.ValidString(doc) {
		return "", ErrDocIDInvalid
	}
	if utf8.RuneCountInString(doc) > MaxDocIDLength {
		return "", ErrDocIDTooLong
	}
	for _, r := range doc {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return "", ErrDocIDInvalid
		}
	}
	return doc, nil
}
