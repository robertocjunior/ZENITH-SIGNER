package models

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeDocID(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{"simple", "POLITICA-SEGURANCA-2026", "POLITICA-SEGURANCA-2026", nil},
		{"trimmed", "  Politica-RH.pdf  ", "Politica-RH.pdf", nil},
		{"accents and spaces", "Política de Férias (v2)", "Política de Férias (v2)", nil},
		{"empty", "   ", "", ErrDocIDEmpty},
		{"crlf header injection", "doc\r\nBcc: atacante@evil.com", "", ErrDocIDInvalid},
		{"lone lf", "doc\nX", "", ErrDocIDInvalid},
		{"tab", "doc\tX", "", ErrDocIDInvalid},
		{"nul byte", "doc\x00X", "", ErrDocIDInvalid},
		{"bidi override", "doc‮fdp.exe", "", ErrDocIDInvalid},
		{"zero width space", "doc​X", "", ErrDocIDInvalid},
		{"invalid utf8", "doc\xff", "", ErrDocIDInvalid},
		{"max length", strings.Repeat("a", MaxDocIDLength), strings.Repeat("a", MaxDocIDLength), nil},
		{"too long", strings.Repeat("a", MaxDocIDLength+1), "", ErrDocIDTooLong},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeDocID(tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NormalizeDocID(%q) error = %v, want %v", tc.in, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("NormalizeDocID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
