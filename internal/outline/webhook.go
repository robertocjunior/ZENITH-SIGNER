package outline

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader is the header Outline uses to sign webhook deliveries.
const SignatureHeader = "Outline-Signature"

var (
	ErrMissingSignature = errors.New("missing webhook signature")
	ErrBadSignature     = errors.New("invalid webhook signature")
	ErrStaleSignature   = errors.New("webhook signature timestamp outside tolerance")
)

// VerifySignature validates an Outline-Signature header ("t=<ms>,s=<hex>"),
// where s = HMAC-SHA256(secret, "<t>.<raw body>"). Deliveries whose timestamp
// is further than tolerance from now are rejected to limit replays.
func VerifySignature(header string, body []byte, secret string, now time.Time, tolerance time.Duration) error {
	if strings.TrimSpace(header) == "" {
		return ErrMissingSignature
	}
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "s":
			sig = v
		}
	}
	if ts == "" || sig == "" {
		return ErrBadSignature
	}

	ms, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrBadSignature
	}
	if tolerance > 0 {
		age := now.Sub(time.UnixMilli(ms))
		if age > tolerance || age < -tolerance {
			return ErrStaleSignature
		}
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := mac.Sum(nil)

	provided, err := hex.DecodeString(sig)
	if err != nil || !hmac.Equal(provided, expected) {
		return ErrBadSignature
	}
	return nil
}

// WebhookEvent is the envelope Outline sends to webhook subscribers.
type WebhookEvent struct {
	ID      string `json:"id"`
	Event   string `json:"event"`
	Payload struct {
		ID    string          `json:"id"`
		Model json.RawMessage `json:"model"`
	} `json:"payload"`
}

// DocumentID extracts the affected document id from a document or revision event.
func (e *WebhookEvent) DocumentID() string {
	var m struct {
		ID         string `json:"id"`
		DocumentID string `json:"documentId"`
	}
	_ = json.Unmarshal(e.Payload.Model, &m)
	if strings.HasPrefix(e.Event, "revisions.") {
		if m.DocumentID != "" {
			return m.DocumentID
		}
		return ""
	}
	if m.ID != "" {
		return m.ID
	}
	return e.Payload.ID
}

// IsContentEvent reports whether the event may change a document's content or title.
func (e *WebhookEvent) IsContentEvent() bool {
	switch e.Event {
	case "documents.update", "documents.update.delayed", "documents.update.debounced",
		"documents.publish", "documents.title_change", "documents.restore", "documents.unarchive",
		"revisions.create":
		return true
	}
	return false
}
