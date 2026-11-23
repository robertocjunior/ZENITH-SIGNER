package outline

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sign(secret, body string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", ts, body)
	return fmt.Sprintf("t=%d,s=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func TestVerifySignature(t *testing.T) {
	now := time.Now()
	ts := now.UnixMilli()
	body := `{"event":"documents.update"}`
	secret := "ol_whs_test"

	if err := VerifySignature(sign(secret, body, ts), []byte(body), secret, now, 5*time.Minute); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	cases := map[string]struct {
		header string
		body   string
		want   error
	}{
		"missing":       {"", body, ErrMissingSignature},
		"malformed":     {"garbage", body, ErrBadSignature},
		"wrong secret":  {sign("other", body, ts), body, ErrBadSignature},
		"tampered body": {sign(secret, body, ts), `{"event":"documents.delete"}`, ErrBadSignature},
		"stale":         {sign(secret, body, now.Add(-10*time.Minute).UnixMilli()), body, ErrStaleSignature},
		"future":        {sign(secret, body, now.Add(10*time.Minute).UnixMilli()), body, ErrStaleSignature},
		"not hex":       {fmt.Sprintf("t=%d,s=zz", ts), body, ErrBadSignature},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := VerifySignature(tc.header, []byte(tc.body), secret, now, 5*time.Minute)
			if !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestWebhookEventDocumentID(t *testing.T) {
	var doc WebhookEvent
	_ = json.Unmarshal([]byte(`{"event":"documents.update","payload":{"id":"d1","model":{"id":"d1","title":"X"}}}`), &doc)
	if doc.DocumentID() != "d1" || !doc.IsContentEvent() {
		t.Errorf("document event: id=%q content=%v", doc.DocumentID(), doc.IsContentEvent())
	}
	var rev WebhookEvent
	_ = json.Unmarshal([]byte(`{"event":"revisions.create","payload":{"id":"r1","model":{"id":"r1","documentId":"d2"}}}`), &rev)
	if rev.DocumentID() != "d2" || !rev.IsContentEvent() {
		t.Errorf("revision event must map to its document, got %q", rev.DocumentID())
	}
	var other WebhookEvent
	_ = json.Unmarshal([]byte(`{"event":"users.signin","payload":{"id":"u1","model":{"id":"u1"}}}`), &other)
	if other.IsContentEvent() {
		t.Errorf("users.signin must not trigger a sync")
	}
}

func TestNormalizeContent(t *testing.T) {
	widget := "https://assinador.empresa.com/assinar?doc="
	a := "[https://assinador.empresa.com/assinar?doc=POL%5F1](https://assinador.empresa.com/assinar?doc=POL%5F1)\n\n# Política\r\n\r\nTexto   \n\n\n\nFim\n"
	b := "# Política\n\nTexto\n\nFim"
	if NormalizeContent(a, widget) != b {
		t.Errorf("unexpected normalisation:\n%q\nwant\n%q", NormalizeContent(a, widget), b)
	}
	if ContentHash(NormalizeContent(a, widget)) != ContentHash(b) {
		t.Errorf("embed line / whitespace must not change the hash")
	}
	if ContentHash(NormalizeContent(b+" alterado", widget)) == ContentHash(b) {
		t.Errorf("real text change must change the hash")
	}
}

func TestEmbedMarkdownAndContainsEmbed(t *testing.T) {
	u := "https://assinador.empresa.com/assinar?doc=POL_1"
	if got := EmbedMarkdown(u); got != "[https://assinador.empresa.com/assinar?doc=POL%5F1](https://assinador.empresa.com/assinar?doc=POL%5F1)\n\n" {
		t.Errorf("unexpected embed markdown: %q", got)
	}
	withEmbed := json.RawMessage(`{"type":"doc","content":[{"type":"embed","attrs":{"href":"https://assinador.empresa.com/assinar?doc=POL%5F1"}}]}`)
	withLink := json.RawMessage(`{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","marks":[{"type":"link","attrs":{"href":"` + u + `"}}]}]}]}`)
	if !ContainsEmbed(withEmbed, u) {
		t.Errorf("embed node not detected")
	}
	if ContainsEmbed(withLink, u) {
		t.Errorf("plain link must not count as embed")
	}
	if ContainsEmbed(nil, u) || ContainsEmbed(json.RawMessage(`not json`), u) {
		t.Errorf("empty/invalid data must not count as embed")
	}
}

func TestClientRequests(t *testing.T) {
	var gotPath, gotAuth, gotVersion string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotVersion = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("x-api-version")
		raw, _ := io.ReadAll(r.Body)
		gotBody = nil
		_ = json.Unmarshal(raw, &gotBody)
		switch r.URL.Path {
		case "/api/documents.info":
			if gotBody["id"] == "missing" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"ok":false,"error":"not_found","message":"Resource not found"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"data":{"id":"uuid-1","urlId":"AbC123","title":"Política","text":"# Olá","url":"/doc/politica-AbC123","revision":4}}`))
		case "/api/documents.search_titles":
			_, _ = w.Write([]byte(`{"ok":true,"data":[{"id":"uuid-1","urlId":"AbC123","title":"Política"}]}`))
		case "/api/documents.update":
			_, _ = w.Write([]byte(`{"ok":true,"data":{"id":"uuid-1","revision":5}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"ok":false,"error":"boom","message":"internal"}`))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL+"/", "ol_api_secret", time.Second)
	ctx := context.Background()

	d, err := c.Info(ctx, "AbC123")
	if err != nil || d.ID != "uuid-1" || d.Text != "# Olá" || d.Revision != 4 {
		t.Fatalf("Info: %+v %v", d, err)
	}
	if gotPath != "/api/documents.info" || gotAuth != "Bearer ol_api_secret" || gotVersion != "" || gotBody["id"] != "AbC123" {
		t.Errorf("Info request: path=%s auth=%s version=%q body=%v", gotPath, gotAuth, gotVersion, gotBody)
	}

	if _, err := c.InfoStructured(ctx, "AbC123"); err != nil || gotVersion != "3" {
		t.Errorf("InfoStructured must send x-api-version: 3 (got %q, err %v)", gotVersion, err)
	}

	if docs, err := c.SearchTitles(ctx, "pol", 0); err != nil || len(docs) != 1 || gotBody["query"] != "pol" {
		t.Errorf("SearchTitles: %v %v body=%v", docs, err, gotBody)
	}

	if _, err := c.Prepend(ctx, "uuid-1", "[x](x)\n\n"); err != nil {
		t.Fatalf("Prepend: %v", err)
	}
	if gotBody["editMode"] != "prepend" || gotBody["text"] != "[x](x)\n\n" || gotBody["id"] != "uuid-1" {
		t.Errorf("Prepend body: %v", gotBody)
	}

	if _, err := c.Info(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404 must map to ErrNotFound, got %v", err)
	}

	bad := NewClient(srv.URL, "k", time.Second)
	err = bad.call(ctx, "unknown.method", map[string]string{}, &struct{}{}, 0)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 || !strings.Contains(apiErr.Error(), "boom") {
		t.Errorf("expected APIError 500, got %v", err)
	}
}
