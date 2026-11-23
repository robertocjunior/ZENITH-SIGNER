package handlers

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"zenith-signer/internal/auth"
	"zenith-signer/internal/config"
	"zenith-signer/internal/database"
	"zenith-signer/internal/models"
)

// ---------------------------------------------------------------------------
// Item 4: client IP resolution only trusts configured proxies
// ---------------------------------------------------------------------------

func TestClientIPResolver(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8", "172.17.0.1", "fd00::/8"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name   string
		remote string
		xff    []string
		realIP string
		want   string
	}{
		{"no proxy headers", "203.0.113.7:5555", nil, "", "203.0.113.7"},
		{"untrusted peer spoofing XFF is ignored", "203.0.113.7:5555", []string{"1.2.3.4"}, "", "203.0.113.7"},
		{"untrusted peer spoofing X-Real-IP is ignored", "203.0.113.7:5555", nil, "1.2.3.4", "203.0.113.7"},
		{"trusted proxy forwards client", "10.1.2.3:443", []string{"198.51.100.20"}, "", "198.51.100.20"},
		{"trusted single IP proxy", "172.17.0.1:443", []string{"198.51.100.20"}, "", "198.51.100.20"},
		{"client-supplied left entries are not trusted", "10.1.2.3:443", []string{"6.6.6.6, 198.51.100.20"}, "", "198.51.100.20"},
		{"chain of trusted proxies is skipped", "10.1.2.3:443", []string{"198.51.100.20, 10.9.9.9", "10.8.8.8"}, "", "198.51.100.20"},
		{"all hops trusted returns leftmost", "10.1.2.3:443", []string{"10.5.5.5, 10.6.6.6"}, "", "10.5.5.5"},
		{"malformed hop stops at last verified", "10.1.2.3:443", []string{"198.51.100.20, garbage"}, "", "10.1.2.3"},
		{"XFF entry with port", "10.1.2.3:443", []string{"198.51.100.20:1234"}, "", "198.51.100.20"},
		{"trusted proxy with X-Real-IP", "10.1.2.3:443", nil, "198.51.100.30", "198.51.100.30"},
		{"trusted proxy with invalid X-Real-IP", "10.1.2.3:443", nil, "not-an-ip", "10.1.2.3"},
		{"IPv6 trusted proxy", "[fd00::1]:443", []string{"2001:db8::5"}, "", "2001:db8::5"},
		{"IPv4-mapped IPv6 peer", "[::ffff:10.1.2.3]:443", []string{"198.51.100.20"}, "", "198.51.100.20"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if tc.realIP != "" {
				r.Header.Set("X-Real-IP", tc.realIP)
			}
			if got := resolver.Resolve(r); got != tc.want {
				t.Errorf("Resolve() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientIPResolverNoTrustedProxies(t *testing.T) {
	resolver, err := NewClientIPResolver(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")
	if got := resolver.Resolve(r); got != "127.0.0.1" {
		t.Errorf("headers must be ignored without trusted proxies, got %q", got)
	}
}

func TestNewClientIPResolverRejectsInvalidEntries(t *testing.T) {
	for _, entry := range []string{"10.0.0.0/99", "not-an-ip", "10.0.0"} {
		if _, err := NewClientIPResolver([]string{entry}); err == nil {
			t.Errorf("expected error for invalid entry %q", entry)
		}
	}
}

func TestExtractClientIPWithoutMiddlewareIgnoresHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.10:9999"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := extractClientIP(r); got != "192.0.2.10" {
		t.Errorf("expected TCP peer address, got %q", got)
	}
}

func TestSignatureStoresResolvedClientIP(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
	router, repo := setupTestRouter(t)

	// Behind the trusted proxy: the forwarded client IP is recorded.
	rec := postConfirm(t, router, "Doc-Proxy", "joao@empresa.com", validCSRF("joao@empresa.com"), func(r *http.Request) {
		r.RemoteAddr = "10.0.0.5:443"
		r.Header.Set("X-Forwarded-For", "198.51.100.20")
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	sig, err := repo.GetByDocAndEmail(context.Background(), "Doc-Proxy", "joao@empresa.com")
	if err != nil || sig == nil {
		t.Fatalf("expected stored signature, err=%v", err)
	}
	if sig.IPAddress != "198.51.100.20" {
		t.Errorf("expected forwarded client IP, got %q", sig.IPAddress)
	}

	// Direct (untrusted) connection: a spoofed header must not be recorded.
	rec = postConfirm(t, router, "Doc-Spoof", "joao@empresa.com", validCSRF("joao@empresa.com"), func(r *http.Request) {
		r.RemoteAddr = "203.0.113.9:5555"
		r.Header.Set("X-Forwarded-For", "1.1.1.1")
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	sig, _ = repo.GetByDocAndEmail(context.Background(), "Doc-Spoof", "joao@empresa.com")
	if sig == nil || sig.IPAddress != "203.0.113.9" {
		t.Errorf("expected TCP peer IP to be stored, got %+v", sig)
	}
}

// ---------------------------------------------------------------------------
// Item 2: framing policy (clickjacking)
// ---------------------------------------------------------------------------

func TestParseEmbedOrigins(t *testing.T) {
	got, err := ParseEmbedOrigins([]string{"https://Wiki.Empresa.com.br/", "http://intranet:8080", "https://*.empresa.com.br"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"https://wiki.empresa.com.br", "http://intranet:8080", "https://*.empresa.com.br"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v, want %v", got, want)
	}

	invalid := []string{
		"wiki.empresa.com.br",                       // no scheme
		"ftp://wiki.empresa.com.br",                 // bad scheme
		"https://wiki.empresa.com.br/path",          // path
		"https://wiki.empresa.com.br?x=1",           // query
		"https://user@wiki.empresa.com.br",          // userinfo
		"https://wiki.empresa.com.br; script-src *", // CSP injection
		"https://a.com 'unsafe-inline'",             // CSP injection
		"https://",                                  // no host
	}
	for _, entry := range invalid {
		if _, err := ParseEmbedOrigins([]string{entry}); err == nil {
			t.Errorf("expected error for %q", entry)
		}
	}
}

func TestSecurityHeadersFramingPolicy(t *testing.T) {
	t.Setenv("ALLOWED_EMBED_ORIGINS", "https://wiki.empresa.com.br")
	router, _ := setupTestRouter(t)

	// Logged-in user (can sign): restricted to the configured origins.
	loggedReq := httptest.NewRequest(http.MethodGet, "/assinar?doc=X", nil)
	loggedReq.AddCookie(testSession().SignedCookie("user_email", "maria@empresa.com"))
	embed := httptest.NewRecorder()
	router.ServeHTTP(embed, loggedReq)
	csp := embed.Header().Get("Content-Security-Policy")
	if csp != "frame-ancestors 'self' https://wiki.empresa.com.br" {
		t.Errorf("unexpected CSP on /assinar with session: %q", csp)
	}
	if xfo := embed.Header().Get("X-Frame-Options"); xfo != "" {
		t.Errorf("/assinar must not send X-Frame-Options (it would block allowed embeds), got %q", xfo)
	}

	// Even an invalid/tampered session cookie selects the restrictive policy.
	tampered := httptest.NewRequest(http.MethodGet, "/assinar?doc=X", nil)
	tampered.AddCookie(&http.Cookie{Name: "user_email", Value: "forged"})
	recTampered := httptest.NewRecorder()
	router.ServeHTTP(recTampered, tampered)
	if got := recTampered.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'self' https://wiki.empresa.com.br" {
		t.Errorf("tampered cookie must get restrictive CSP, got %q", got)
	}

	// Anonymous (e.g. Outline's server-side /urls.checkEmbed): embeddable anywhere,
	// since the page only offers a top-level login link.
	anon := httptest.NewRecorder()
	router.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, "/assinar?doc=X", nil))
	if got := anon.Header().Get("Content-Security-Policy"); got != "frame-ancestors *" {
		t.Errorf("anonymous /assinar should allow any ancestor, got %q", got)
	}
	if strings.Contains(anon.Body.String(), "<form") {
		t.Errorf("anonymous widget must not render a signing form")
	}

	for _, path := range []string{"/", "/admin", "/admin/export?format=csv", "/auth/login", "/confirmar", "/healthz"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
			t.Errorf("%s: expected frame-ancestors 'none', got %q", path, got)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: expected X-Frame-Options DENY, got %q", path, got)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: expected nosniff, got %q", path, got)
		}
	}
}

func TestSecurityHeadersDefaultSelfOnly(t *testing.T) {
	router, _ := setupTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/assinar?doc=X", nil)
	req.AddCookie(testSession().SignedCookie("user_email", "maria@empresa.com"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if csp := rec.Header().Get("Content-Security-Policy"); csp != "frame-ancestors 'self'" {
		t.Errorf("expected self-only framing by default, got %q", csp)
	}
}

func TestNewRouterRejectsInvalidSecurityConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := database.Open(config.DatabaseConfig{Path: ":memory:"}, logger)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer db.Close()

	cases := map[string]config.ServerConfig{
		"bad embed origin":  {BaseURL: "http://localhost:8080", AllowedEmbedOrigins: []string{"https://x.com; script-src *"}},
		"bad trusted proxy": {BaseURL: "http://localhost:8080", TrustedProxies: []string{"300.1.1.1"}},
	}
	for name, server := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewRouter(RouterParams{
				Config:     &config.Config{Server: server},
				Repo:       database.NewRepository(db),
				DB:         db,
				AuthSvc:    auth.NewService(config.AuthConfig{}),
				TemplateFS: os.DirFS("../.."),
				Logger:     logger,
				StartTime:  time.Now(),
			})
			if err == nil {
				t.Errorf("expected NewRouter to fail fast on invalid config")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Item 1: CSRF protection on POST /confirmar
// ---------------------------------------------------------------------------

const testSecret = "test-session-secret"

func testSession() *SessionManager {
	return NewSessionManager(testSecret, "http://localhost:8080")
}

func validCSRF(email string) string {
	return testSession().CSRFToken(email)
}

func postConfirm(t *testing.T, router http.Handler, doc, email, token string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("doc", doc)
	if token != "" {
		form.Set(csrfFieldName, token)
	}
	req := httptest.NewRequest(http.MethodPost, "/confirmar", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if email != "" {
		req.AddCookie(testSession().SignedCookie("user_email", email))
		req.AddCookie(testSession().SignedCookie("user_name", "Usuario Teste"))
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestCSRFTokenProperties(t *testing.T) {
	sm := testSession()
	a := sm.CSRFToken("maria@empresa.com")
	if a != sm.CSRFToken("  MARIA@empresa.com ") {
		t.Errorf("token must be stable and case-insensitive on e-mail")
	}
	if a == sm.CSRFToken("joao@empresa.com") {
		t.Errorf("token must differ between users")
	}
	if a == NewSessionManager("other-secret", "").CSRFToken("maria@empresa.com") {
		t.Errorf("token must depend on the server secret")
	}
	if !sm.ValidCSRFToken("maria@empresa.com", a) {
		t.Errorf("expected valid token")
	}
	if sm.ValidCSRFToken("", a) || sm.ValidCSRFToken("maria@empresa.com", "") {
		t.Errorf("empty session or token must be rejected")
	}
	// A cookie signature must never be usable as a CSRF token.
	cookieSig := strings.SplitN(sm.signValue("maria@empresa.com"), ".", 2)[1]
	if sm.ValidCSRFToken("maria@empresa.com", cookieSig) {
		t.Errorf("cookie signature accepted as CSRF token")
	}
}

func TestConfirmRequiresCSRFToken(t *testing.T) {
	router, repo := setupTestRouter(t)
	ctx := context.Background()
	const email = "maria@empresa.com"

	rejected := map[string]struct {
		token  string
		mutate func(*http.Request)
	}{
		"missing token":           {"", nil},
		"garbage token":           {"deadbeef", nil},
		"token of another user":   {validCSRF("outro@empresa.com"), nil},
		"token from other secret": {NewSessionManager("x", "").CSRFToken(email), nil},
		"cross-site origin":       {validCSRF(email), func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
		"null origin (sandboxed)": {validCSRF(email), func(r *http.Request) { r.Header.Set("Origin", "null") }},
	}
	for name, tc := range rejected {
		t.Run(name, func(t *testing.T) {
			rec := postConfirm(t, router, "Politica-CSRF", email, tc.token, tc.mutate)
			if rec.Code != http.StatusForbidden {
				t.Errorf("expected 403, got %d", rec.Code)
			}
			if sig, _ := repo.GetByDocAndEmail(ctx, "Politica-CSRF", email); sig != nil {
				t.Fatalf("signature must not be recorded on CSRF failure")
			}
		})
	}

	// Valid token, same-origin request -> signature recorded.
	rec := postConfirm(t, router, "Politica-CSRF", email, validCSRF(email), func(r *http.Request) {
		r.Header.Set("Origin", "http://localhost:8080")
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for valid request, got %d: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/assinar?doc=Politica-CSRF" {
		t.Errorf("unexpected redirect: %q", loc)
	}
	if sig, _ := repo.GetByDocAndEmail(ctx, "Politica-CSRF", email); sig == nil {
		t.Fatalf("expected signature to be recorded")
	}

	// Valid token without Origin header (older browsers) is accepted.
	rec = postConfirm(t, router, "Politica-SemOrigin", email, validCSRF(email), nil)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("expected 303 without Origin header, got %d", rec.Code)
	}
}

func TestEmbedRendersCSRFTokenForLoggedUser(t *testing.T) {
	router, _ := setupTestRouter(t)
	const email = "maria@empresa.com"

	req := httptest.NewRequest(http.MethodGet, "/assinar?doc=Politica-RH", nil)
	req.AddCookie(testSession().SignedCookie("user_email", email))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	body := rec.Body.String()
	want := `name="` + csrfFieldName + `" value="` + validCSRF(email) + `"`
	if !strings.Contains(body, want) {
		t.Errorf("expected CSRF hidden input in widget form")
	}

	// Anonymous users do not get a form nor a token.
	anon := httptest.NewRecorder()
	router.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, "/assinar?doc=Politica-RH", nil))
	if strings.Contains(anon.Body.String(), csrfFieldName) {
		t.Errorf("anonymous widget must not render the CSRF field")
	}
}

// ---------------------------------------------------------------------------
// Item 5: document identifier validation and URL escaping
// ---------------------------------------------------------------------------

func TestInvalidDocIdentifiersAreRejected(t *testing.T) {
	router, repo := setupTestRouter(t)
	const email = "maria@empresa.com"

	for _, doc := range []string{"doc\r\nBcc: evil@example.com", "doc\x00", strings.Repeat("a", 201), "doc‮txt"} {
		get := httptest.NewRecorder()
		router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/assinar?doc="+url.QueryEscape(doc), nil))
		if get.Code != http.StatusBadRequest {
			t.Errorf("GET /assinar with %q: expected 400, got %d", doc, get.Code)
		}

		post := postConfirm(t, router, doc, email, validCSRF(email), nil)
		if post.Code != http.StatusBadRequest {
			t.Errorf("POST /confirmar with %q: expected 400, got %d", doc, post.Code)
		}
	}

	list, err := repo.List(context.Background(), models.FilterCriteria{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("no signature should be recorded for invalid docs, got %d", len(list))
	}
}

func TestDocWithSpecialCharsIsEscapedInRedirects(t *testing.T) {
	router, _ := setupTestRouter(t)
	const email = "maria@empresa.com"
	const doc = "Política & Férias #2"

	// Unauthenticated POST -> login URL keeps doc intact (no parameter smuggling via '&').
	anon := postConfirm(t, router, doc, "", "", nil)
	if anon.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", anon.Code)
	}
	loginURL, err := url.Parse(anon.Header().Get("Location"))
	if err != nil {
		t.Fatalf("invalid login redirect: %v", err)
	}
	if loginURL.Path != "/auth/login" || loginURL.Query().Get("doc") != doc {
		t.Errorf("login redirect lost doc: %q", anon.Header().Get("Location"))
	}
	ret, _ := url.Parse(loginURL.Query().Get("return"))
	if ret == nil || ret.Path != "/assinar" || ret.Query().Get("doc") != doc {
		t.Errorf("return URL lost doc: %q", loginURL.Query().Get("return"))
	}

	// Authenticated POST -> redirect back to the widget with the same doc.
	rec := postConfirm(t, router, doc, email, validCSRF(email), nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	back, _ := url.Parse(rec.Header().Get("Location"))
	if back == nil || back.Query().Get("doc") != doc {
		t.Errorf("widget redirect lost doc: %q", rec.Header().Get("Location"))
	}
}

// TestOutlineEmbedCheckAcceptsWidget mirrors Outline's server-side embeddability
// check (server/utils/embeds.ts isBlockedByCSP / isBlockedByXFrameOptions) so a
// regression that breaks creating embeds in Outline fails the build.
func TestOutlineEmbedCheckAcceptsWidget(t *testing.T) {
	t.Setenv("ALLOWED_EMBED_ORIGINS", "https://wiki.empresa.com.br")
	router, _ := setupTestRouter(t)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assinar?doc=Politica-RH", nil))

	if rec.Code >= 400 {
		t.Fatalf("Outline treats HTTP >= 400 as not embeddable, got %d", rec.Code)
	}
	if xfo := strings.ToUpper(rec.Header().Get("X-Frame-Options")); xfo == "DENY" || xfo == "SAMEORIGIN" || strings.HasPrefix(xfo, "ALLOW-FROM") {
		t.Fatalf("X-Frame-Options %q blocks Outline embeds", xfo)
	}
	if coep := rec.Header().Get("Cross-Origin-Embedder-Policy"); coep != "" && coep != "unsafe-none" {
		t.Fatalf("COEP %q blocks Outline embeds", coep)
	}
	if outlineBlockedByCSP(rec.Header().Get("Content-Security-Policy")) {
		t.Fatalf("CSP %q is rejected by Outline's embed check", rec.Header().Get("Content-Security-Policy"))
	}
}

// outlineBlockedByCSP is a Go port of Outline's isBlockedByCSP.
func outlineBlockedByCSP(value string) bool {
	if value == "" {
		return false
	}
	for _, policy := range strings.Split(value, ",") {
		var sources []string
		found := false
		for _, d := range strings.Split(policy, ";") {
			parts := strings.Fields(strings.TrimSpace(d))
			if len(parts) > 0 && strings.EqualFold(parts[0], "frame-ancestors") {
				sources, found = parts[1:], true
				break
			}
		}
		if !found {
			continue
		}
		if len(sources) == 1 && (sources[0] == "'none'" || sources[0] == "'self'") {
			return true
		}
		hasStar := false
		onlyKeywords := true
		for _, s := range sources {
			if s == "*" {
				hasStar = true
			}
			if s != "'self'" && s != "'none'" {
				onlyKeywords = false
			}
		}
		if hasStar {
			continue
		}
		if len(sources) > 0 && !onlyKeywords {
			return true
		}
	}
	return false
}

func TestOutlineBlockedByCSPPort(t *testing.T) {
	cases := map[string]bool{
		"":                                   false,
		"frame-ancestors *":                  false,
		"frame-ancestors 'none'":             true,
		"frame-ancestors 'self'":             true,
		"frame-ancestors 'self' https://a.b": true,
		"default-src 'self'":                 false,
	}
	for csp, want := range cases {
		if got := outlineBlockedByCSP(csp); got != want {
			t.Errorf("outlineBlockedByCSP(%q) = %v, want %v", csp, got, want)
		}
	}
}
