package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"zenith-signer/internal/models"
	"zenith-signer/internal/outline"
	"zenith-signer/internal/service"
)

// stubOutline is a minimal in-memory Outline for handler tests.
type stubOutline struct {
	mu   sync.Mutex
	docs map[string]*outline.Document
}

func newStubOutline() *stubOutline { return &stubOutline{docs: map[string]*outline.Document{}} }

func (s *stubOutline) set(id, urlID, title, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[id] = &outline.Document{ID: id, URLID: urlID, Title: title, Text: text, URL: "/doc/x-" + urlID}
}

func (s *stubOutline) get(id string) (*outline.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.docs {
		if d.ID == id || d.URLID == id {
			cp := *d
			return &cp, nil
		}
	}
	return nil, outline.ErrNotFound
}

func (s *stubOutline) Info(_ context.Context, id string) (*outline.Document, error) { return s.get(id) }
func (s *stubOutline) InfoStructured(_ context.Context, id string) (*outline.Document, error) {
	d, err := s.get(id)
	if err != nil {
		return nil, err
	}
	href := ""
	if strings.HasPrefix(d.Text, "[") {
		href = d.Text[1:strings.Index(d.Text, "]")]
	}
	d.Data, _ = json.Marshal(map[string]any{"type": "doc", "content": []any{map[string]any{"type": "embed", "attrs": map[string]any{"href": href}}}})
	return d, nil
}
func (s *stubOutline) SearchTitles(_ context.Context, q string, _ int) ([]outline.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []outline.Document
	for _, d := range s.docs {
		if strings.Contains(strings.ToLower(d.Title), strings.ToLower(q)) {
			out = append(out, *d)
		}
	}
	return out, nil
}
func (s *stubOutline) Prepend(_ context.Context, id, md string) (*outline.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.docs {
		if d.ID == id {
			d.Text = md + d.Text
			cp := *d
			return &cp, nil
		}
	}
	return nil, outline.ErrNotFound
}

const adminEmail = "admin@empresa.com"

func adminPost(t *testing.T, router http.Handler, path string, form url.Values, withCSRF bool) *httptest.ResponseRecorder {
	t.Helper()
	if withCSRF {
		form.Set(csrfFieldName, validCSRF(adminEmail))
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(testSession().SignedCookie("user_email", adminEmail))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func adminGet(router http.Handler, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(testSession().SignedCookie("user_email", adminEmail))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func flashFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == flashCookie {
			return c
		}
	}
	return nil
}

func TestAdminDocumentsAccessControl(t *testing.T) {
	env := newTestEnv(t, newStubOutline())

	// Anonymous -> login redirect; non-admin -> 403.
	anon := httptest.NewRecorder()
	env.router.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, "/admin/documentos", nil))
	if anon.Code != http.StatusSeeOther {
		t.Errorf("anonymous: expected 303, got %d", anon.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/documentos", nil)
	req.AddCookie(testSession().SignedCookie("user_email", "user@empresa.com"))
	user := httptest.NewRecorder()
	env.router.ServeHTTP(user, req)
	if user.Code != http.StatusForbidden {
		t.Errorf("non-admin: expected 403, got %d", user.Code)
	}

	// Every admin POST requires the CSRF token.
	for _, path := range []string{"/admin/documentos/cadastrar", "/admin/documentos/decidir", "/admin/documentos/sincronizar", "/admin/documentos/status"} {
		rec := adminPost(t, env.router, path, url.Values{"outline_ref": {"u"}}, false)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s without CSRF: expected 403, got %d", path, rec.Code)
		}
		get := adminGet(env.router, path)
		if get.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s via GET: expected 405, got %d", path, get.Code)
		}
	}

	// Admin pages cannot be framed.
	page := adminGet(env.router, "/admin/documentos")
	if page.Code != http.StatusOK || page.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("admin page: code=%d xfo=%q", page.Code, page.Header().Get("X-Frame-Options"))
	}
}

func TestAdminRegisterDecideAndWidgetFlow(t *testing.T) {
	stub := newStubOutline()
	stub.set("uuid-1", "AbC123", "Política de Férias", "# Política\n\nTexto v1")
	env := newTestEnv(t, stub)
	ctx := context.Background()

	// Search shows the Outline document.
	search := adminGet(env.router, "/admin/documentos?q=f%C3%A9rias")
	if !strings.Contains(search.Body.String(), "Política de Férias") || !strings.Contains(search.Body.String(), `value="uuid-1"`) {
		t.Fatalf("search results missing document")
	}

	// Register it (with embed insertion).
	reg := adminPost(t, env.router, "/admin/documentos/cadastrar", url.Values{"outline_ref": {"uuid-1"}, "insert_embed": {"1"}}, true)
	if reg.Code != http.StatusSeeOther || reg.Header().Get("Location") != "/admin/documentos" {
		t.Fatalf("register: %d %s", reg.Code, reg.Body.String())
	}
	doc, _ := env.docRepo.GetDocumentByKey(ctx, "AbC123")
	if doc == nil || doc.EmbedStatus != models.EmbedInserted {
		t.Fatalf("document not registered with embed: %+v", doc)
	}
	od, _ := stub.get("uuid-1")
	if !strings.HasPrefix(od.Text, "[http://localhost:8080/assinar?doc=AbC123]") {
		t.Errorf("widget not inserted at the top: %q", od.Text)
	}

	// Flash message is shown once on the next page view.
	page := adminGet(env.router, "/admin/documentos", flashFrom(reg))
	if !strings.Contains(page.Body.String(), "cadastrado (versão 1)") || !strings.Contains(page.Body.String(), "Política de Férias") {
		t.Errorf("documents page missing flash or document")
	}

	// Widget shows title and version for a logged user and carries version_id.
	wreq := httptest.NewRequest(http.MethodGet, "/assinar?doc=AbC123", nil)
	wreq.AddCookie(testSession().SignedCookie("user_email", "maria@empresa.com"))
	widget := httptest.NewRecorder()
	env.router.ServeHTTP(widget, wreq)
	body := widget.Body.String()
	if !strings.Contains(body, "Política de Férias") || !strings.Contains(body, "versão 1") ||
		!strings.Contains(body, fmt.Sprintf(`name="version_id" value="%d"`, doc.CurrentVersionID)) {
		t.Fatalf("widget missing title/version: %s", body)
	}

	// Maria signs v1.
	v1 := doc.CurrentVersionID
	form := url.Values{"doc": {"AbC123"}, csrfFieldName: {validCSRF("maria@empresa.com")}, "version_id": {fmt.Sprint(v1)}}
	sreq := httptest.NewRequest(http.MethodPost, "/confirmar", strings.NewReader(form.Encode()))
	sreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sreq.AddCookie(testSession().SignedCookie("user_email", "maria@empresa.com"))
	srec := httptest.NewRecorder()
	env.router.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusSeeOther {
		t.Fatalf("sign v1: %d %s", srec.Code, srec.Body.String())
	}

	// Text changes; admin syncs manually -> pending version shown with decision buttons.
	stub.set("uuid-1", "AbC123", "Política de Férias", "[http://localhost:8080/assinar?doc=AbC123](http://localhost:8080/assinar?doc=AbC123)\n\n# Política\n\nTexto v2 com nova regra")
	syncRec := adminPost(t, env.router, "/admin/documentos/sincronizar", url.Values{"document_id": {fmt.Sprint(doc.ID)}}, true)
	if syncRec.Code != http.StatusSeeOther {
		t.Fatalf("sync: %d", syncRec.Code)
	}
	doc, _ = env.docRepo.GetDocumentByKey(ctx, "AbC123")
	v2 := doc.CurrentVersionID
	if v2 == v1 {
		t.Fatalf("new version not created")
	}
	page = adminGet(env.router, "/admin/documentos")
	if !strings.Contains(page.Body.String(), "aguardando decisão") {
		t.Errorf("pending decision banner missing")
	}

	// Version page shows the diff.
	vpage := adminGet(env.router, fmt.Sprintf("/admin/documentos/versao?id=%d", v2))
	if vpage.Code != http.StatusOK || !strings.Contains(vpage.Body.String(), "Texto v2 com nova regra") || !strings.Contains(vpage.Body.String(), `class="d-del"`) {
		t.Fatalf("version diff page: %d", vpage.Code)
	}

	// A stale widget (v1) is redirected back with the "updated" notice.
	stale := url.Values{"doc": {"AbC123"}, csrfFieldName: {validCSRF("joao@empresa.com")}, "version_id": {fmt.Sprint(v1)}}
	streq := httptest.NewRequest(http.MethodPost, "/confirmar", strings.NewReader(stale.Encode()))
	streq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	streq.AddCookie(testSession().SignedCookie("user_email", "joao@empresa.com"))
	strec := httptest.NewRecorder()
	env.router.ServeHTTP(strec, streq)
	if strec.Code != http.StatusSeeOther || !strings.Contains(strec.Header().Get("Location"), "atualizado=1") {
		t.Errorf("stale version: %d %s", strec.Code, strec.Header().Get("Location"))
	}

	// Admin requires re-signing (return target restricted to /admin/).
	dec := adminPost(t, env.router, "/admin/documentos/decidir", url.Values{"version_id": {fmt.Sprint(v2)}, "decision": {"resign"}, "return": {"https://evil.example/phish"}}, true)
	if dec.Code != http.StatusSeeOther || dec.Header().Get("Location") != "/admin/documentos" {
		t.Errorf("decide: %d location=%q (must not redirect off-site)", dec.Code, dec.Header().Get("Location"))
	}

	// Maria now sees the "updated, confirm again" notice.
	wreq = httptest.NewRequest(http.MethodGet, "/assinar?doc=AbC123", nil)
	wreq.AddCookie(testSession().SignedCookie("user_email", "maria@empresa.com"))
	widget = httptest.NewRecorder()
	env.router.ServeHTTP(widget, wreq)
	if !strings.Contains(widget.Body.String(), "Leia a nova versão e confirme novamente") {
		t.Errorf("outdated notice missing in widget")
	}
}

func outlineSignature(secret string, body []byte, ts time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", ts.UnixMilli())
	mac.Write(body)
	return fmt.Sprintf("t=%d,s=%s", ts.UnixMilli(), hex.EncodeToString(mac.Sum(nil)))
}

func TestOutlineWebhook(t *testing.T) {
	// Without a secret the endpoint does not exist.
	envNoSecret := newTestEnv(t, newStubOutline())
	rec := httptest.NewRecorder()
	envNoSecret.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhooks/outline", strings.NewReader("{}")))
	if rec.Code != http.StatusNotFound {
		t.Errorf("webhook without secret must be 404, got %d", rec.Code)
	}
}

func TestOutlineWebhookTriggersSync(t *testing.T) {
	const secret = "ol_whs_testsecret"
	t.Setenv("OUTLINE_WEBHOOK_SECRET", secret)
	stub := newStubOutline()
	stub.set("uuid-9", "WbK", "Norma", "texto 1")
	env := newTestEnv(t, stub)
	ctx := context.Background()

	if _, err := env.docSvc.Register(ctx, serviceRegister("uuid-9")); err != nil {
		t.Fatal(err)
	}
	stub.set("uuid-9", "WbK", "Norma", "texto 2")

	body := []byte(`{"id":"del-1","event":"documents.update","payload":{"id":"uuid-9","model":{"id":"uuid-9"}}}`)
	send := func(sig string) int {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/outline", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		if sig != "" {
			req.Header.Set("Outline-Signature", sig)
		}
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := send(""); code != http.StatusUnauthorized {
		t.Errorf("unsigned webhook: expected 401, got %d", code)
	}
	if code := send(outlineSignature("wrong", body, time.Now())); code != http.StatusUnauthorized {
		t.Errorf("bad signature: expected 401, got %d", code)
	}
	if code := send(outlineSignature(secret, body, time.Now().Add(-time.Hour))); code != http.StatusUnauthorized {
		t.Errorf("replayed (old) webhook: expected 401, got %d", code)
	}
	doc, _ := env.docRepo.GetDocumentByKey(ctx, "WbK")
	if versions, _ := env.docRepo.ListVersions(ctx, doc.ID); len(versions) != 1 {
		t.Fatalf("rejected webhooks must not sync")
	}

	if code := send(outlineSignature(secret, body, time.Now())); code != http.StatusOK {
		t.Fatalf("valid webhook: expected 200, got %d", code)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = env.docSvc.Wait(waitCtx)
	versions, _ := env.docRepo.ListVersions(ctx, doc.ID)
	if len(versions) != 2 || versions[0].Decision != models.DecisionPending {
		t.Errorf("webhook should have created a pending version, got %+v", versions)
	}
}

func TestIntegrityCheckDetectsTampering(t *testing.T) {
	env := newTestEnv(t, nil)
	for _, email := range []string{"a@empresa.com", "b@empresa.com", "c@empresa.com"} {
		if rec := postConfirm(t, env.router, "Politica", email, validCSRF(email), nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("sign %s: %d", email, rec.Code)
		}
	}

	ok := adminGet(env.router, "/admin/documentos?integridade=1")
	if !strings.Contains(ok.Body.String(), "Cadeia íntegra: 3 assinatura(s)") {
		t.Fatalf("intact chain not reported")
	}

	// Someone edits the database directly.
	if _, err := env.db.Exec(`UPDATE signatures SET ip_address = '6.6.6.6' WHERE user_email = 'b@empresa.com'`); err != nil {
		t.Fatal(err)
	}
	bad := adminGet(env.router, "/admin/documentos?integridade=1")
	if !strings.Contains(bad.Body.String(), "Foram encontrados") || !strings.Contains(bad.Body.String(), "dados alterados") {
		t.Errorf("tampering not reported")
	}
}

func serviceRegister(ref string) service.RegisterInput {
	return service.RegisterInput{OutlineRef: ref, Admin: adminEmail}
}

func TestDocumentTitleShownInAdminExportsAndValidator(t *testing.T) {
	stub := newStubOutline()
	stub.set("uuid-t", "SPDSySCsxL", "Criação e Publicação de APIs REST com TL++ no Protheus", "texto")
	env := newTestEnv(t, stub)
	ctx := context.Background()
	if _, err := env.docSvc.Register(ctx, serviceRegister("uuid-t")); err != nil {
		t.Fatal(err)
	}
	const title = "Criação e Publicação de APIs REST com TL++ no Protheus"
	if rec := postConfirm(t, env.router, "SPDSySCsxL", "maria@empresa.com", validCSRF("maria@empresa.com"), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("sign: %d", rec.Code)
	}
	// Unregistered doc keeps showing only its identifier.
	if rec := postConfirm(t, env.router, "AVULSO-1", "maria@empresa.com", validCSRF("maria@empresa.com"), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("sign: %d", rec.Code)
	}

	admin := adminGet(env.router, "/admin").Body.String()
	htmlTitle := strings.ReplaceAll(title, "+", "&#43;") // html/template renders "+" as &#43;
	if !strings.Contains(admin, "<strong>"+htmlTitle+"</strong>") || !strings.Contains(admin, "SPDSySCsxL") || !strings.Contains(admin, "<strong>AVULSO-1</strong>") {
		t.Errorf("admin list must show title + identifier")
	}

	// The document filter also matches the title.
	filtered := adminGet(env.router, "/admin?doc="+url.QueryEscape("APIs REST")).Body.String()
	if !strings.Contains(filtered, "SPDSySCsxL") || strings.Contains(filtered, "AVULSO-1") {
		t.Errorf("filter by title failed")
	}

	csv := adminGet(env.router, "/admin/export?format=csv").Body.String()
	if !strings.Contains(csv, "Titulo do Documento") || !strings.Contains(csv, "SPDSySCsxL;"+title+";") {
		t.Errorf("CSV must carry the title next to the identifier:\n%s", csv)
	}
	xml := adminGet(env.router, "/admin/export?format=xml").Body.String()
	if !strings.Contains(xml, "<document_title>"+title+"</document_title>") {
		t.Errorf("XML must carry document_title")
	}
	if adminGet(env.router, "/admin/export?format=xlsx").Code != http.StatusOK {
		t.Errorf("XLSX export failed")
	}

	sig, _ := env.repo.GetByDocAndEmail(ctx, "SPDSySCsxL", "maria@empresa.com")
	home := httptest.NewRecorder()
	env.router.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/?hash="+sig.HashID, nil))
	if !strings.Contains(home.Body.String(), htmlTitle) {
		t.Errorf("public validator must show the document title")
	}
}
