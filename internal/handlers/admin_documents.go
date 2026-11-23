package handlers

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"zenith-signer/internal/audit"
	"zenith-signer/internal/auth"
	"zenith-signer/internal/database"
	"zenith-signer/internal/models"
	"zenith-signer/internal/outline"
	"zenith-signer/internal/service"
	"zenith-signer/internal/textdiff"
)

const flashCookie = "admin_flash"

// adminGuard centralises admin authentication and CSRF checks for admin forms.
type adminGuard struct {
	authSvc   auth.Service
	session   *SessionManager
	appOrigin string
	logger    *slog.Logger
}

// requireAdmin returns the admin e-mail, or writes a redirect/403 and returns false.
func (g *adminGuard) requireAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	email := strings.ToLower(g.session.GetCookie(r, "user_email"))
	if email == "" {
		http.Redirect(w, r, "/auth/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return "", false
	}
	if !g.authSvc.IsAdmin(email) {
		g.logger.Warn("admin access denied",
			slog.String("email", email),
			slog.String("path", r.URL.Path),
			slog.String("ip", extractClientIP(r)),
			slog.String("request_id", RequestIDFromContext(r.Context())),
		)
		http.Error(w, "Acesso restrito para administradores.", http.StatusForbidden)
		return "", false
	}
	return email, true
}

// requireAdminPost checks admin, method POST, same origin and CSRF token.
func (g *adminGuard) requireAdminPost(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return "", false
	}
	email, ok := g.requireAdmin(w, r)
	if !ok {
		return "", false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	sameOrigin := origin == "" || (g.appOrigin != "" && strings.EqualFold(origin, g.appOrigin))
	if !sameOrigin || !g.session.ValidCSRFToken(email, r.PostFormValue(csrfFieldName)) {
		g.logger.Warn("admin action rejected: CSRF validation failed",
			slog.String("email", email),
			slog.String("path", r.URL.Path),
			slog.String("origin", origin),
		)
		http.Error(w, "Requisição inválida ou expirada. Recarregue a página e tente novamente.", http.StatusForbidden)
		return "", false
	}
	return email, true
}

func (g *adminGuard) setFlash(w http.ResponseWriter, kind, msg string) {
	g.session.SetCookie(w, flashCookie, kind+"|"+msg)
}

func (g *adminGuard) popFlash(w http.ResponseWriter, r *http.Request) (kind, msg string) {
	raw := g.session.GetCookie(r, flashCookie)
	if raw == "" {
		return "", ""
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: g.session.isHTTPS})
	kind, msg, _ = strings.Cut(raw, "|")
	return kind, msg
}

// DocumentsAdminHandler serves the document registry, version decisions and integrity check.
type DocumentsAdminHandler struct {
	guard       *adminGuard
	docs        *service.DocumentService
	repo        database.Repository
	sealer      *audit.Sealer
	listTmpl    *template.Template
	versionTmpl *template.Template
	appName     string
	logger      *slog.Logger
}

func NewDocumentsAdminHandler(guard *adminGuard, docs *service.DocumentService, repo database.Repository, sealer *audit.Sealer,
	listTmpl, versionTmpl *template.Template, appName string, logger *slog.Logger) *DocumentsAdminHandler {
	return &DocumentsAdminHandler{
		guard: guard, docs: docs, repo: repo, sealer: sealer,
		listTmpl: listTmpl, versionTmpl: versionTmpl, appName: appName, logger: logger,
	}
}

type outlineResult struct {
	ID         string
	URLID      string
	Title      string
	Registered *models.Document
}

type integrityView struct {
	Ran     bool
	Checked int
	Issues  []audit.Issue
	Error   string
}

// List renders GET /admin/documentos.
func (h *DocumentsAdminHandler) List(w http.ResponseWriter, r *http.Request) {
	email, ok := h.guard.requireAdmin(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	flashKind, flashMsg := h.guard.popFlash(w, r)

	docs, err := h.docs.Repo().ListDocuments(ctx)
	if err != nil {
		h.logger.Error("failed to list documents", slog.String("error", err.Error()))
		http.Error(w, "Erro ao carregar documentos.", http.StatusInternalServerError)
		return
	}

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	var results []outlineResult
	searchErr := ""
	if query != "" {
		found, err := h.docs.SearchOutline(ctx, query)
		if err != nil {
			searchErr = err.Error()
		}
		for _, d := range found {
			reg, _ := h.docs.Repo().GetDocumentByOutlineID(ctx, d.ID)
			results = append(results, outlineResult{ID: d.ID, URLID: d.URLID, Title: d.Title, Registered: reg})
		}
	}

	integrity := integrityView{}
	if r.URL.Query().Get("integridade") == "1" {
		integrity = h.verifyChain(ctx, email)
	}

	widgetURLs := map[int64]string{}
	for _, d := range docs {
		widgetURLs[d.ID] = h.docs.WidgetURL(d.DocKey)
	}

	data := map[string]any{
		"AppName":        h.appName,
		"UserEmail":      email,
		"CSRFField":      csrfFieldName,
		"CSRFToken":      h.guard.session.CSRFToken(email),
		"FlashKind":      flashKind,
		"FlashMsg":       flashMsg,
		"OutlineEnabled": h.docs.Enabled(),
		"Documents":      docs,
		"WidgetURLs":     widgetURLs,
		"Query":          query,
		"Results":        results,
		"SearchError":    searchErr,
		"Integrity":      integrity,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.listTmpl.Execute(w, data); err != nil {
		h.logger.Error("failed to render documents page", slog.String("error", err.Error()))
	}
}

func (h *DocumentsAdminHandler) verifyChain(ctx context.Context, admin string) integrityView {
	records, err := h.repo.ListChain(ctx)
	if err != nil {
		return integrityView{Ran: true, Error: err.Error()}
	}
	rep := h.sealer.Verify(records, database.GenesisHash)
	h.logger.Info("audit chain verified",
		slog.String("admin", admin),
		slog.Int("checked", rep.Checked),
		slog.Int("issues", len(rep.Issues)))
	if !rep.OK() {
		h.logger.Error("AUDIT CHAIN INTEGRITY FAILURE", slog.Int("issues", len(rep.Issues)))
	}
	return integrityView{Ran: true, Checked: rep.Checked, Issues: rep.Issues}
}

func (h *DocumentsAdminHandler) back(w http.ResponseWriter, r *http.Request, target string) {
	// Only local admin pages are accepted as return targets (no open redirect).
	target = sanitizeReturnURL(target, "/admin/documentos")
	if !strings.HasPrefix(target, "/admin/") {
		target = "/admin/documentos"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// Register handles POST /admin/documentos/cadastrar.
func (h *DocumentsAdminHandler) Register(w http.ResponseWriter, r *http.Request) {
	email, ok := h.guard.requireAdminPost(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	res, err := h.docs.Register(ctx, service.RegisterInput{
		OutlineRef:  r.PostFormValue("outline_ref"),
		DocKey:      r.PostFormValue("doc_key"),
		InsertEmbed: r.PostFormValue("insert_embed") == "1",
		AcceptPrior: r.PostFormValue("accept_prior") == "1",
		Admin:       email,
	})
	if err != nil {
		h.logger.Warn("document registration failed", slog.String("admin", email), slog.String("error", err.Error()))
		h.guard.setFlash(w, "err", "Não foi possível cadastrar: "+err.Error())
		h.back(w, r, "")
		return
	}

	msg := "Documento \"" + res.Document.Title + "\" cadastrado (versão 1). "
	switch res.Document.EmbedStatus {
	case models.EmbedInserted:
		msg += "O widget foi inserido no topo da página do Outline."
	case models.EmbedExisting:
		msg += "A página já continha o widget."
	case models.EmbedLink:
		msg += "O link do widget foi inserido no topo da página, mas o Outline o exibiu como link: abra a página, clique no link e escolha \"Embed\"."
	default:
		msg += "Cole o link do widget na página do Outline usando o comando /embed: " + res.WidgetURL
	}
	if res.EmbedError != "" {
		msg += " (" + res.EmbedError + ")"
	}
	kind := "ok"
	if res.Document.EmbedStatus == models.EmbedLink || res.EmbedError != "" {
		kind = "warn"
	}
	h.guard.setFlash(w, kind, msg)
	h.back(w, r, "")
}

func formInt64(r *http.Request, name string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(r.PostFormValue(name)), 10, 64)
	return v
}

// Decide handles POST /admin/documentos/decidir.
func (h *DocumentsAdminHandler) Decide(w http.ResponseWriter, r *http.Request) {
	email, ok := h.guard.requireAdminPost(w, r)
	if !ok {
		return
	}
	versionID := formInt64(r, "version_id")
	decision := r.PostFormValue("decision")
	err := h.docs.Decide(r.Context(), versionID, decision, email)
	switch {
	case errors.Is(err, database.ErrVersionNotPending):
		h.guard.setFlash(w, "warn", "Esta versão já tinha uma decisão registrada.")
	case err != nil:
		h.guard.setFlash(w, "err", "Não foi possível registrar a decisão: "+err.Error())
	case decision == models.DecisionResign:
		h.guard.setFlash(w, "ok", "Nova assinatura exigida: os colaboradores verão o pedido de confirmação novamente.")
	default:
		h.guard.setFlash(w, "ok", "Alteração marcada como correção menor: as assinaturas anteriores continuam válidas.")
	}
	h.back(w, r, r.PostFormValue("return"))
}

// Sync handles POST /admin/documentos/sincronizar.
func (h *DocumentsAdminHandler) Sync(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.guard.requireAdminPost(w, r); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	doc, err := h.docs.Repo().GetDocumentByID(ctx, formInt64(r, "document_id"))
	if err != nil || doc == nil {
		h.guard.setFlash(w, "err", "Documento não encontrado.")
		h.back(w, r, "")
		return
	}
	changed, err := h.docs.SyncDocument(ctx, doc)
	switch {
	case err != nil:
		h.guard.setFlash(w, "err", "Falha ao sincronizar com o Outline: "+err.Error())
	case changed:
		h.guard.setFlash(w, "warn", "O texto de \""+doc.Title+"\" mudou no Outline: uma nova versão aguarda sua decisão.")
	default:
		h.guard.setFlash(w, "ok", "\""+doc.Title+"\" está igual à versão registrada.")
	}
	h.back(w, r, "")
}

// SetActive handles POST /admin/documentos/status.
func (h *DocumentsAdminHandler) SetActive(w http.ResponseWriter, r *http.Request) {
	email, ok := h.guard.requireAdminPost(w, r)
	if !ok {
		return
	}
	id := formInt64(r, "document_id")
	active := r.PostFormValue("active") == "1"
	if err := h.docs.Repo().SetActive(r.Context(), id, active); err != nil {
		h.guard.setFlash(w, "err", "Não foi possível alterar o status: "+err.Error())
	} else if active {
		h.guard.setFlash(w, "ok", "Documento reativado: voltou a aceitar confirmações.")
	} else {
		h.guard.setFlash(w, "ok", "Documento desativado: não aceita novas confirmações.")
	}
	h.logger.Info("document active status changed", slog.Int64("document_id", id), slog.Bool("active", active), slog.String("admin", email))
	h.back(w, r, "")
}

// Version renders GET /admin/documentos/versao?id=.
func (h *DocumentsAdminHandler) Version(w http.ResponseWriter, r *http.Request) {
	email, ok := h.guard.requireAdmin(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	v, err := h.docs.Repo().GetVersion(ctx, id)
	if err != nil || v == nil {
		http.NotFound(w, r)
		return
	}
	doc, err := h.docs.Repo().GetDocumentByID(ctx, v.DocumentID)
	if err != nil || doc == nil {
		http.NotFound(w, r)
		return
	}
	prev, _ := h.docs.Repo().GetPreviousVersion(ctx, v)
	versions, _ := h.docs.Repo().ListVersions(ctx, doc.ID)

	var ops []textdiff.Op
	if prev != nil {
		ops = textdiff.Lines(prev.Content, v.Content)
	} else {
		ops = textdiff.Lines("", v.Content)
	}
	added, removed := textdiff.Stats(ops)
	flashKind, flashMsg := h.guard.popFlash(w, r)

	data := map[string]any{
		"AppName":   h.appName,
		"UserEmail": email,
		"CSRFField": csrfFieldName,
		"CSRFToken": h.guard.session.CSRFToken(email),
		"FlashKind": flashKind,
		"FlashMsg":  flashMsg,
		"Doc":       doc,
		"Version":   v,
		"Previous":  prev,
		"Versions":  versions,
		"Diff":      ops,
		"Added":     added,
		"Removed":   removed,
		"Self":      r.URL.RequestURI(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.versionTmpl.Execute(w, data); err != nil {
		h.logger.Error("failed to render version page", slog.String("error", err.Error()))
	}
}

// OutlineWebhookHandler receives Outline webhooks and triggers document syncs.
type OutlineWebhookHandler struct {
	docs   *service.DocumentService
	secret string
	logger *slog.Logger
}

func NewOutlineWebhookHandler(docs *service.DocumentService, secret string, logger *slog.Logger) *OutlineWebhookHandler {
	return &OutlineWebhookHandler{docs: docs, secret: secret, logger: logger}
}

const webhookTolerance = 5 * time.Minute

func (h *OutlineWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.secret == "" || !h.docs.Enabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	body, err := readLimited(r, 1<<20)
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := outline.VerifySignature(r.Header.Get(outline.SignatureHeader), body, h.secret, time.Now(), webhookTolerance); err != nil {
		h.logger.Warn("outline webhook rejected", slog.String("error", err.Error()), slog.String("ip", extractClientIP(r)))
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var ev outline.WebhookEvent
	if err := jsonUnmarshal(body, &ev); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	if ev.IsContentEvent() {
		if id := ev.DocumentID(); id != "" {
			h.docs.QueueSync(id)
			h.logger.Debug("outline webhook queued sync", slog.String("event", ev.Event), slog.String("outline_id", id))
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}
