package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"zenith-signer/internal/models"
	"zenith-signer/internal/service"
)

// csrfFieldName is the form field carrying the anti-CSRF token on POST /confirmar.
const csrfFieldName = "csrf_token"

type SignHandler struct {
	signerSvc service.SignerService
	session   *SessionManager
	appOrigin string
	logger    *slog.Logger
}

func NewSignHandler(signerSvc service.SignerService, session *SessionManager, baseURL string, logger *slog.Logger) *SignHandler {
	return &SignHandler{
		signerSvc: signerSvc,
		session:   session,
		appOrigin: originOf(baseURL),
		logger:    logger,
	}
}

// originOf returns the scheme://host[:port] origin of a URL, lower-cased.
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// loginURLFor builds the login URL that returns the user to the widget of doc.
func loginURLFor(doc string) string {
	q := url.Values{}
	q.Set("doc", doc)
	q.Set("return", embedURLFor(doc))
	return "/auth/login?" + q.Encode()
}

// embedURLFor builds the widget URL for doc with proper escaping.
func embedURLFor(doc string) string {
	return embedPath + "?doc=" + url.QueryEscape(doc)
}

// sameOriginRequest rejects requests whose Origin header (sent by browsers on
// cross-site POSTs) does not match the application origin. Requests without
// an Origin header are left to the CSRF token check.
func (h *SignHandler) sameOriginRequest(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	return h.appOrigin != "" && strings.EqualFold(origin, h.appOrigin)
}

func (h *SignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	doc, err := models.NormalizeDocID(r.PostFormValue("doc"))
	if err != nil {
		http.Error(w, "Identificador de documento inválido.", http.StatusBadRequest)
		return
	}

	userEmail := h.session.GetCookie(r, "user_email")
	if userEmail == "" {
		http.Redirect(w, r, loginURLFor(doc), http.StatusSeeOther)
		return
	}

	if !h.sameOriginRequest(r) || !h.session.ValidCSRFToken(userEmail, r.PostFormValue(csrfFieldName)) {
		h.logger.Warn("signature rejected: CSRF validation failed",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("doc", doc),
			slog.String("email", userEmail),
			slog.String("origin", r.Header.Get("Origin")),
			slog.String("ip", extractClientIP(r)),
		)
		http.Error(w, "Requisição inválida ou expirada. Recarregue a página e tente novamente.", http.StatusForbidden)
		return
	}

	req := service.SignRequest{
		Doc:            doc,
		UserEmail:      userEmail,
		UserName:       h.session.GetCookie(r, "user_name"),
		Department:     h.session.GetCookie(r, "user_department"),
		JobTitle:       h.session.GetCookie(r, "user_job"),
		OfficeLocation: h.session.GetCookie(r, "user_location"),
		IP:             extractClientIP(r),
		UserAgent:      r.UserAgent(),
	}
	req.ExpectedVersionID, _ = strconv.ParseInt(strings.TrimSpace(r.PostFormValue("version_id")), 10, 64)

	if _, err := h.signerSvc.SignDocument(r.Context(), req); err != nil {
		if errors.Is(err, service.ErrDocumentChanged) {
			// The page changed while the widget was open: show the new version.
			http.Redirect(w, r, embedURLFor(doc)+"&atualizado=1", http.StatusSeeOther)
			return
		}
		if errors.Is(err, service.ErrDocumentInactive) {
			http.Error(w, err.Error(), http.StatusGone)
			return
		}
		h.logger.Error("error registering signature",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("doc", doc),
			slog.String("email", userEmail),
			slog.String("error", err.Error()),
		)
		http.Error(w, "Erro ao registrar confirmação: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, embedURLFor(doc), http.StatusSeeOther)
}
