package handlers

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"

	"zenith-signer/internal/models"
	"zenith-signer/internal/service"
)

type EmbedHandler struct {
	signerSvc service.SignerService
	tmpl      *template.Template
	session   *SessionManager
	logger    *slog.Logger
}

func NewEmbedHandler(signerSvc service.SignerService, tmpl *template.Template, session *SessionManager, logger *slog.Logger) *EmbedHandler {
	return &EmbedHandler{
		signerSvc: signerSvc,
		tmpl:      tmpl,
		session:   session,
		logger:    logger,
	}
}

func (h *EmbedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	doc, err := models.NormalizeDocID(extractDocParam(r))
	if err != nil {
		msg := "Identificador de documento 'doc' inválido."
		if errors.Is(err, models.ErrDocIDEmpty) {
			msg = "Identificador de documento 'doc' não informado."
		}
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	userEmail := h.session.GetCookie(r, "user_email")
	userName := h.session.GetCookie(r, "user_name")
	userDept := h.session.GetCookie(r, "user_department")
	isLogged := userEmail != ""

	status := &service.SignatureStatus{}
	csrfToken := ""
	if isLogged {
		csrfToken = h.session.CSRFToken(userEmail)
	}
	// Also loaded for anonymous visitors so the widget shows the document title.
	if st, err := h.signerSvc.GetStatus(r.Context(), doc, userEmail); err != nil {
		// Non-fatal: render as unsigned and let the POST handle errors.
		if h.logger != nil {
			h.logger.Warn("failed to load signature status", slog.String("doc", doc), slog.String("error", err.Error()))
		}
	} else {
		status = st
	}

	title := doc
	var versionID int64
	versionNo := 0
	active := true
	if status.Document != nil {
		title = status.Document.Title
		active = status.Document.Active
	}
	if status.CurrentVersion != nil {
		versionID = status.CurrentVersion.ID
		versionNo = status.CurrentVersion.VersionNo
	}

	data := map[string]interface{}{
		"Doc":            doc,
		"Title":          title,
		"IsRegistered":   status.Document != nil,
		"Active":         active,
		"VersionID":      versionID,
		"VersionNo":      versionNo,
		"IsLogged":       isLogged,
		"UserEmail":      userEmail,
		"UserName":       userName,
		"UserDepartment": userDept,
		"Record":         status.Record,
		"IsSigned":       status.Valid,
		"Outdated":       status.Outdated,
		"Changed":        r.URL.Query().Get("atualizado") == "1",
		"LoginURL":       loginURLFor(doc),
		"CSRFField":      csrfFieldName,
		"CSRFToken":      csrfToken,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, data)
}
