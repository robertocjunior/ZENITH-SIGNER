package handlers

import (
	"errors"
	"html/template"
	"net/http"

	"zenith-signer/internal/models"
	"zenith-signer/internal/service"
)

type EmbedHandler struct {
	signerSvc service.SignerService
	tmpl      *template.Template
	session   *SessionManager
}

func NewEmbedHandler(signerSvc service.SignerService, tmpl *template.Template, session *SessionManager) *EmbedHandler {
	return &EmbedHandler{
		signerSvc: signerSvc,
		tmpl:      tmpl,
		session:   session,
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

	var signedRecord *models.SignatureRecord
	csrfToken := ""
	if isLogged {
		csrfToken = h.session.CSRFToken(userEmail)
		signedRecord, err = h.signerSvc.GetSignature(r.Context(), doc, userEmail)
		if err != nil {
			// Non-fatal, just log and render as unsigned
			signedRecord = nil
		}
	}

	data := map[string]interface{}{
		"Doc":            doc,
		"IsLogged":       isLogged,
		"UserEmail":      userEmail,
		"UserName":       userName,
		"UserDepartment": userDept,
		"Record":         signedRecord,
		"IsSigned":       signedRecord != nil,
		"LoginURL":       loginURLFor(doc),
		"CSRFField":      csrfFieldName,
		"CSRFToken":      csrfToken,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, data)
}
