package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"zenith-signer/internal/service"
)

type SignHandler struct {
	signerSvc service.SignerService
	session   *SessionManager
	logger    *slog.Logger
}

func NewSignHandler(signerSvc service.SignerService, session *SessionManager, logger *slog.Logger) *SignHandler {
	return &SignHandler{
		signerSvc: signerSvc,
		session:   session,
		logger:    logger,
	}
}

func (h *SignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	doc := strings.TrimSpace(r.FormValue("doc"))
	if doc == "" {
		http.Error(w, "Documento não informado", http.StatusBadRequest)
		return
	}

	userEmail := h.session.GetCookie(r, "user_email")
	if userEmail == "" {
		http.Redirect(w, r, fmt.Sprintf("/auth/login?doc=%s&return=/assinar%%3Fdoc%%3D%s", doc, doc), http.StatusSeeOther)
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

	_, err := h.signerSvc.SignDocument(r.Context(), req)
	if err != nil {
		h.logger.Error("error registering signature",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("doc", doc),
			slog.String("email", userEmail),
			slog.String("error", err.Error()),
		)
		http.Error(w, "Erro ao registrar confirmação: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/assinar?doc="+doc, http.StatusSeeOther)
}
