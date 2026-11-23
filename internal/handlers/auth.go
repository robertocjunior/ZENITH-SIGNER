package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"zenith-signer/internal/auth"
	"zenith-signer/internal/models"
)

const oauthStateCookieName = "oauth_state"

type AuthHandler struct {
	authSvc auth.Service
	session *SessionManager
	logger  *slog.Logger
}

func NewAuthHandler(authSvc auth.Service, session *SessionManager, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		authSvc: authSvc,
		session: session,
		logger:  logger,
	}
}

func generateOAuthNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return generateRequestID()
	}
	return hex.EncodeToString(b)
}

func sanitizeReturnURL(raw, fallback string) string {
	clean := strings.TrimSpace(raw)
	if clean == "" || !strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "//") {
		return fallback
	}
	return clean
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	fallbackReturn := embedPath
	doc, err := models.NormalizeDocID(extractDocParam(r))
	if err != nil {
		doc = ""
	} else {
		fallbackReturn = embedURLFor(doc)
	}
	returnURL := sanitizeReturnURL(r.URL.Query().Get("return"), fallbackReturn)

	nonce := generateOAuthNonce()
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    nonce,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   h.session.isHTTPS,
		SameSite: http.SameSiteLaxMode,
	})

	state := fmt.Sprintf("%s|%s|%s", nonce, doc, returnURL)
	redirectURL := h.authSvc.GetAuthURL(state)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if code == "" {
		http.Error(w, "Código de autorização não recebido da Microsoft", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(state, "|", 3)
	stateCookie, err := r.Cookie(oauthStateCookieName)
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.session.isHTTPS,
		SameSite: http.SameSiteLaxMode,
	})

	if err != nil || len(parts) < 3 || parts[0] == "" || !hmac.Equal([]byte(parts[0]), []byte(stateCookie.Value)) {
		h.logger.Warn("oauth state mismatch or expired",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("ip", extractClientIP(r)),
		)
		http.Error(w, "Estado de autenticação inválido ou expirado. Tente fazer login novamente.", http.StatusBadRequest)
		return
	}

	token, err := h.authSvc.Exchange(r.Context(), code)
	if err != nil {
		h.logger.Error("failed to exchange oauth code",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		http.Error(w, "Falha na troca de token com o Azure: "+err.Error(), http.StatusInternalServerError)
		return
	}

	profile, err := h.authSvc.GetProfile(r.Context(), token)
	if err != nil {
		h.logger.Error("failed to fetch user profile from Microsoft Graph",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		http.Error(w, "Falha ao consultar perfil no Microsoft Graph: "+err.Error(), http.StatusInternalServerError)
		return
	}

	effectiveEmail := strings.ToLower(strings.TrimSpace(profile.EffectiveEmail()))

	h.session.SetCookie(w, "user_email", effectiveEmail)
	h.session.SetCookie(w, "user_name", profile.DisplayName)
	h.session.SetCookie(w, "user_department", profile.Department)
	h.session.SetCookie(w, "user_job", profile.JobTitle)
	h.session.SetCookie(w, "user_location", profile.OfficeLocation)

	h.logger.Info("user authenticated successfully via Microsoft Entra ID",
		slog.String("request_id", RequestIDFromContext(r.Context())),
		slog.String("email", effectiveEmail),
		slog.String("name", profile.DisplayName),
	)

	returnURL := sanitizeReturnURL(parts[2], "/assinar")
	http.Redirect(w, r, returnURL, http.StatusSeeOther)
}

func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	email := h.session.GetCookie(r, "user_email")
	h.session.ClearSession(w)
	h.logger.Info("admin user logged out",
		slog.String("request_id", RequestIDFromContext(r.Context())),
		slog.String("email", email),
	)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
