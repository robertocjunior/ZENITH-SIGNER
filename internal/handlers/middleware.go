package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

type ctxKey string

const requestIDKey ctxKey = "request_id"

// RequestIDFromContext returns the correlation request ID stored in context, if any.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000")
	}
	return hex.EncodeToString(b)
}

type responseWriterInterceptor struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (w *responseWriterInterceptor) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriterInterceptor) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += n
	return n, err
}

// Recovery recovers from unexpected panics in handlers to keep the server running 24/7.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					stack := string(debug.Stack())
					logger.Error("PANIC RECOVERED: HTTP handler panicked",
						slog.Any("recover", rec),
						slog.String("request_id", RequestIDFromContext(r.Context())),
						slog.String("path", r.URL.Path),
						slog.String("method", r.Method),
						slog.String("stack", stack),
					)
					http.Error(w, "Erro interno do servidor. A equipe já foi notificada.", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestLogger logs incoming HTTP requests with structured context, request ID, and status-based severity.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			reqID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
			if reqID == "" {
				reqID = generateRequestID()
			}
			w.Header().Set("X-Request-Id", reqID)
			r = r.WithContext(context.WithValue(r.Context(), requestIDKey, reqID))

			interceptor := &responseWriterInterceptor{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(interceptor, r)

			duration := time.Since(start)
			ip := extractClientIP(r)

			// Don't clutter logs with high-frequency health probes unless debug level is enabled
			if (r.URL.Path == "/healthz" || r.URL.Path == "/livez") && interceptor.statusCode == http.StatusOK {
				logger.Debug("http health probe",
					slog.String("request_id", reqID),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", interceptor.statusCode),
					slog.Duration("duration", duration),
				)
				return
			}

			attrs := []any{
				slog.String("request_id", reqID),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", interceptor.statusCode),
				slog.Int("bytes", interceptor.bytesWritten),
				slog.Duration("duration", duration),
				slog.String("ip", ip),
				slog.String("user_agent", r.UserAgent()),
			}

			switch {
			case interceptor.statusCode >= 500:
				logger.Error("http request", attrs...)
			case interceptor.statusCode >= 400:
				logger.Warn("http request", attrs...)
			default:
				logger.Info("http request", attrs...)
			}
		})
	}
}

var sessionCookieNames = []string{
	"user_email",
	"user_name",
	"user_department",
	"user_job",
	"user_location",
}

// SessionManager signs and verifies session cookies with HMAC-SHA256 and applies HTTPS/iframe attributes.
type SessionManager struct {
	secret  []byte
	isHTTPS bool
}

// NewSessionManager creates a SessionManager using secret (or a random 32-byte key if empty).
func NewSessionManager(secret, baseURL string) *SessionManager {
	var key []byte
	if strings.TrimSpace(secret) != "" {
		key = []byte(secret)
	} else {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}

	isHTTPS := strings.HasPrefix(strings.ToLower(strings.TrimSpace(baseURL)), "https://")
	return &SessionManager{
		secret:  key,
		isHTTPS: isHTTPS,
	}
}

func (sm *SessionManager) signValue(value string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(value))
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(encoded))
	sig := hex.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig
}

func (sm *SessionManager) verifyValue(raw string) (string, bool) {
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return "", false
	}

	expectedMac := hmac.New(sha256.New, sm.secret)
	expectedMac.Write([]byte(parts[0]))
	expectedSig := expectedMac.Sum(nil)

	providedSig, err := hex.DecodeString(parts[1])
	if err != nil || !hmac.Equal(providedSig, expectedSig) {
		return "", false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

// SignedCookie builds a signed *http.Cookie (useful for handlers and tests).
func (sm *SessionManager) SignedCookie(name, value string) *http.Cookie {
	sameSite := http.SameSiteLaxMode
	if sm.isHTTPS {
		sameSite = http.SameSiteNoneMode
	}

	return &http.Cookie{
		Name:     name,
		Value:    sm.signValue(value),
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.isHTTPS,
		SameSite: sameSite,
		Expires:  time.Now().Add(24 * time.Hour * 30),
	}
}

func (sm *SessionManager) SetCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, sm.SignedCookie(name, value))
}

func (sm *SessionManager) GetCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	val, ok := sm.verifyValue(c.Value)
	if !ok {
		return ""
	}
	return val
}

// CSRFToken derives an anti-CSRF token bound to the session identity.
// The token is an HMAC of the user e-mail with a domain separator, so it
// cannot be computed without the server secret and is distinct from cookie signatures.
func (sm *SessionManager) CSRFToken(sessionEmail string) string {
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte("csrf\x00"))
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(sessionEmail))))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidCSRFToken checks token against the expected token for sessionEmail in constant time.
func (sm *SessionManager) ValidCSRFToken(sessionEmail, token string) bool {
	if strings.TrimSpace(sessionEmail) == "" || token == "" {
		return false
	}
	return hmac.Equal([]byte(token), []byte(sm.CSRFToken(sessionEmail)))
}

func (sm *SessionManager) ClearSession(w http.ResponseWriter) {
	sameSite := http.SameSiteLaxMode
	if sm.isHTTPS {
		sameSite = http.SameSiteNoneMode
	}
	for _, name := range sessionCookieNames {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   sm.isHTTPS,
			SameSite: sameSite,
		})
	}
}

func extractDocParam(r *http.Request) string {
	doc := r.URL.Query().Get("doc")
	if doc == "" {
		raw := r.URL.RawQuery
		if idx := strings.Index(raw, "doc="); idx != -1 {
			sub := raw[idx+4:]
			if ampHex := strings.Index(sub, "&"); ampHex != -1 {
				doc = sub[:ampHex]
			} else {
				doc = sub
			}
		}
	}
	return strings.TrimSpace(doc)
}
