package handlers

import (
	"context"
	"crypto/rand"
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
	statusCode int
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

// SecurityHeaders sets basic security headers while allowing iframe embedding for /assinar.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return r.RemoteAddr
}

func getCookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err == nil {
		return c.Value
	}
	return ""
}

func setSessionCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour * 30),
	})
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
