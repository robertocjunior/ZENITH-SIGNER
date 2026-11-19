package handlers

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"zenith-signer/internal/auth"
	"zenith-signer/internal/config"
	"zenith-signer/internal/database"
	"zenith-signer/internal/service"
)

// RouterParams encapsulates dependencies required to construct the HTTP routing tree.
type RouterParams struct {
	Config     *config.Config
	Repo       database.Repository
	DB         *sql.DB
	AuthSvc    auth.Service
	SignerSvc  service.SignerService
	TemplateFS fs.FS
	Logger     *slog.Logger
	StartTime  time.Time
}

// NewRouter wires handlers, templates, and middlewares into a unified http.Handler.
func NewRouter(p RouterParams) (http.Handler, error) {
	homeTmpl, err := template.ParseFS(p.TemplateFS, "templates/home.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates/home.html: %w", err)
	}

	embedTmpl, err := template.ParseFS(p.TemplateFS, "templates/embed.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates/embed.html: %w", err)
	}

	adminTmpl, err := template.ParseFS(p.TemplateFS, "templates/admin.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates/admin.html: %w", err)
	}

	sessionMgr := NewSessionManager(p.Config.Auth.SessionSecret, p.Config.Server.BaseURL)

	homeHandler := NewHomeHandler(p.Repo, homeTmpl, p.Config.Server.AppName, p.Logger)
	embedHandler := NewEmbedHandler(p.SignerSvc, embedTmpl, sessionMgr)
	authHandler := NewAuthHandler(p.AuthSvc, sessionMgr, p.Logger)
	signHandler := NewSignHandler(p.SignerSvc, sessionMgr, p.Logger)
	adminHandler := NewAdminHandler(p.Repo, p.AuthSvc, adminTmpl, p.Config.Server.AppName, sessionMgr, p.Logger)
	exportHandler := NewExportHandler(p.Repo, p.AuthSvc, sessionMgr, p.Logger)
	healthHandler := NewHealthHandler(p.DB, p.StartTime)

	mux := http.NewServeMux()

	// Public and document embed routes
	mux.Handle("/", homeHandler)
	mux.Handle("/assinar", embedHandler)
	mux.HandleFunc("/auth/login", authHandler.HandleLogin)
	mux.HandleFunc("/auth/callback", authHandler.HandleCallback)
	mux.HandleFunc("/auth/logout", authHandler.HandleLogout)
	mux.Handle("/confirmar", signHandler)

	// Admin and reporting routes
	mux.Handle("/admin", adminHandler)
	mux.Handle("/admin/export", exportHandler)

	// Liveness and healthcheck routes for 24/7 monitoring
	mux.HandleFunc("/healthz", healthHandler.HandleHealth)
	mux.HandleFunc("/livez", healthHandler.HandleLive)

	// Middleware chain: Recovery -> RequestLogger -> SecurityHeaders -> Router Mux
	var handler http.Handler = mux
	handler = SecurityHeaders(handler)
	handler = RequestLogger(p.Logger)(handler)
	handler = Recovery(p.Logger)(handler)

	return handler, nil
}
