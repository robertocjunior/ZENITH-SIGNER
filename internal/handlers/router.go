package handlers

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"zenith-signer/internal/audit"
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
	DocSvc     *service.DocumentService
	Sealer     *audit.Sealer
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

	docsTmpl, err := template.ParseFS(p.TemplateFS, "templates/admin_documents.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates/admin_documents.html: %w", err)
	}

	versionTmpl, err := template.ParseFS(p.TemplateFS, "templates/admin_version.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates/admin_version.html: %w", err)
	}

	if p.DocSvc == nil {
		return nil, fmt.Errorf("router: DocSvc is required")
	}
	if p.Sealer == nil {
		return nil, fmt.Errorf("router: Sealer is required")
	}

	embedOrigins, err := ParseEmbedOrigins(p.Config.Server.AllowedEmbedOrigins)
	if err != nil {
		return nil, err
	}

	ipResolver, err := NewClientIPResolver(p.Config.Server.TrustedProxies)
	if err != nil {
		return nil, err
	}

	sessionMgr := NewSessionManager(p.Config.Auth.SessionSecret, p.Config.Server.BaseURL)

	homeHandler := NewHomeHandler(p.Repo, homeTmpl, p.Config.Server.AppName, p.Logger)
	embedHandler := NewEmbedHandler(p.SignerSvc, embedTmpl, sessionMgr, p.Logger)
	authHandler := NewAuthHandler(p.AuthSvc, sessionMgr, p.Logger)
	signHandler := NewSignHandler(p.SignerSvc, sessionMgr, p.Config.Server.BaseURL, p.Logger)
	adminHandler := NewAdminHandler(p.Repo, p.AuthSvc, adminTmpl, p.Config.Server.AppName, sessionMgr, p.Logger)
	exportHandler := NewExportHandler(p.Repo, p.AuthSvc, sessionMgr, p.Logger)
	healthHandler := NewHealthHandler(p.DB, p.StartTime)

	appName := p.Config.Server.AppName
	if strings.TrimSpace(appName) == "" {
		appName = "Zenith Signer"
	}
	guard := &adminGuard{authSvc: p.AuthSvc, session: sessionMgr, appOrigin: originOf(p.Config.Server.BaseURL), logger: p.Logger}
	docsAdmin := NewDocumentsAdminHandler(guard, p.DocSvc, p.Repo, p.Sealer, docsTmpl, versionTmpl, appName, p.Logger)
	webhookHandler := NewOutlineWebhookHandler(p.DocSvc, p.Config.Outline.WebhookSecret, p.Logger)

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
	mux.HandleFunc("/admin/documentos", docsAdmin.List)
	mux.HandleFunc("/admin/documentos/cadastrar", docsAdmin.Register)
	mux.HandleFunc("/admin/documentos/decidir", docsAdmin.Decide)
	mux.HandleFunc("/admin/documentos/sincronizar", docsAdmin.Sync)
	mux.HandleFunc("/admin/documentos/status", docsAdmin.SetActive)
	mux.HandleFunc("/admin/documentos/versao", docsAdmin.Version)

	// Outline integration
	mux.Handle("/webhooks/outline", webhookHandler)

	// Liveness and healthcheck routes for 24/7 monitoring
	mux.HandleFunc("/healthz", healthHandler.HandleHealth)
	mux.HandleFunc("/livez", healthHandler.HandleLive)

	// Middleware chain: Recovery -> ClientIP -> RequestLogger -> SecurityHeaders -> Router Mux
	var handler http.Handler = mux
	handler = SecurityHeaders(embedOrigins)(handler)
	handler = RequestLogger(p.Logger)(handler)
	handler = ClientIP(ipResolver)(handler)
	handler = Recovery(p.Logger)(handler)

	return handler, nil
}
