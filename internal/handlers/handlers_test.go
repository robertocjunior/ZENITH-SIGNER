package handlers

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"zenith-signer/internal/audit"
	"zenith-signer/internal/auth"
	"zenith-signer/internal/config"
	"zenith-signer/internal/database"
	"zenith-signer/internal/models"
	"zenith-signer/internal/service"
)

type mockEmailSender struct{}

func (m *mockEmailSender) SendReceipt(ctx context.Context, toEmail, toName, docName, hashID, dateStr string) error {
	return nil
}

func setupTestRouter(t *testing.T) (http.Handler, database.Repository) {
	t.Helper()
	env := newTestEnv(t, nil)
	return env.router, env.repo
}

// testEnv bundles a fully wired router for handler tests.
type testEnv struct {
	db      *sql.DB
	router  http.Handler
	repo    database.Repository
	docRepo database.DocumentRepository
	docSvc  *service.DocumentService
	sealer  *audit.Sealer
}

// newTestEnv builds the router with an in-memory DB; outlineAPI may be nil (integration disabled).
func newTestEnv(t *testing.T, outlineAPI service.OutlineAPI) *testEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A single connection keeps the in-memory database shared across queries.
	dbCfg := config.DatabaseConfig{Path: "file:" + t.Name() + "?mode=memory&cache=shared", MaxOpenConns: 1, MaxIdleConns: 1}
	db, err := database.Open(dbCfg, logger)
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	if err := database.Migrate(ctx, db, logger); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := database.NewRepository(db)
	docRepo := database.NewDocumentRepository(db)

	authCfg := config.AuthConfig{
		AdminEmails: map[string]bool{
			"admin@empresa.com": true,
		},
	}
	authSvc := auth.NewService(authCfg)
	sealer := audit.NewSealer([]byte("test-audit-key"))
	signerSvc := service.NewSignerService(repo, &mockEmailSender{}, logger,
		service.WithDocuments(docRepo), service.WithSealer(sealer))

	t.Setenv("SESSION_SECRET", "test-session-secret")
	cfg := config.Load()

	var docSvc *service.DocumentService
	if outlineAPI != nil {
		docSvc = service.NewDocumentService(docRepo, outlineAPI, "https://wiki.empresa.com.br", cfg.Server.BaseURL, logger)
	} else {
		docSvc = service.NewDocumentService(docRepo, nil, "", cfg.Server.BaseURL, logger)
	}

	rootFS := os.DirFS("../..")
	router, err := NewRouter(RouterParams{
		Config:     cfg,
		Repo:       repo,
		DB:         db,
		AuthSvc:    authSvc,
		SignerSvc:  signerSvc,
		DocSvc:     docSvc,
		Sealer:     sealer,
		TemplateFS: rootFS,
		Logger:     logger,
		StartTime:  time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to create test router: %v", err)
	}

	return &testEnv{db: db, router: router, repo: repo, docRepo: docRepo, docSvc: docSvc, sealer: sealer}
}

func TestHealthEndpoints(t *testing.T) {
	router, _ := setupTestRouter(t)

	// Test /healthz
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /healthz, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"healthy"`) {
		t.Errorf("expected status healthy, got: %s", rec.Body.String())
	}

	// Test /livez
	reqLive := httptest.NewRequest(http.MethodGet, "/livez", nil)
	recLive := httptest.NewRecorder()
	router.ServeHTTP(recLive, reqLive)

	if recLive.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /livez, got %d", recLive.Code)
	}
	if !strings.Contains(recLive.Body.String(), `"status":"alive"`) {
		t.Errorf("expected status alive, got: %s", recLive.Body.String())
	}
}

func TestSignEmbedEndpoint(t *testing.T) {
	router, _ := setupTestRouter(t)

	// Missing 'doc' parameter -> 400 Bad Request
	reqMissing := httptest.NewRequest(http.MethodGet, "/assinar", nil)
	recMissing := httptest.NewRecorder()
	router.ServeHTTP(recMissing, reqMissing)

	if recMissing.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing doc parameter, got %d", recMissing.Code)
	}

	// Valid 'doc' parameter -> 200 OK with HTML content
	reqValid := httptest.NewRequest(http.MethodGet, "/assinar?doc=Politica-RH.pdf", nil)
	recValid := httptest.NewRecorder()
	router.ServeHTTP(recValid, reqValid)

	if recValid.Code != http.StatusOK {
		t.Errorf("expected 200 OK for valid doc, got %d", recValid.Code)
	}
	if !strings.Contains(recValid.Body.String(), "Politica-RH.pdf") {
		t.Errorf("expected body to contain document name")
	}
}

func TestConfirmSignEndpoint(t *testing.T) {
	router, _ := setupTestRouter(t)

	// GET method not allowed on /confirmar
	reqGet := httptest.NewRequest(http.MethodGet, "/confirmar", nil)
	recGet := httptest.NewRecorder()
	router.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed for GET /confirmar, got %d", recGet.Code)
	}

	// POST without login cookie -> redirects to login
	form := url.Values{}
	form.Set("doc", "Politica-RH.pdf")
	reqPost := httptest.NewRequest(http.MethodPost, "/confirmar", strings.NewReader(form.Encode()))
	reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recPost := httptest.NewRecorder()
	router.ServeHTTP(recPost, reqPost)

	if recPost.Code != http.StatusSeeOther {
		t.Errorf("expected 303 See Other redirect to login, got %d", recPost.Code)
	}
	loc := recPost.Header().Get("Location")
	if !strings.Contains(loc, "/auth/login") {
		t.Errorf("expected redirect location to /auth/login, got: %s", loc)
	}
}

func TestAdminAuthAndExport(t *testing.T) {
	router, repo := setupTestRouter(t)
	ctx := context.Background()

	_ = repo.Create(ctx, &models.SignatureRecord{
		HashID:       "hash-export-1",
		DocumentName: "Contrato.pdf",
		UserName:     "Joao Silva",
		UserEmail:    "joao@empresa.com",
		Department:   "Juridico",
		SignedAt:     time.Now(),
	})

	sm := NewSessionManager("test-session-secret", "http://localhost:8080")

	// 0. Tampered/unsigned cookie accessing /admin -> redirect to login
	reqTampered := httptest.NewRequest(http.MethodGet, "/admin", nil)
	reqTampered.AddCookie(&http.Cookie{Name: "user_email", Value: "admin@empresa.com"})
	recTampered := httptest.NewRecorder()
	router.ServeHTTP(recTampered, reqTampered)

	if recTampered.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect for unsigned/tampered cookie, got %d", recTampered.Code)
	}

	// 1. Unauthorized user accessing /admin -> 403 Forbidden
	reqUnauth := httptest.NewRequest(http.MethodGet, "/admin", nil)
	reqUnauth.AddCookie(sm.SignedCookie("user_email", "normal_user@empresa.com"))
	recUnauth := httptest.NewRecorder()
	router.ServeHTTP(recUnauth, reqUnauth)

	if recUnauth.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for non-admin, got %d", recUnauth.Code)
	}

	// 2. Authorized admin accessing /admin -> 200 OK
	reqAdmin := httptest.NewRequest(http.MethodGet, "/admin", nil)
	reqAdmin.AddCookie(sm.SignedCookie("user_email", "admin@empresa.com"))
	recAdmin := httptest.NewRecorder()
	router.ServeHTTP(recAdmin, reqAdmin)

	if recAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 OK for admin, got %d", recAdmin.Code)
	}

	// 3. Export CSV
	reqCSV := httptest.NewRequest(http.MethodGet, "/admin/export?format=csv", nil)
	reqCSV.AddCookie(sm.SignedCookie("user_email", "admin@empresa.com"))
	recCSV := httptest.NewRecorder()
	router.ServeHTTP(recCSV, reqCSV)

	if recCSV.Code != http.StatusOK {
		t.Errorf("expected 200 for CSV export, got %d", recCSV.Code)
	}
	if !strings.Contains(recCSV.Header().Get("Content-Type"), "text/csv") {
		t.Errorf("expected text/csv header, got: %s", recCSV.Header().Get("Content-Type"))
	}
	if !strings.Contains(recCSV.Body.String(), "Contrato.pdf") {
		t.Errorf("expected CSV body to contain Contrato.pdf")
	}

	// 4. Export XLSX
	reqXLSX := httptest.NewRequest(http.MethodGet, "/admin/export?format=xlsx", nil)
	reqXLSX.AddCookie(sm.SignedCookie("user_email", "admin@empresa.com"))
	recXLSX := httptest.NewRecorder()
	router.ServeHTTP(recXLSX, reqXLSX)

	if recXLSX.Code != http.StatusOK {
		t.Errorf("expected 200 for XLSX export, got %d", recXLSX.Code)
	}
	if !strings.Contains(recXLSX.Header().Get("Content-Type"), "spreadsheetml.sheet") {
		t.Errorf("expected spreadsheetml header, got: %s", recXLSX.Header().Get("Content-Type"))
	}
}

func TestPanicRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	recovery := Recovery(logger)

	panickingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulated fatal error")
	})

	wrapped := recovery(panickingHandler)
	req := httptest.NewRequest(http.MethodGet, "/test-panic", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error on panic recovery, got %d", rec.Code)
	}
}
