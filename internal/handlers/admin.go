package handlers

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"zenith-signer/internal/auth"
	"zenith-signer/internal/database"
	"zenith-signer/internal/models"
)

const adminPageSize = 50

type AdminHandler struct {
	repo    database.Repository
	authSvc auth.Service
	tmpl    *template.Template
	appName string
	session *SessionManager
	logger  *slog.Logger
}

func NewAdminHandler(repo database.Repository, authSvc auth.Service, tmpl *template.Template, appName string, session *SessionManager, logger *slog.Logger) *AdminHandler {
	if strings.TrimSpace(appName) == "" {
		appName = "Zenith Signer"
	}
	return &AdminHandler{
		repo:    repo,
		authSvc: authSvc,
		tmpl:    tmpl,
		appName: appName,
		session: session,
		logger:  logger,
	}
}

func (h *AdminHandler) checkAdminAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	email := h.session.GetCookie(r, "user_email")
	if email == "" {
		http.Redirect(w, r, "/auth/login?return="+url.QueryEscape(r.RequestURI), http.StatusSeeOther)
		return "", false
	}

	userEmail := strings.ToLower(email)
	if !h.authSvc.IsAdmin(userEmail) {
		h.logger.Warn("admin access denied",
			slog.String("email", userEmail),
			slog.String("ip", extractClientIP(r)),
			slog.String("request_id", RequestIDFromContext(r.Context())),
		)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Acesso restrito: Seu e-mail (" + userEmail + ") não está autorizado."))
		return "", false
	}

	return userEmail, true
}

func extractFilterCriteria(r *http.Request) models.FilterCriteria {
	return models.FilterCriteria{
		Document: strings.TrimSpace(r.URL.Query().Get("doc")),
		User:     strings.TrimSpace(r.URL.Query().Get("user")),
		Dept:     strings.TrimSpace(r.URL.Query().Get("dept")),
		Job:      strings.TrimSpace(r.URL.Query().Get("job")),
		Hash:     strings.TrimSpace(r.URL.Query().Get("hash")),
		IP:       strings.TrimSpace(r.URL.Query().Get("ip")),
		DateFrom: strings.TrimSpace(r.URL.Query().Get("date_from")),
		DateTo:   strings.TrimSpace(r.URL.Query().Get("date_to")),
	}
}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userEmail, ok := h.checkAdminAuth(w, r)
	if !ok {
		return
	}

	filter := extractFilterCriteria(r)
	records, err := h.repo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to query admin records",
			slog.String("email", userEmail),
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.String("error", err.Error()),
		)
		http.Error(w, "Erro ao buscar registros: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.logger.Info("admin panel accessed",
		slog.String("email", userEmail),
		slog.Int("records_count", len(records)),
		slog.String("doc_filter", filter.Document),
		slog.String("request_id", RequestIDFromContext(r.Context())),
	)

	uniqueDocs := make(map[string]struct{})
	uniqueUsers := make(map[string]struct{})
	for _, rec := range records {
		uniqueDocs[rec.DocumentName] = struct{}{}
		uniqueUsers[strings.ToLower(rec.UserEmail)] = struct{}{}
	}

	totalCount := len(records)
	totalPages := (totalCount + adminPageSize - 1) / adminPageSize
	if totalPages < 1 {
		totalPages = 1
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	startIdx := (page - 1) * adminPageSize
	endIdx := startIdx + adminPageSize
	if startIdx > totalCount {
		startIdx = totalCount
	}
	if endIdx > totalCount {
		endIdx = totalCount
	}
	pagedRecords := records[startIdx:endIdx]

	q := r.URL.Query()
	q.Del("format")
	q.Del("page")
	baseQuery := q.Encode()

	data := map[string]interface{}{
		"AppName":        h.appName,
		"UserEmail":      userEmail,
		"Records":        pagedRecords,
		"FilterDoc":      filter.Document,
		"FilterUser":     filter.User,
		"FilterDept":     filter.Dept,
		"FilterJob":      filter.Job,
		"FilterHash":     filter.Hash,
		"FilterIP":       filter.IP,
		"FilterDateFrom": filter.DateFrom,
		"FilterDateTo":   filter.DateTo,
		"QueryString":    baseQuery,
		"Count":          totalCount,
		"UniqueDocs":     len(uniqueDocs),
		"UniqueUsers":    len(uniqueUsers),
		"Page":           page,
		"TotalPages":     totalPages,
		"HasPrev":        page > 1,
		"HasNext":        page < totalPages,
		"PrevPage":       page - 1,
		"NextPage":       page + 1,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, data)
}
