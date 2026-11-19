package handlers

import (
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"zenith-signer/internal/database"
	"zenith-signer/internal/models"
)

type HomeHandler struct {
	repo    database.Repository
	tmpl    *template.Template
	appName string
	logger  *slog.Logger
}

func NewHomeHandler(repo database.Repository, tmpl *template.Template, appName string, logger *slog.Logger) *HomeHandler {
	if strings.TrimSpace(appName) == "" {
		appName = "Zenith Signer"
	}
	return &HomeHandler{
		repo:    repo,
		tmpl:    tmpl,
		appName: appName,
		logger:  logger,
	}
}

func (h *HomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	hashQuery := strings.TrimSpace(r.URL.Query().Get("hash"))
	var record *models.SignatureRecord
	searched := hashQuery != ""

	if searched {
		var err error
		record, err = h.repo.GetByHash(r.Context(), hashQuery)
		if err != nil {
			h.logger.Error("failed to verify signature hash",
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("error", err.Error()),
			)
			http.Error(w, "Erro ao verificar assinatura: "+err.Error(), http.StatusInternalServerError)
			return
		}

		h.logger.Info("public hash verification",
			slog.String("request_id", RequestIDFromContext(r.Context())),
			slog.Bool("found", record != nil),
			slog.String("ip", extractClientIP(r)),
		)
	}

	data := map[string]interface{}{
		"AppName":   h.appName,
		"HashQuery": hashQuery,
		"Searched":  searched,
		"Record":    record,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, data)
}
