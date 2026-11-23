package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"zenith-signer/internal/auth"
	"zenith-signer/internal/config"
	"zenith-signer/internal/database"
	"zenith-signer/internal/email"
	"zenith-signer/internal/handlers"
	"zenith-signer/internal/service"
)

// RunWithTemplates initializes all dependencies and runs the HTTP server with 24/7 reliability patterns.
func RunWithTemplates(templateFS fs.FS) {
	cfg := config.Load()
	logger, closeLogFile := setupLogger(cfg.Logging)
	defer closeLogFile()
	slog.SetDefault(logger)

	startTime := time.Now()
	logger.Info("starting zenith-signer service",
		slog.String("port", cfg.Server.Port),
		slog.String("base_url", cfg.Server.BaseURL),
		slog.String("db_path", cfg.Database.Path),
		slog.String("log_level", cfg.Logging.Level.String()),
	)

	if len(cfg.Server.AllowedEmbedOrigins) == 0 {
		logger.Warn("ALLOWED_EMBED_ORIGINS is empty: /assinar can only be embedded by this application itself; set it to your wiki/intranet origin(s)")
	}
	if len(cfg.Server.TrustedProxies) == 0 {
		logger.Warn("TRUSTED_PROXIES is empty: X-Forwarded-For/X-Real-IP are ignored and the TCP peer IP is recorded; set it when running behind a reverse proxy")
	}

	// Initialize database
	db, err := database.Open(cfg.Database, logger)
	if err != nil {
		logger.Error("fatal: failed to initialize sqlite database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer db.Close()

	// Execute database migrations
	initCtx, initCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := database.Migrate(initCtx, db, logger); err != nil {
		initCancel()
		logger.Error("fatal: database migration failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	initCancel()

	// Context for background workers and graceful shutdown
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	// Start 24/7 background self-healing and maintenance worker (WAL checkpoints, integrity checks)
	if cfg.Maintenance.Enabled {
		database.StartMaintenanceWorker(appCtx, db, cfg.Maintenance.Interval, logger)
	}

	// Initialize application layer services
	repo := database.NewRepository(db)
	authSvc := auth.NewService(cfg.Auth)
	emailSender := email.NewSender(cfg.SMTP, logger)
	signerSvc := service.NewSignerService(repo, emailSender, logger)

	// Build HTTP router and middleware chain
	router, err := handlers.NewRouter(handlers.RouterParams{
		Config:     cfg,
		Repo:       repo,
		DB:         db,
		AuthSvc:    authSvc,
		SignerSvc:  signerSvc,
		TemplateFS: templateFS,
		Logger:     logger,
		StartTime:  startTime,
	})
	if err != nil {
		logger.Error("fatal: failed to configure HTTP router", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Configure HTTP server with production-grade timeouts
	server := &http.Server{
		Addr:              ":" + cfg.Server.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}

	// Channel to listen for OS signals (SIGINT, SIGTERM)
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("server listening for requests", slog.String("address", server.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- fmt.Errorf("http server failure: %w", err)
		}
	}()

	// Wait for shutdown signal or fatal server error
	select {
	case err := <-serverErrors:
		logger.Error("server encountered fatal runtime error", slog.String("error", err.Error()))
		os.Exit(1)

	case sig := <-shutdownChan:
		logger.Info("received shutdown signal, initiating graceful drain", slog.String("signal", sig.String()))

		// Stop background workers
		appCancel()

		// Allow active HTTP requests to complete within configured shutdown timeout
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed, forcing close", slog.String("error", err.Error()))
			_ = server.Close()
		}

		// Wait for any in-flight background receipt emails to complete
		if err := signerSvc.Wait(shutdownCtx); err != nil {
			logger.Warn("background email tasks did not finish before shutdown timeout", slog.String("error", err.Error()))
		}

		// Flush WAL pages to disk before termination
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := database.CheckpointWAL(flushCtx, db); err != nil {
			logger.Warn("final wal checkpoint before exit encountered error", slog.String("error", err.Error()))
		}
		flushCancel()

		logger.Info("server shut down gracefully")
	}
}

func setupLogger(cfg config.LoggingConfig) (*slog.Logger, func()) {
	opts := &slog.HandlerOptions{
		Level: cfg.Level,
	}

	var output io.Writer = os.Stdout
	cleanup := func() {}
	var fileErr error

	if cfg.FilePath != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0755); err != nil {
			fileErr = err
		} else if f, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err != nil {
			fileErr = err
		} else {
			output = io.MultiWriter(os.Stdout, f)
			cleanup = func() { _ = f.Close() }
		}
	}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(output, opts)
	} else {
		handler = slog.NewTextHandler(output, opts)
	}

	logger := slog.New(handler)
	if fileErr != nil {
		logger.Warn("failed to open log file, falling back to stdout only",
			slog.String("log_file", cfg.FilePath),
			slog.String("error", fileErr.Error()),
		)
	}

	return logger, cleanup
}
