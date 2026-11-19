package config

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	// Clean environment variables for test
	os.Unsetenv("PORT")
	os.Unsetenv("BASE_URL")
	os.Unsetenv("DB_PATH")
	os.Unsetenv("ADMIN_EMAILS")

	cfg := Load()
	if cfg.Server.Port != "8080" {
		t.Errorf("expected default port 8080, got %s", cfg.Server.Port)
	}
	if cfg.Server.BaseURL != "http://localhost:8080" {
		t.Errorf("expected default base URL http://localhost:8080, got %s", cfg.Server.BaseURL)
	}
	if cfg.Database.Path != "/app/data/signatures.db" {
		t.Errorf("expected default db path /app/data/signatures.db, got %s", cfg.Database.Path)
	}
	if cfg.Logging.Level != slog.LevelInfo {
		t.Errorf("expected default log level INFO, got %v", cfg.Logging.Level)
	}
	if !cfg.Maintenance.Enabled {
		t.Errorf("expected maintenance to be enabled by default")
	}
	if cfg.SMTP.LogoURL != "" {
		t.Errorf("expected empty default email logo URL, got %s", cfg.SMTP.LogoURL)
	}
	if cfg.SMTP.AccentColor != "#8BC74B" {
		t.Errorf("expected default accent color #8BC74B, got %s", cfg.SMTP.AccentColor)
	}
	if cfg.SMTP.SignatureName != "Zenith Signer" {
		t.Errorf("expected default signature name Zenith Signer, got %s", cfg.SMTP.SignatureName)
	}
}

func TestLoadCustom(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("BASE_URL", "https://assinador.empresa.com/")
	t.Setenv("ADMIN_EMAILS", "admin1@empresa.com, Admin2@empresa.com ")
	t.Setenv("LOG_LEVEL", "DEBUG")
	t.Setenv("HTTP_READ_TIMEOUT", "25s")
	t.Setenv("EMAIL_LOGO_URL", "https://example.com/logo.png")
	t.Setenv("EMAIL_ACCENT_COLOR", "C4A54E")
	t.Setenv("EMAIL_SIGNATURE_NAME", "STI - Grupo Lipetral")

	cfg := Load()
	if cfg.Server.Port != "9090" {
		t.Errorf("expected port 9090, got %s", cfg.Server.Port)
	}
	if cfg.Server.BaseURL != "https://assinador.empresa.com" {
		t.Errorf("expected trimmed base URL, got %s", cfg.Server.BaseURL)
	}
	if !cfg.Auth.AdminEmails["admin1@empresa.com"] || !cfg.Auth.AdminEmails["admin2@empresa.com"] {
		t.Errorf("expected parsed admin emails, got %v", cfg.Auth.AdminEmails)
	}
	if cfg.Logging.Level != slog.LevelDebug {
		t.Errorf("expected log level DEBUG, got %v", cfg.Logging.Level)
	}
	if cfg.Server.ReadTimeout != 25*time.Second {
		t.Errorf("expected read timeout 25s, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.SMTP.LogoURL != "https://example.com/logo.png" {
		t.Errorf("expected email logo URL, got %s", cfg.SMTP.LogoURL)
	}
	if cfg.SMTP.AccentColor != "#C4A54E" {
		t.Errorf("expected normalized accent color #C4A54E, got %s", cfg.SMTP.AccentColor)
	}
	if cfg.SMTP.SignatureName != "STI - Grupo Lipetral" {
		t.Errorf("expected custom signature name, got %s", cfg.SMTP.SignatureName)
	}
}
