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
	if cfg.Server.AppName != "Zenith Signer" {
		t.Errorf("expected default app name Zenith Signer, got %s", cfg.Server.AppName)
	}
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
	t.Setenv("APP_NAME", "Grupo Lipetral")
	t.Setenv("PORT", "9090")
	t.Setenv("BASE_URL", "https://assinador.empresa.com/")
	t.Setenv("ADMIN_EMAILS", "admin1@empresa.com, Admin2@empresa.com ")
	t.Setenv("LOG_LEVEL", "DEBUG")
	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("LOG_FILE", "/app/data/zenith-signer.log")
	t.Setenv("HTTP_READ_TIMEOUT", "25s")
	t.Setenv("EMAIL_LOGO_URL", "https://example.com/logo.png")
	t.Setenv("EMAIL_ACCENT_COLOR", "C4A54E")
	t.Setenv("EMAIL_SIGNATURE_NAME", "STI - Grupo Lipetral")

	cfg := Load()
	if cfg.Server.AppName != "Grupo Lipetral" {
		t.Errorf("expected app name Grupo Lipetral, got %s", cfg.Server.AppName)
	}
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
	if cfg.Logging.Format != "json" {
		t.Errorf("expected log format json, got %s", cfg.Logging.Format)
	}
	if cfg.Logging.FilePath != "/app/data/zenith-signer.log" {
		t.Errorf("expected log file /app/data/zenith-signer.log, got %s", cfg.Logging.FilePath)
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

func TestLoadSecurityLists(t *testing.T) {
	t.Setenv("ALLOWED_EMBED_ORIGINS", " https://wiki.empresa.com.br , https://intranet.empresa.com.br,,")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 172.17.0.1 ")

	cfg := Load()
	wantOrigins := []string{"https://wiki.empresa.com.br", "https://intranet.empresa.com.br"}
	if len(cfg.Server.AllowedEmbedOrigins) != len(wantOrigins) {
		t.Fatalf("expected %v, got %v", wantOrigins, cfg.Server.AllowedEmbedOrigins)
	}
	for i, o := range wantOrigins {
		if cfg.Server.AllowedEmbedOrigins[i] != o {
			t.Errorf("origin[%d]: expected %s, got %s", i, o, cfg.Server.AllowedEmbedOrigins[i])
		}
	}
	if len(cfg.Server.TrustedProxies) != 2 || cfg.Server.TrustedProxies[1] != "172.17.0.1" {
		t.Errorf("unexpected trusted proxies: %v", cfg.Server.TrustedProxies)
	}
}

func TestLoadSecurityListsDefaultEmpty(t *testing.T) {
	os.Unsetenv("ALLOWED_EMBED_ORIGINS")
	os.Unsetenv("TRUSTED_PROXIES")
	cfg := Load()
	if len(cfg.Server.AllowedEmbedOrigins) != 0 || len(cfg.Server.TrustedProxies) != 0 {
		t.Errorf("expected empty security lists by default")
	}
}

func TestLoadBackupConfig(t *testing.T) {
	os.Unsetenv("BACKUP_ENABLED")
	os.Unsetenv("BACKUP_DIR")
	os.Unsetenv("BACKUP_INTERVAL")
	os.Unsetenv("BACKUP_RETENTION")
	t.Setenv("DB_PATH", "/srv/zenith/signatures.db")

	cfg := Load()
	if !cfg.Backup.Enabled {
		t.Errorf("backups should be enabled by default")
	}
	if cfg.Backup.Dir != "/srv/zenith/backups" {
		t.Errorf("default backup dir should sit next to the DB, got %s", cfg.Backup.Dir)
	}
	if cfg.Backup.Interval != 24*time.Hour || cfg.Backup.Retention != 7 {
		t.Errorf("unexpected defaults: interval=%v retention=%d", cfg.Backup.Interval, cfg.Backup.Retention)
	}

	t.Setenv("BACKUP_ENABLED", "false")
	t.Setenv("BACKUP_DIR", "/mnt/nas/zenith")
	t.Setenv("BACKUP_INTERVAL", "6h")
	t.Setenv("BACKUP_RETENTION", "30")
	cfg = Load()
	if cfg.Backup.Enabled || cfg.Backup.Dir != "/mnt/nas/zenith" || cfg.Backup.Interval != 6*time.Hour || cfg.Backup.Retention != 30 {
		t.Errorf("custom backup config not applied: %+v", cfg.Backup)
	}
}
