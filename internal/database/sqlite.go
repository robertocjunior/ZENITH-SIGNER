package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"zenith-signer/internal/config"

	_ "github.com/mattn/go-sqlite3"
)

// Open initializes and configures a SQLite connection with production-grade settings for 24/7 reliability.
func Open(cfg config.DatabaseConfig, logger *slog.Logger) (*sql.DB, error) {
	// Ensure parent directory exists for file-based SQLite databases
	if cfg.Path != ":memory:" && !strings.HasPrefix(cfg.Path, "file:") {
		dir := filepath.Dir(cfg.Path)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
			}
		}
	}

	// Build connection string with pragmas
	dsn := cfg.Path
	params := url.Values{}
	params.Set("_journal_mode", "WAL")
	params.Set("_busy_timeout", fmt.Sprintf("%d", cfg.BusyTimeoutMs))
	params.Set("_synchronous", "NORMAL")
	params.Set("_foreign_keys", "ON")
	params.Set("_cache_size", "-20000") // 20MB in-memory cache

	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	dsn = fmt.Sprintf("%s%s%s", dsn, separator, params.Encode())

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Concurrency tuning for SQLite WAL mode
	// SQLite supports multiple readers concurrently. Setting MaxOpenConns allows concurrent reads
	// while busy_timeout prevents lock contention during writes.
	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 10
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 5
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Verify connectivity
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	logger.Info("connected to sqlite database",
		slog.String("path", cfg.Path),
		slog.Int("max_open_conns", maxOpen),
		slog.Int("max_idle_conns", maxIdle),
	)

	return db, nil
}

// Migrate executes schema migrations idempotently.
func Migrate(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	migrationQuery := `
	CREATE TABLE IF NOT EXISTS signatures (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hash_id TEXT UNIQUE NOT NULL,
		document_name TEXT NOT NULL,
		user_name TEXT NOT NULL,
		user_email TEXT NOT NULL,
		department TEXT,
		job_title TEXT,
		office_location TEXT,
		signed_at DATETIME NOT NULL,
		user_agent TEXT,
		ip_address TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_signatures_doc_email ON signatures(document_name, user_email);
	CREATE INDEX IF NOT EXISTS idx_signatures_hash ON signatures(hash_id);
	CREATE INDEX IF NOT EXISTS idx_signatures_signed_at ON signatures(signed_at DESC);
	`

	if _, err := db.ExecContext(ctx, migrationQuery); err != nil {
		return fmt.Errorf("failed to run database migrations: %w", err)
	}

	if err := ensureUniqueSignaturePerUser(ctx, db, logger); err != nil {
		return err
	}
	if err := migrateDocumentVersioning(ctx, db, logger); err != nil {
		return err
	}

	logger.Info("database migrations executed successfully")
	return nil
}

const uniqueDocEmailIndex = "ux_signatures_doc_email"

// ensureUniqueSignaturePerUser enforces one signature per (document, user).
//
// Databases created before this constraint may already contain duplicates
// (e.g. double clicks). Instead of failing the migration or deleting audit
// data, every duplicate except the first signature (lowest id) is moved to
// signatures_duplicates, which stays queryable so receipts already e-mailed
// with those hashes can still be verified. Runs once, in a single transaction.
func ensureUniqueSignaturePerUser(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	const archiveDDL = `
	CREATE TABLE IF NOT EXISTS signatures_duplicates (
		id INTEGER PRIMARY KEY,
		hash_id TEXT NOT NULL,
		document_name TEXT NOT NULL,
		user_name TEXT NOT NULL,
		user_email TEXT NOT NULL,
		department TEXT,
		job_title TEXT,
		office_location TEXT,
		signed_at DATETIME NOT NULL,
		user_agent TEXT,
		ip_address TEXT,
		archived_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_signatures_duplicates_hash ON signatures_duplicates(hash_id);
	`
	if _, err := db.ExecContext(ctx, archiveDDL); err != nil {
		return fmt.Errorf("failed to create signatures_duplicates table: %w", err)
	}

	// Skip when either the original constraint or its versioned successor exists:
	// once documents are versioned a user legitimately has one row per version.
	var exists int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN (?, ?)",
		uniqueDocEmailIndex, uniqueDocEmailVersionIndex,
	).Scan(&exists); err != nil {
		return fmt.Errorf("failed to inspect indexes: %w", err)
	}
	if exists > 0 {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin unique-signature migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const duplicatesFilter = `id NOT IN (SELECT MIN(id) FROM signatures GROUP BY document_name, user_email)`

	res, err := tx.ExecContext(ctx, `
	INSERT INTO signatures_duplicates (
		id, hash_id, document_name, user_name, user_email, department, job_title,
		office_location, signed_at, user_agent, ip_address, archived_at
	)
	SELECT id, hash_id, document_name, user_name, user_email, department, job_title,
	       office_location, signed_at, user_agent, ip_address, CURRENT_TIMESTAMP
	FROM signatures WHERE `+duplicatesFilter)
	if err != nil {
		return fmt.Errorf("failed to archive duplicate signatures: %w", err)
	}
	moved, _ := res.RowsAffected()

	if _, err := tx.ExecContext(ctx, `DELETE FROM signatures WHERE `+duplicatesFilter); err != nil {
		return fmt.Errorf("failed to remove archived duplicate signatures: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"CREATE UNIQUE INDEX "+uniqueDocEmailIndex+" ON signatures(document_name, user_email)",
	); err != nil {
		return fmt.Errorf("failed to create unique signature index: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit unique-signature migration: %w", err)
	}

	if moved > 0 {
		logger.Warn("duplicate signatures found and archived in signatures_duplicates (kept the first signature of each user per document)",
			slog.Int64("archived", moved))
	}
	logger.Info("unique signature per user and document enforced", slog.String("index", uniqueDocEmailIndex))
	return nil
}

const uniqueDocEmailVersionIndex = "ux_signatures_doc_email_version"

// migrateDocumentVersioning adds registered documents, their versions and the
// audit-chain columns. Every step is idempotent.
func migrateDocumentVersioning(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	const ddl = `
	CREATE TABLE IF NOT EXISTS documents (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		doc_key TEXT NOT NULL UNIQUE,
		outline_id TEXT NOT NULL UNIQUE,
		title TEXT NOT NULL,
		outline_url TEXT NOT NULL DEFAULT '',
		collection_id TEXT NOT NULL DEFAULT '',
		current_version_id INTEGER NOT NULL DEFAULT 0,
		required_version_id INTEGER NOT NULL DEFAULT 0,
		embed_status TEXT NOT NULL DEFAULT 'manual',
		active INTEGER NOT NULL DEFAULT 1,
		created_by TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS document_versions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		document_id INTEGER NOT NULL REFERENCES documents(id),
		version_no INTEGER NOT NULL,
		outline_revision INTEGER NOT NULL DEFAULT 0,
		title TEXT NOT NULL DEFAULT '',
		content_hash TEXT NOT NULL,
		content TEXT NOT NULL,
		decision TEXT NOT NULL,
		decided_by TEXT NOT NULL DEFAULT '',
		decided_at DATETIME,
		created_at DATETIME NOT NULL,
		UNIQUE(document_id, version_no)
	);
	CREATE INDEX IF NOT EXISTS idx_document_versions_doc ON document_versions(document_id, id DESC);
	`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create document tables: %w", err)
	}

	columns := []struct{ name, ddl string }{
		{"document_version_id", "ALTER TABLE signatures ADD COLUMN document_version_id INTEGER NOT NULL DEFAULT 0"},
		{"content_hash", "ALTER TABLE signatures ADD COLUMN content_hash TEXT NOT NULL DEFAULT ''"},
		{"prev_hash", "ALTER TABLE signatures ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"},
		{"chain_seq", "ALTER TABLE signatures ADD COLUMN chain_seq INTEGER"},
	}
	for _, c := range columns {
		has, err := hasColumn(ctx, db, "signatures", c.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.ExecContext(ctx, c.ddl); err != nil {
				return fmt.Errorf("failed to add signatures.%s: %w", c.name, err)
			}
			logger.Info("database column added", slog.String("column", "signatures."+c.name))
		}
	}

	const indexes = `
	CREATE UNIQUE INDEX IF NOT EXISTS ` + uniqueDocEmailVersionIndex + ` ON signatures(document_name, user_email, document_version_id);
	DROP INDEX IF EXISTS ` + uniqueDocEmailIndex + `;
	CREATE UNIQUE INDEX IF NOT EXISTS ux_signatures_chain_seq ON signatures(chain_seq);
	CREATE INDEX IF NOT EXISTS idx_signatures_version ON signatures(document_version_id);
	`
	if _, err := db.ExecContext(ctx, indexes); err != nil {
		return fmt.Errorf("failed to create versioning indexes: %w", err)
	}
	return nil
}

func hasColumn(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return false, fmt.Errorf("failed to inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
