package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"zenith-signer/internal/config"
)

const (
	backupPrefix     = "signatures-"
	backupSuffix     = ".db"
	backupTimeLayout = "20060102-150405.000"
)

// Backup writes a consistent, compacted snapshot of db into dir using
// SQLite's VACUUM INTO (safe while the application keeps writing in WAL mode).
// The snapshot is written to a temporary file, verified with quick_check and
// only then renamed to its final name, so a partial file is never left behind
// as a valid backup. It returns the path of the new backup file.
func Backup(ctx context.Context, db *sql.DB, dir string, now time.Time) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("failed to create backup directory %s: %w", dir, err)
	}

	name := backupPrefix + now.Format(backupTimeLayout) + backupSuffix
	final := filepath.Join(dir, name)
	tmp := final + ".tmp"
	_ = os.Remove(tmp)

	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("VACUUM INTO failed: %w", err)
	}

	if err := verifyBackupFile(ctx, tmp); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}

	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("failed to finalize backup file: %w", err)
	}
	return final, nil
}

// verifyBackupFile opens the snapshot read-only and runs PRAGMA quick_check.
func verifyBackupFile(ctx context.Context, path string) error {
	bdb, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return fmt.Errorf("failed to open backup for verification: %w", err)
	}
	defer bdb.Close()

	var result string
	if err := bdb.QueryRowContext(ctx, "PRAGMA quick_check;").Scan(&result); err != nil {
		return fmt.Errorf("backup verification failed: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("backup verification failed: quick_check returned %q", result)
	}
	return nil
}

// ListBackups returns backup files in dir, oldest first.
func ListBackups(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(n, backupPrefix) && strings.HasSuffix(n, backupSuffix) {
			files = append(files, filepath.Join(dir, n))
		}
	}
	// The timestamp layout sorts lexicographically in chronological order.
	sort.Strings(files)
	return files, nil
}

// PruneBackups keeps only the newest `keep` backups in dir and returns the removed files.
// Files that do not follow the backup naming pattern are never touched.
func PruneBackups(dir string, keep int) ([]string, error) {
	if keep < 1 {
		keep = 1
	}
	files, err := ListBackups(dir)
	if err != nil {
		return nil, err
	}
	if len(files) <= keep {
		return nil, nil
	}
	var removed []string
	for _, f := range files[:len(files)-keep] {
		if err := os.Remove(f); err != nil {
			return removed, fmt.Errorf("failed to remove old backup %s: %w", f, err)
		}
		removed = append(removed, f)
	}
	return removed, nil
}

// RunBackupCycle creates a backup and prunes old ones, logging the outcome.
func RunBackupCycle(ctx context.Context, db *sql.DB, cfg config.BackupConfig, logger *slog.Logger) error {
	cycleCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	start := time.Now()
	path, err := Backup(cycleCtx, db, cfg.Dir, start)
	if err != nil {
		logger.Error("database backup failed", slog.String("dir", cfg.Dir), slog.String("error", err.Error()))
		return err
	}

	var size int64
	if info, statErr := os.Stat(path); statErr == nil {
		size = info.Size()
	}
	logger.Info("database backup created",
		slog.String("file", path),
		slog.Int64("bytes", size),
		slog.Duration("duration", time.Since(start)),
	)

	removed, err := PruneBackups(cfg.Dir, cfg.Retention)
	if err != nil {
		logger.Warn("failed to prune old backups", slog.String("error", err.Error()))
	}
	for _, f := range removed {
		logger.Info("old database backup removed", slog.String("file", f))
	}
	return nil
}

// StartBackupWorker takes a backup shortly after startup and then every cfg.Interval.
func StartBackupWorker(ctx context.Context, db *sql.DB, cfg config.BackupConfig, logger *slog.Logger) {
	if cfg.Interval < time.Minute {
		cfg.Interval = 24 * time.Hour
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}
	logger.Info("starting database backup worker",
		slog.String("dir", cfg.Dir),
		slog.Duration("interval", cfg.Interval),
		slog.Int("retention", cfg.Retention),
	)

	go func() {
		// Initial backup right after startup, so a fresh deploy is covered immediately.
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.InitialDelay):
			_ = RunBackupCycle(ctx, db, cfg, logger)
		}

		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				logger.Info("stopping database backup worker")
				return
			case <-ticker.C:
				_ = RunBackupCycle(ctx, db, cfg, logger)
			}
		}
	}()
}
