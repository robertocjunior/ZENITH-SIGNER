package database

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zenith-signer/internal/config"
	"zenith-signer/internal/models"
)

func openFileDB(t *testing.T) (*sql.DB, Repository, string) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	db, err := Open(config.DatabaseConfig{Path: filepath.Join(dir, "signatures.db"), BusyTimeoutMs: 5000}, logger)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(context.Background(), db, logger); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db, NewRepository(db), dir
}

func seed(t *testing.T, repo Repository, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := repo.Create(context.Background(), &models.SignatureRecord{
			HashID:       fmt.Sprintf("hash-%d", i),
			DocumentName: "Politica-RH",
			UserName:     "Usuario",
			UserEmail:    fmt.Sprintf("user%d@empresa.com", i),
			SignedAt:     time.Now(),
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func countRows(t *testing.T, path string) int {
	t.Helper()
	bdb, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer bdb.Close()
	var n int
	if err := bdb.QueryRow("SELECT COUNT(*) FROM signatures").Scan(&n); err != nil {
		t.Fatalf("count backup rows: %v", err)
	}
	return n
}

func TestBackupCreatesVerifiedSnapshot(t *testing.T) {
	db, repo, dir := openFileDB(t)
	seed(t, repo, 25)

	backupDir := filepath.Join(dir, "backups")
	path, err := Backup(context.Background(), db, backupDir, time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if filepath.Base(path) != "signatures-20261123-030000.000.db" {
		t.Errorf("unexpected backup name: %s", path)
	}
	if got := countRows(t, path); got != 25 {
		t.Errorf("backup should contain 25 rows, got %d", got)
	}

	// Writes after the backup must not affect the snapshot.
	seed2 := &models.SignatureRecord{HashID: "late", DocumentName: "X", UserName: "U", UserEmail: "late@empresa.com", SignedAt: time.Now()}
	if err := repo.Create(context.Background(), seed2); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := countRows(t, path); got != 25 {
		t.Errorf("snapshot changed after later writes: %d rows", got)
	}

	leftovers, _ := filepath.Glob(filepath.Join(backupDir, "*.tmp"))
	if len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
}

func TestBackupFailsCleanlyOnInvalidDir(t *testing.T) {
	db, _, dir := openFileDB(t)
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Backup(context.Background(), db, notADir, time.Now()); err == nil {
		t.Fatalf("expected error when backup dir is a regular file")
	}
}

func TestBackupDoesNotOverwriteExistingFile(t *testing.T) {
	db, _, dir := openFileDB(t)
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := Backup(context.Background(), db, dir, ts); err != nil {
		t.Fatalf("first backup: %v", err)
	}
	// Same timestamp -> VACUUM INTO target exists only as final name; tmp is fresh,
	// so the call must succeed and still leave exactly one valid file.
	if _, err := Backup(context.Background(), db, dir, ts); err != nil {
		t.Fatalf("second backup with same timestamp: %v", err)
	}
	files, _ := ListBackups(dir)
	if len(files) != 1 {
		t.Errorf("expected 1 backup file, got %v", files)
	}
}

func TestPruneBackupsKeepsNewestAndIgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"signatures-20261101-030000.000.db",
		"signatures-20261102-030000.000.db",
		"signatures-20261103-030000.000.db",
		"signatures-20261104-030000.000.db",
		"signatures-20261105-030000.000.db",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Files that are not backups must never be removed.
	for _, n := range []string{"signatures.db", "notes.txt", "signatures-manual.db.bak"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := PruneBackups(dir, 2)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(removed) != 3 {
		t.Errorf("expected 3 removed, got %v", removed)
	}

	remaining, _ := ListBackups(dir)
	if len(remaining) != 2 ||
		!strings.HasSuffix(remaining[0], names[3]) ||
		!strings.HasSuffix(remaining[1], names[4]) {
		t.Errorf("expected the 2 newest backups to remain, got %v", remaining)
	}
	for _, n := range []string{"signatures.db", "notes.txt", "signatures-manual.db.bak"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("non-backup file %s was removed", n)
		}
	}

	// keep < 1 is treated as 1 (never delete every backup).
	if _, err := PruneBackups(dir, 0); err != nil {
		t.Fatal(err)
	}
	if remaining, _ := ListBackups(dir); len(remaining) != 1 {
		t.Errorf("expected 1 backup with keep=0, got %v", remaining)
	}
}

func TestListBackupsMissingDir(t *testing.T) {
	files, err := ListBackups(filepath.Join(t.TempDir(), "nope"))
	if err != nil || len(files) != 0 {
		t.Errorf("missing dir should yield no files and no error, got %v %v", files, err)
	}
}

func TestBackupWorkerRunsAndAppliesRetention(t *testing.T) {
	db, repo, dir := openFileDB(t)
	seed(t, repo, 3)
	backupDir := filepath.Join(dir, "backups")

	// Pre-existing old backups that should be pruned by the worker.
	if err := os.MkdirAll(backupDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"signatures-20200101-000000.000.db", "signatures-20200102-000000.000.db"} {
		if err := os.WriteFile(filepath.Join(backupDir, n), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	StartBackupWorker(ctx, db, config.BackupConfig{
		Dir:          backupDir,
		Interval:     time.Hour,
		Retention:    1,
		InitialDelay: 0,
		Timeout:      time.Minute,
	}, logger)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		files, _ := ListBackups(backupDir)
		if len(files) == 1 && !strings.Contains(files[0], "2020") {
			if got := countRows(t, files[0]); got != 3 {
				t.Errorf("worker backup should contain 3 rows, got %d", got)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	files, _ := ListBackups(backupDir)
	t.Fatalf("worker did not create a backup and prune old ones in time; files: %v", files)
}
