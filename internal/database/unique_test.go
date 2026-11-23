package database

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"zenith-signer/internal/config"
	"zenith-signer/internal/models"
)

// legacySchema is the signatures table as created before the unique constraint.
const legacySchema = `
CREATE TABLE signatures (
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
CREATE INDEX idx_signatures_doc_email ON signatures(document_name, user_email);
`

func TestMigrateArchivesLegacyDuplicates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := Open(config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "legacy.db"), BusyTimeoutMs: 5000}, logger)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()

	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	insert := `INSERT INTO signatures (hash_id, document_name, user_name, user_email, signed_at, user_agent, ip_address) VALUES (?, ?, 'U', ?, ?, 'ua', '1.1.1.1')`
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	rows := []struct{ hash, doc, email string }{
		{"h1", "DocA", "maria@empresa.com"}, // kept (first)
		{"h2", "DocA", "maria@empresa.com"}, // duplicate (double click)
		{"h3", "DocA", "maria@empresa.com"}, // duplicate
		{"h4", "DocA", "joao@empresa.com"},  // kept
		{"h5", "DocB", "maria@empresa.com"}, // kept (other doc)
		{"h6", "DocB", "maria@empresa.com"}, // duplicate
	}
	for i, r := range rows {
		if _, err := db.Exec(insert, r.hash, r.doc, r.email, base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	if err := Migrate(ctx, db, logger); err != nil {
		t.Fatalf("migrate on legacy db with duplicates must succeed: %v", err)
	}

	var kept, archived int
	_ = db.QueryRow("SELECT COUNT(*) FROM signatures").Scan(&kept)
	_ = db.QueryRow("SELECT COUNT(*) FROM signatures_duplicates").Scan(&archived)
	if kept != 3 || archived != 3 {
		t.Fatalf("expected 3 kept / 3 archived, got %d / %d", kept, archived)
	}

	repo := NewRepository(db)
	first, _ := repo.GetByDocAndEmail(ctx, "DocA", "maria@empresa.com")
	if first == nil || first.HashID != "h1" {
		t.Errorf("the first signature must be kept, got %+v", first)
	}

	// Receipts e-mailed with archived hashes must still verify.
	for _, h := range []string{"h2", "h3", "h6"} {
		rec, err := repo.GetByHash(ctx, h)
		if err != nil || rec == nil || rec.HashID != h {
			t.Errorf("archived hash %s should still be verifiable, got %+v err=%v", h, rec, err)
		}
	}
	if rec, _ := repo.GetByHash(ctx, "does-not-exist"); rec != nil {
		t.Errorf("unknown hash must not be found")
	}

	// Constraint is now active.
	err = repo.Create(ctx, &models.SignatureRecord{HashID: "h7", DocumentName: "DocA", UserName: "U", UserEmail: "maria@empresa.com", SignedAt: time.Now()})
	if !errors.Is(err, ErrAlreadySigned) {
		t.Errorf("expected ErrAlreadySigned after migration, got %v", err)
	}

	// Idempotent: running again changes nothing.
	if err := Migrate(ctx, db, logger); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	_ = db.QueryRow("SELECT COUNT(*) FROM signatures_duplicates").Scan(&archived)
	if archived != 3 {
		t.Errorf("second migration must not archive again, got %d", archived)
	}
}

func TestCreateDuplicateReturnsErrAlreadySigned(t *testing.T) {
	_, repo, _ := openFileDB(t)
	ctx := context.Background()

	first := &models.SignatureRecord{HashID: "a", DocumentName: "Doc", UserName: "U", UserEmail: "Maria@Empresa.com", SignedAt: time.Now()}
	if err := repo.Create(ctx, first); err != nil || first.ID == 0 {
		t.Fatalf("first create: id=%d err=%v", first.ID, err)
	}

	// Same doc + same e-mail (different case) must conflict.
	dup := &models.SignatureRecord{HashID: "b", DocumentName: "Doc", UserName: "U", UserEmail: "maria@empresa.com", SignedAt: time.Now()}
	if err := repo.Create(ctx, dup); !errors.Is(err, ErrAlreadySigned) {
		t.Fatalf("expected ErrAlreadySigned, got %v", err)
	}
	if dup.ID != 0 {
		t.Errorf("conflicting record must not receive an ID, got %d", dup.ID)
	}

	// Other user or other doc is fine.
	if err := repo.Create(ctx, &models.SignatureRecord{HashID: "c", DocumentName: "Doc", UserName: "U", UserEmail: "joao@empresa.com", SignedAt: time.Now()}); err != nil {
		t.Errorf("other user should sign: %v", err)
	}
	if err := repo.Create(ctx, &models.SignatureRecord{HashID: "d", DocumentName: "Doc2", UserName: "U", UserEmail: "maria@empresa.com", SignedAt: time.Now()}); err != nil {
		t.Errorf("other doc should sign: %v", err)
	}

	// Non-conflict errors are not reported as ErrAlreadySigned (duplicate hash_id).
	err := repo.Create(ctx, &models.SignatureRecord{HashID: "a", DocumentName: "Doc3", UserName: "U", UserEmail: "x@empresa.com", SignedAt: time.Now()})
	if err == nil || errors.Is(err, ErrAlreadySigned) {
		t.Errorf("duplicate hash_id should be a regular error, got %v", err)
	}
}
