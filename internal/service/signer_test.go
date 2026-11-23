package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zenith-signer/internal/config"
	"zenith-signer/internal/database"
	"zenith-signer/internal/models"
)

type dummyEmailSender struct {
	sentCount int
}

func (d *dummyEmailSender) SendReceipt(ctx context.Context, toEmail, toName, docName, hashID, dateStr string) error {
	d.sentCount++
	return nil
}

func TestSignerServiceHashGeneration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := NewSignerService(nil, nil, logger)

	fixedTime := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	hash1 := svc.GenerateHash("docA", "user@empresa.com", fixedTime, "127.0.0.1", "curl")
	hash2 := svc.GenerateHash("docA", "user@empresa.com", fixedTime, "127.0.0.1", "curl")
	hash3 := svc.GenerateHash("docB", "user@empresa.com", fixedTime, "127.0.0.1", "curl")

	if hash1 != hash2 {
		t.Errorf("expected deterministic hash output, got %s and %s", hash1, hash2)
	}
	if hash1 == hash3 {
		t.Errorf("expected different hash for different doc, got same: %s", hash1)
	}
	if len(hash1) != 64 {
		t.Errorf("expected 64 character hex SHA-256 string, got %d", len(hash1))
	}
}

func TestSignerServiceSignAndDuplicate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := database.Open(config.DatabaseConfig{Path: ":memory:"}, logger)
	if err != nil {
		t.Fatalf("failed to open memory db: %v", err)
	}
	ctx := context.Background()
	_ = database.Migrate(ctx, db, logger)
	repo := database.NewRepository(db)

	emailSender := &dummyEmailSender{}
	svc := NewSignerService(repo, emailSender, logger)

	req := SignRequest{
		Doc:            "Termo-Uso.pdf",
		UserEmail:      "maria@empresa.com",
		UserName:       "Maria Silva",
		Department:     "RH",
		JobTitle:       "Analista",
		OfficeLocation: "Filial",
		IP:             "10.0.0.1",
		UserAgent:      "Mozilla",
	}

	// 1. Initial sign
	record, err := svc.SignDocument(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error signing document: %v", err)
	}
	if record == nil || record.ID == 0 {
		t.Fatalf("expected valid record with non-zero ID")
	}

	// 2. Duplicate sign attempt: must be idempotent and return existing record
	duplicateRecord, err := svc.SignDocument(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error on duplicate sign: %v", err)
	}
	if duplicateRecord.ID != record.ID {
		t.Errorf("expected duplicate sign to return existing record ID %d, got %d", record.ID, duplicateRecord.ID)
	}
	if duplicateRecord.HashID != record.HashID {
		t.Errorf("expected matching hash ID for duplicate sign")
	}
}

func TestSignerServiceRejectsInvalidDoc(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := database.Open(config.DatabaseConfig{Path: ":memory:"}, logger)
	if err != nil {
		t.Fatalf("failed to open memory db: %v", err)
	}
	ctx := context.Background()
	_ = database.Migrate(ctx, db, logger)
	repo := database.NewRepository(db)
	sender := &dummyEmailSender{}
	svc := NewSignerService(repo, sender, logger)

	for _, doc := range []string{"", "  ", "Doc\r\nBcc: evil@example.com", "Doc\x00"} {
		_, err := svc.SignDocument(ctx, SignRequest{Doc: doc, UserEmail: "maria@empresa.com"})
		if err == nil {
			t.Errorf("expected error for doc %q", doc)
		}
	}
	if !errors.Is(func() error {
		_, err := svc.SignDocument(ctx, SignRequest{Doc: "a\nb", UserEmail: "maria@empresa.com"})
		return err
	}(), models.ErrDocIDInvalid) {
		t.Errorf("expected ErrDocIDInvalid")
	}

	records, _ := repo.List(ctx, models.FilterCriteria{})
	if len(records) != 0 {
		t.Errorf("no record should be stored, got %d", len(records))
	}
	_ = svc.Wait(ctx)
	if sender.sentCount != 0 {
		t.Errorf("no e-mail should be sent, got %d", sender.sentCount)
	}
}

type countingSender struct{ n atomic.Int32 }

func (c *countingSender) SendReceipt(ctx context.Context, toEmail, toName, docName, hashID, dateStr string) error {
	c.n.Add(1)
	return nil
}

func TestSignerServiceConcurrentDoubleClick(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := database.Open(config.DatabaseConfig{
		Path:          filepath.Join(t.TempDir(), "race.db"),
		BusyTimeoutMs: 5000,
		MaxOpenConns:  10,
	}, logger)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := database.Migrate(ctx, db, logger); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := database.NewRepository(db)
	sender := &countingSender{}
	svc := NewSignerService(repo, sender, logger)

	const clicks = 20
	var wg sync.WaitGroup
	start := make(chan struct{})
	hashes := make([]string, clicks)
	errs := make([]error, clicks)
	for i := 0; i < clicks; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec, err := svc.SignDocument(ctx, SignRequest{
				Doc: "Politica-Clique-Duplo", UserEmail: "maria@empresa.com", UserName: "Maria",
				IP: "10.0.0.1", UserAgent: fmt.Sprintf("click-%d", i),
			})
			errs[i] = err
			if rec != nil {
				hashes[i] = rec.HashID
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("click %d failed: %v", i, err)
		}
		if hashes[i] != hashes[0] {
			t.Errorf("all clicks must return the same signature, got %s vs %s", hashes[i], hashes[0])
		}
	}

	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM signatures WHERE document_name = 'Politica-Clique-Duplo'").Scan(&n)
	if n != 1 {
		t.Errorf("expected exactly 1 signature after %d concurrent clicks, got %d", clicks, n)
	}

	_ = svc.Wait(ctx)
	if got := sender.n.Load(); got != 1 {
		t.Errorf("expected exactly 1 receipt e-mail, got %d", got)
	}
}

// raceRepo simulates the race window of a double click: the idempotency
// pre-check does not see the signature another request has just committed.
type raceRepo struct {
	database.Repository
	hideOnce atomic.Bool
}

func (r *raceRepo) GetByDocAndEmail(ctx context.Context, doc, email string) (*models.SignatureRecord, error) {
	if r.hideOnce.CompareAndSwap(true, false) {
		return nil, nil
	}
	return r.Repository.GetByDocAndEmail(ctx, doc, email)
}

func TestSignerServiceHandlesInsertConflict(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := database.Open(config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "conflict.db"), BusyTimeoutMs: 5000}, logger)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := database.Migrate(ctx, db, logger); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	base := database.NewRepository(db)
	sender := &countingSender{}

	// First click commits normally.
	first, err := NewSignerService(base, sender, logger).SignDocument(ctx, SignRequest{Doc: "Doc", UserEmail: "maria@empresa.com", UserName: "Maria"})
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}

	// Second click passes the pre-check (race) and hits the unique constraint.
	repo := &raceRepo{Repository: base}
	repo.hideOnce.Store(true)
	svc := NewSignerService(repo, sender, logger)
	second, err := svc.SignDocument(ctx, SignRequest{Doc: "Doc", UserEmail: "maria@empresa.com", UserName: "Maria", UserAgent: "second"})
	if err != nil {
		t.Fatalf("conflicting click must not fail: %v", err)
	}
	if second.HashID != first.HashID || second.ID != first.ID {
		t.Errorf("conflicting click must return the original signature, got %+v", second)
	}

	_ = svc.Wait(ctx)
	if got := sender.n.Load(); got != 1 {
		t.Errorf("only the first click may send a receipt, got %d e-mails", got)
	}
}
