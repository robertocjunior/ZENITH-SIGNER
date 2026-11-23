package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"zenith-signer/internal/audit"
	"zenith-signer/internal/database"
	"zenith-signer/internal/email"
	"zenith-signer/internal/models"
)

var (
	// ErrDocumentChanged is returned when the user tries to sign a version that is no longer current.
	ErrDocumentChanged = errors.New("o documento foi atualizado; recarregue a página para ler a versão atual")
	// ErrDocumentInactive is returned when signing a registered document that was deactivated.
	ErrDocumentInactive = errors.New("este documento não está mais aceitando confirmações")
)

// SignRequest contains input data for registering a document signature.
type SignRequest struct {
	Doc            string
	UserEmail      string
	UserName       string
	Department     string
	JobTitle       string
	OfficeLocation string
	IP             string
	UserAgent      string
	// ExpectedVersionID is the document version shown to the user (0 if unknown).
	ExpectedVersionID int64
}

// SignatureStatus describes a user's situation regarding a document.
type SignatureStatus struct {
	Document       *models.Document        // nil when the doc is not registered from Outline
	CurrentVersion *models.DocumentVersion // nil when not registered
	Record         *models.SignatureRecord // user's latest signature, if any
	Valid          bool                    // Record covers the required version
	Outdated       bool                    // Record exists but predates the required version
}

// SignerService defines business operations for document signing.
type SignerService interface {
	GenerateHash(doc, email string, timestamp time.Time, ip, ua string) string
	GetSignature(ctx context.Context, doc, email string) (*models.SignatureRecord, error)
	GetStatus(ctx context.Context, doc, email string) (*SignatureStatus, error)
	SignDocument(ctx context.Context, req SignRequest) (*models.SignatureRecord, error)
	Wait(ctx context.Context) error
}

// Option customises the signer service.
type Option func(*signerService)

// WithDocuments enables version-aware signing for documents registered from Outline.
func WithDocuments(docs database.DocumentRepository) Option {
	return func(s *signerService) { s.docs = docs }
}

// WithSealer sets the audit-chain sealer (required in production; tests get a random key).
func WithSealer(sealer *audit.Sealer) Option {
	return func(s *signerService) { s.sealer = sealer }
}

type signerService struct {
	repo        database.Repository
	docs        database.DocumentRepository
	sealer      *audit.Sealer
	emailSender email.Sender
	logger      *slog.Logger
	wg          sync.WaitGroup
}

// NewSignerService creates a new signature business logic service.
func NewSignerService(repo database.Repository, emailSender email.Sender, logger *slog.Logger, opts ...Option) SignerService {
	s := &signerService{
		repo:        repo,
		emailSender: emailSender,
		logger:      logger,
	}
	for _, o := range opts {
		o(s)
	}
	if s.sealer == nil {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		s.sealer = audit.NewSealer(key)
	}
	return s
}

// GenerateHash is the legacy (pre audit chain) receipt hash, kept for compatibility.
func (s *signerService) GenerateHash(doc, email string, timestamp time.Time, ip, ua string) string {
	rawSeed := fmt.Sprintf("%s|%s|%s|%s|%s",
		strings.TrimSpace(doc),
		strings.ToLower(strings.TrimSpace(email)),
		timestamp.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(ip),
		strings.TrimSpace(ua),
	)

	hasher := sha256.New()
	hasher.Write([]byte(rawSeed))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (s *signerService) GetSignature(ctx context.Context, doc, email string) (*models.SignatureRecord, error) {
	return s.repo.GetByDocAndEmail(ctx, doc, email)
}

// registered returns the registered document (and its current version) for doc, if any.
func (s *signerService) registered(ctx context.Context, doc string) (*models.Document, *models.DocumentVersion, error) {
	if s.docs == nil {
		return nil, nil, nil
	}
	d, err := s.docs.GetDocumentByKey(ctx, doc)
	if err != nil || d == nil {
		return nil, nil, err
	}
	v, err := s.docs.GetVersion(ctx, d.CurrentVersionID)
	if err != nil {
		return nil, nil, err
	}
	return d, v, nil
}

func isValidFor(rec *models.SignatureRecord, d *models.Document) bool {
	if rec == nil {
		return false
	}
	return d == nil || rec.DocumentVersionID >= d.RequiredVersionID
}

func (s *signerService) GetStatus(ctx context.Context, doc, email string) (*SignatureStatus, error) {
	d, v, err := s.registered(ctx, doc)
	if err != nil {
		return nil, err
	}
	rec, err := s.repo.GetByDocAndEmail(ctx, doc, email)
	if err != nil {
		return nil, err
	}
	st := &SignatureStatus{Document: d, CurrentVersion: v, Record: rec}
	st.Valid = isValidFor(rec, d)
	st.Outdated = rec != nil && !st.Valid
	return st, nil
}

func (s *signerService) SignDocument(ctx context.Context, req SignRequest) (*models.SignatureRecord, error) {
	doc, err := models.NormalizeDocID(req.Doc)
	if err != nil {
		return nil, err
	}
	emailAddr := strings.ToLower(strings.TrimSpace(req.UserEmail))
	if emailAddr == "" {
		return nil, errors.New("user email cannot be empty")
	}

	d, version, err := s.registered(ctx, doc)
	if err != nil {
		return nil, fmt.Errorf("failed to load document: %w", err)
	}
	if d != nil {
		if !d.Active {
			return nil, ErrDocumentInactive
		}
		if req.ExpectedVersionID != 0 && req.ExpectedVersionID != d.CurrentVersionID {
			return nil, ErrDocumentChanged
		}
	}

	// Idempotency: an existing signature that still covers the required version is returned as-is.
	existing, err := s.repo.GetByDocAndEmail(ctx, doc, emailAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to verify existing signature: %w", err)
	}
	if isValidFor(existing, d) {
		s.logger.Info("document already signed by user",
			slog.String("doc", doc),
			slog.String("email", emailAddr),
			slog.String("hash", existing.HashID),
		)
		return existing, nil
	}

	record := &models.SignatureRecord{
		DocumentName:   doc,
		UserName:       strings.TrimSpace(req.UserName),
		UserEmail:      emailAddr,
		Department:     strings.TrimSpace(req.Department),
		JobTitle:       strings.TrimSpace(req.JobTitle),
		OfficeLocation: strings.TrimSpace(req.OfficeLocation),
		SignedAt:       time.Now(),
		UserAgent:      req.UserAgent,
		IPAddress:      req.IP,
	}
	if version != nil {
		record.DocumentVersionID = version.ID
		record.ContentHash = version.ContentHash
	}

	if err := s.repo.CreateSealed(ctx, record, s.sealer.Seal); err != nil {
		if errors.Is(err, database.ErrAlreadySigned) {
			// Lost a race with a concurrent request (e.g. double click): the
			// database kept the first signature, return it and skip the receipt.
			existing, getErr := s.repo.GetByDocAndEmail(ctx, doc, emailAddr)
			if getErr != nil || existing == nil {
				return nil, fmt.Errorf("signature conflict but existing record not found: %w", errors.Join(err, getErr))
			}
			s.logger.Info("concurrent duplicate signature ignored",
				slog.String("doc", doc),
				slog.String("email", emailAddr),
				slog.String("hash", existing.HashID),
			)
			return existing, nil
		}
		return nil, fmt.Errorf("failed to save signature record: %w", err)
	}

	s.logger.Info("signature successfully recorded",
		slog.String("doc", doc),
		slog.String("user", record.UserName),
		slog.String("email", record.UserEmail),
		slog.String("hash", record.HashID),
		slog.Int64("id", record.ID),
		slog.Int64("chain_seq", record.ChainSeq),
		slog.Int64("document_version_id", record.DocumentVersionID),
	)

	displayName := record.DocumentName
	if d != nil && d.Title != "" {
		displayName = d.Title
		if version != nil {
			displayName = fmt.Sprintf("%s (versão %d)", d.Title, version.VersionNo)
		}
	}

	// Asynchronous receipt dispatch with detached context and timeout
	s.wg.Add(1)
	go func(toEmail, toName, docName, hash string, signedTime time.Time) {
		defer s.wg.Done()
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		dateStr := signedTime.Format("02/01/2006 às 15:04:05")
		if err := s.emailSender.SendReceipt(bgCtx, toEmail, toName, docName, hash, dateStr); err != nil {
			s.logger.Error("async email receipt failed",
				slog.String("email", toEmail),
				slog.String("doc", docName),
				slog.String("error", err.Error()),
			)
		}
	}(record.UserEmail, record.UserName, displayName, record.HashID, record.SignedAt)

	return record, nil
}

// Wait blocks until all in-flight background email tasks finish or ctx expires.
func (s *signerService) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
