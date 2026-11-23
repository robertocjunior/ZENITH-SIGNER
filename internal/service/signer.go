package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"zenith-signer/internal/database"
	"zenith-signer/internal/email"
	"zenith-signer/internal/models"
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
}

// SignerService defines business operations for document signing.
type SignerService interface {
	GenerateHash(doc, email string, timestamp time.Time, ip, ua string) string
	GetSignature(ctx context.Context, doc, email string) (*models.SignatureRecord, error)
	SignDocument(ctx context.Context, req SignRequest) (*models.SignatureRecord, error)
	Wait(ctx context.Context) error
}

type signerService struct {
	repo        database.Repository
	emailSender email.Sender
	logger      *slog.Logger
	wg          sync.WaitGroup
}

// NewSignerService creates a new signature business logic service.
func NewSignerService(repo database.Repository, emailSender email.Sender, logger *slog.Logger) SignerService {
	return &signerService{
		repo:        repo,
		emailSender: emailSender,
		logger:      logger,
	}
}

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

func (s *signerService) SignDocument(ctx context.Context, req SignRequest) (*models.SignatureRecord, error) {
	doc, err := models.NormalizeDocID(req.Doc)
	if err != nil {
		return nil, err
	}
	emailAddr := strings.ToLower(strings.TrimSpace(req.UserEmail))

	if emailAddr == "" {
		return nil, errors.New("user email cannot be empty")
	}

	// Idempotency check: if user already signed this document, return existing record
	existing, err := s.repo.GetByDocAndEmail(ctx, doc, emailAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to verify existing signature: %w", err)
	}
	if existing != nil {
		s.logger.Info("document already signed by user",
			slog.String("doc", doc),
			slog.String("email", emailAddr),
			slog.String("hash", existing.HashID),
		)
		return existing, nil
	}

	now := time.Now()
	hashID := s.GenerateHash(doc, emailAddr, now, req.IP, req.UserAgent)

	record := &models.SignatureRecord{
		HashID:         hashID,
		DocumentName:   doc,
		UserName:       strings.TrimSpace(req.UserName),
		UserEmail:      emailAddr,
		Department:     strings.TrimSpace(req.Department),
		JobTitle:       strings.TrimSpace(req.JobTitle),
		OfficeLocation: strings.TrimSpace(req.OfficeLocation),
		SignedAt:       now,
		UserAgent:      req.UserAgent,
		IPAddress:      req.IP,
	}

	if err := s.repo.Create(ctx, record); err != nil {
		return nil, fmt.Errorf("failed to save signature record: %w", err)
	}

	s.logger.Info("signature successfully recorded",
		slog.String("doc", doc),
		slog.String("user", record.UserName),
		slog.String("email", record.UserEmail),
		slog.String("hash", record.HashID),
		slog.Int64("id", record.ID),
	)

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
	}(record.UserEmail, record.UserName, record.DocumentName, record.HashID, record.SignedAt)

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
