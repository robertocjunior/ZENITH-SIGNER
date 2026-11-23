package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"zenith-signer/internal/database"
	"zenith-signer/internal/models"
	"zenith-signer/internal/outline"
)

// ErrOutlineDisabled is returned when the Outline integration is not configured.
var ErrOutlineDisabled = errors.New("integração com o Outline não configurada (OUTLINE_URL / OUTLINE_API_KEY)")

// OutlineAPI is the subset of the Outline client used by DocumentService.
type OutlineAPI interface {
	Info(ctx context.Context, id string) (*outline.Document, error)
	InfoStructured(ctx context.Context, id string) (*outline.Document, error)
	SearchTitles(ctx context.Context, query string, limit int) ([]outline.Document, error)
	Prepend(ctx context.Context, id, markdown string) (*outline.Document, error)
}

// RegisterInput describes a document registration requested by an admin.
type RegisterInput struct {
	OutlineRef  string // document id, urlId or full Outline URL
	DocKey      string // optional doc= identifier; defaults to the Outline urlId
	InsertEmbed bool   // insert the widget at the top of the Outline page
	AcceptPrior bool   // keep signatures made before registration valid
	Admin       string
}

// RegisterResult reports what happened during registration.
type RegisterResult struct {
	Document   *models.Document
	WidgetURL  string
	EmbedError string
}

// DocumentService registers Outline documents and keeps their versions in sync.
type DocumentService struct {
	repo        database.DocumentRepository
	outline     OutlineAPI
	outlineBase string
	appBaseURL  string
	logger      *slog.Logger

	syncMu sync.Mutex
	wg     sync.WaitGroup
}

// NewDocumentService creates the service. client may be nil when Outline is not configured.
func NewDocumentService(repo database.DocumentRepository, client OutlineAPI, outlineBase, appBaseURL string, logger *slog.Logger) *DocumentService {
	return &DocumentService{
		repo:        repo,
		outline:     client,
		outlineBase: strings.TrimRight(outlineBase, "/"),
		appBaseURL:  strings.TrimRight(appBaseURL, "/"),
		logger:      logger,
	}
}

// Enabled reports whether the Outline integration is available.
func (s *DocumentService) Enabled() bool { return s.outline != nil }

// Repo exposes the document repository for read-only admin views.
func (s *DocumentService) Repo() database.DocumentRepository { return s.repo }

// WidgetURL returns the embed URL for a doc key.
func (s *DocumentService) WidgetURL(key string) string {
	return s.appBaseURL + "/assinar?doc=" + url.QueryEscape(key)
}

// widgetMarkers identify widget lines inside document markdown (any doc key).
func (s *DocumentService) widgetMarkers() []string {
	return []string{s.appBaseURL + "/assinar?doc="}
}

// ParseOutlineRef extracts a document identifier from an Outline URL
// ("https://wiki/doc/politica-de-ferias-AbC123xyz" -> "AbC123xyz") or returns
// the input unchanged when it is already an id.
func ParseOutlineRef(ref string) string {
	ref = strings.TrimSpace(ref)
	u, err := url.Parse(ref)
	if err != nil || u.Host == "" {
		return ref
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "doc" {
			slug := parts[i+1]
			if idx := strings.LastIndex(slug, "-"); idx >= 0 {
				return slug[idx+1:]
			}
			return slug
		}
	}
	return ref
}

// SearchOutline searches Outline documents by title.
func (s *DocumentService) SearchOutline(ctx context.Context, query string) ([]outline.Document, error) {
	if !s.Enabled() {
		return nil, ErrOutlineDisabled
	}
	return s.outline.SearchTitles(ctx, query, 15)
}

// Register captures an Outline document as version 1 and, optionally, inserts the widget embed.
func (s *DocumentService) Register(ctx context.Context, in RegisterInput) (*RegisterResult, error) {
	if !s.Enabled() {
		return nil, ErrOutlineDisabled
	}
	ref := ParseOutlineRef(in.OutlineRef)
	if ref == "" {
		return nil, errors.New("informe o documento do Outline")
	}

	od, err := s.outline.Info(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("não foi possível ler o documento no Outline: %w", err)
	}

	key := strings.TrimSpace(in.DocKey)
	if key == "" {
		key = od.URLID
	}
	key, err = models.NormalizeDocID(key)
	if err != nil {
		return nil, fmt.Errorf("identificador inválido: %w", err)
	}

	if existing, err := s.repo.GetDocumentByOutlineID(ctx, od.ID); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, fmt.Errorf("%w: este documento do Outline já está cadastrado como %q", database.ErrDocumentExists, existing.DocKey)
	}
	if existing, err := s.repo.GetDocumentByKey(ctx, key); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, fmt.Errorf("%w: o identificador %q já é usado por %q", database.ErrDocumentExists, key, existing.Title)
	}

	content := outline.NormalizeContent(od.Text, s.widgetMarkers()...)
	doc := &models.Document{
		DocKey:       key,
		OutlineID:    od.ID,
		Title:        od.Title,
		OutlineURL:   s.outlineDocURL(od),
		CollectionID: od.CollectionID,
		EmbedStatus:  models.EmbedManual,
		CreatedBy:    in.Admin,
	}
	first := &models.DocumentVersion{
		OutlineRevision: od.Revision,
		Title:           od.Title,
		ContentHash:     outline.ContentHash(content),
		Content:         content,
	}
	if err := s.repo.CreateDocument(ctx, doc, first); err != nil {
		return nil, err
	}
	if in.AcceptPrior {
		if err := s.repo.AcceptPriorSignatures(ctx, doc.ID); err != nil {
			return nil, err
		}
		doc.RequiredVersionID = 0
	}

	res := &RegisterResult{Document: doc, WidgetURL: s.WidgetURL(key)}
	status, embedErr := s.placeEmbed(ctx, od, res.WidgetURL, in.InsertEmbed)
	if embedErr != nil {
		res.EmbedError = embedErr.Error()
	}
	doc.EmbedStatus = status
	if err := s.repo.UpdateEmbedStatus(ctx, doc.ID, status); err != nil {
		return nil, err
	}

	s.logger.Info("document registered from Outline",
		slog.String("doc_key", key),
		slog.String("outline_id", od.ID),
		slog.String("title", od.Title),
		slog.String("content_hash", first.ContentHash),
		slog.String("embed_status", status),
		slog.String("admin", in.Admin),
	)
	return res, nil
}

func (s *DocumentService) outlineDocURL(od *outline.Document) string {
	if od.URL == "" {
		return ""
	}
	if strings.HasPrefix(od.URL, "http://") || strings.HasPrefix(od.URL, "https://") {
		return od.URL
	}
	return s.outlineBase + od.URL
}

// placeEmbed makes sure the widget is on the page and reports how it ended up.
func (s *DocumentService) placeEmbed(ctx context.Context, od *outline.Document, widgetURL string, insert bool) (string, error) {
	text := strings.ReplaceAll(od.Text, "%5F", "_")
	if strings.Contains(text, widgetURL) {
		return models.EmbedExisting, nil
	}
	if !insert {
		return models.EmbedManual, nil
	}

	if _, err := s.outline.Prepend(ctx, od.ID, outline.EmbedMarkdown(widgetURL)); err != nil {
		return models.EmbedManual, fmt.Errorf("falha ao inserir o embed no Outline: %w", err)
	}

	// The markdown of an embed and of a plain link is identical; only the
	// structured (ProseMirror) document tells them apart.
	structured, err := s.outline.InfoStructured(ctx, od.ID)
	if err != nil {
		return models.EmbedLink, fmt.Errorf("embed inserido, mas não foi possível confirmar como o Outline o exibiu: %w", err)
	}
	if len(structured.Data) == 0 {
		// Older Outline versions do not return the structured document.
		return models.EmbedLink, errors.New("não foi possível confirmar como o Outline exibiu o widget; confira a página e, se aparecer como link, clique nele e escolha \"Embed\"")
	}
	if outline.ContainsEmbed(structured.Data, widgetURL) {
		return models.EmbedInserted, nil
	}
	return models.EmbedLink, nil
}

// SyncDocument re-reads a registered document from Outline and records a new
// version (pending an admin decision) when its content changed.
func (s *DocumentService) SyncDocument(ctx context.Context, doc *models.Document) (bool, error) {
	if !s.Enabled() {
		return false, ErrOutlineDisabled
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	od, err := s.outline.Info(ctx, doc.OutlineID)
	if err != nil {
		return false, err
	}
	content := outline.NormalizeContent(od.Text, s.widgetMarkers()...)
	hash := outline.ContentHash(content)

	current, err := s.repo.GetVersion(ctx, doc.CurrentVersionID)
	if err != nil {
		return false, err
	}
	if current != nil && current.ContentHash == hash {
		if od.Title != "" && od.Title != doc.Title {
			return false, s.repo.UpdateTitle(ctx, doc.ID, od.Title, s.outlineDocURL(od))
		}
		return false, nil
	}

	v := &models.DocumentVersion{
		OutlineRevision: od.Revision,
		Title:           od.Title,
		ContentHash:     hash,
		Content:         content,
		Decision:        models.DecisionPending,
	}
	if err := s.repo.AddVersion(ctx, doc.ID, v); err != nil {
		return false, err
	}
	s.logger.Warn("document content changed in Outline; new version awaits admin decision",
		slog.String("doc_key", doc.DocKey),
		slog.String("title", od.Title),
		slog.Int("version", v.VersionNo),
		slog.String("content_hash", hash),
	)
	return true, nil
}

// SyncByOutlineID syncs the registered document with the given Outline id, if any.
func (s *DocumentService) SyncByOutlineID(ctx context.Context, outlineID string) (bool, error) {
	doc, err := s.repo.GetDocumentByOutlineID(ctx, outlineID)
	if err != nil || doc == nil || !doc.Active {
		return false, err
	}
	return s.SyncDocument(ctx, doc)
}

// SyncAll syncs every active registered document.
func (s *DocumentService) SyncAll(ctx context.Context) {
	docs, err := s.repo.ListActiveDocuments(ctx)
	if err != nil {
		s.logger.Error("outline sync: failed to list documents", slog.String("error", err.Error()))
		return
	}
	for i := range docs {
		if ctx.Err() != nil {
			return
		}
		if _, err := s.SyncDocument(ctx, &docs[i]); err != nil {
			s.logger.Warn("outline sync failed",
				slog.String("doc_key", docs[i].DocKey),
				slog.String("error", err.Error()))
		}
	}
}

// QueueSync syncs a document in the background (used by the webhook, which must answer fast).
func (s *DocumentService) QueueSync(outlineID string) {
	if !s.Enabled() || outlineID == "" {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := s.SyncByOutlineID(ctx, outlineID); err != nil {
			s.logger.Warn("webhook-triggered sync failed",
				slog.String("outline_id", outlineID),
				slog.String("error", err.Error()))
		}
	}()
}

// StartSyncWorker periodically syncs all documents (fallback when webhooks are not configured or missed).
func (s *DocumentService) StartSyncWorker(ctx context.Context, interval time.Duration) {
	if !s.Enabled() {
		return
	}
	if interval < time.Minute {
		interval = 15 * time.Minute
	}
	s.logger.Info("starting outline sync worker", slog.Duration("interval", interval))
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				syncCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				s.SyncAll(syncCtx)
				cancel()
			}
		}
	}()
}

// Wait blocks until background syncs finish or ctx expires.
func (s *DocumentService) Wait(ctx context.Context) error {
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

// Decide records the admin decision about a pending version.
func (s *DocumentService) Decide(ctx context.Context, versionID int64, decision, admin string) error {
	if err := s.repo.DecideVersion(ctx, versionID, decision, admin); err != nil {
		return err
	}
	s.logger.Info("document version decision recorded",
		slog.Int64("version_id", versionID),
		slog.String("decision", decision),
		slog.String("admin", admin))
	return nil
}
