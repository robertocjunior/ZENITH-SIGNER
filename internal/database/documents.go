package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"zenith-signer/internal/models"
)

var (
	// ErrDocumentExists is returned when the Outline document or the doc key is already registered.
	ErrDocumentExists = errors.New("document already registered")
	// ErrVersionNotPending is returned when deciding on a version that is not awaiting a decision.
	ErrVersionNotPending = errors.New("version is not pending a decision")
)

// DocumentRepository stores documents registered from Outline and their versions.
type DocumentRepository interface {
	// CreateDocument registers doc with its first version (decision "initial") in one transaction.
	CreateDocument(ctx context.Context, doc *models.Document, first *models.DocumentVersion) error
	GetDocumentByID(ctx context.Context, id int64) (*models.Document, error)
	GetDocumentByKey(ctx context.Context, key string) (*models.Document, error)
	GetDocumentByOutlineID(ctx context.Context, outlineID string) (*models.Document, error)
	ListDocuments(ctx context.Context) ([]models.DocumentSummary, error)
	ListActiveDocuments(ctx context.Context) ([]models.Document, error)
	// AddVersion appends a new version (becoming the current one) and updates the title.
	AddVersion(ctx context.Context, documentID int64, v *models.DocumentVersion) error
	UpdateTitle(ctx context.Context, documentID int64, title, outlineURL string) error
	GetVersion(ctx context.Context, id int64) (*models.DocumentVersion, error)
	// GetPreviousVersion returns the version immediately before v (nil for the first).
	GetPreviousVersion(ctx context.Context, v *models.DocumentVersion) (*models.DocumentVersion, error)
	ListVersions(ctx context.Context, documentID int64) ([]models.DocumentVersion, error)
	// DecideVersion records the admin decision on a pending version. Deciding
	// "resign" makes it the required version for valid signatures.
	DecideVersion(ctx context.Context, versionID int64, decision, decidedBy string) error
	UpdateEmbedStatus(ctx context.Context, documentID int64, status string) error
	// AcceptPriorSignatures sets the required version to 0, so signatures made
	// before the document was registered (version 0) remain valid.
	AcceptPriorSignatures(ctx context.Context, documentID int64) error
	SetActive(ctx context.Context, documentID int64, active bool) error
}

type sqliteDocumentRepository struct {
	db *sql.DB
}

// NewDocumentRepository creates a SQLite-backed DocumentRepository.
func NewDocumentRepository(db *sql.DB) DocumentRepository {
	return &sqliteDocumentRepository{db: db}
}

const documentColumns = `id, doc_key, outline_id, title, outline_url, collection_id,
	current_version_id, required_version_id, embed_status, active, created_by, created_at, updated_at`

func scanDocument(row rowScanner) (*models.Document, error) {
	var d models.Document
	err := row.Scan(&d.ID, &d.DocKey, &d.OutlineID, &d.Title, &d.OutlineURL, &d.CollectionID,
		&d.CurrentVersionID, &d.RequiredVersionID, &d.EmbedStatus, &d.Active, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

const versionColumns = `id, document_id, version_no, outline_revision, title, content_hash, content,
	decision, decided_by, decided_at, created_at`

func scanVersion(row rowScanner) (*models.DocumentVersion, error) {
	var v models.DocumentVersion
	var decidedAt sql.NullTime
	err := row.Scan(&v.ID, &v.DocumentID, &v.VersionNo, &v.OutlineRevision, &v.Title, &v.ContentHash, &v.Content,
		&v.Decision, &v.DecidedBy, &decidedAt, &v.CreatedAt)
	if err != nil {
		return nil, err
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		v.DecidedAt = &t
	}
	return &v, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func (r *sqliteDocumentRepository) CreateDocument(ctx context.Context, doc *models.Document, first *models.DocumentVersion) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin document registration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	doc.CreatedAt, doc.UpdatedAt, doc.Active = now, now, true

	res, err := tx.ExecContext(ctx, `
	INSERT INTO documents (doc_key, outline_id, title, outline_url, collection_id, embed_status, active, created_by, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
		doc.DocKey, doc.OutlineID, doc.Title, doc.OutlineURL, doc.CollectionID, doc.EmbedStatus, doc.CreatedBy, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDocumentExists
		}
		return fmt.Errorf("failed to insert document: %w", err)
	}
	doc.ID, _ = res.LastInsertId()

	first.DocumentID = doc.ID
	first.VersionNo = 1
	first.Decision = models.DecisionInitial
	first.CreatedAt = now
	res, err = tx.ExecContext(ctx, `
	INSERT INTO document_versions (document_id, version_no, outline_revision, title, content_hash, content, decision, decided_by, decided_at, created_at)
	VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		doc.ID, first.OutlineRevision, first.Title, first.ContentHash, first.Content, first.Decision, doc.CreatedBy, now, now)
	if err != nil {
		return fmt.Errorf("failed to insert first document version: %w", err)
	}
	first.ID, _ = res.LastInsertId()

	if _, err := tx.ExecContext(ctx,
		`UPDATE documents SET current_version_id = ?, required_version_id = ? WHERE id = ?`,
		first.ID, first.ID, doc.ID); err != nil {
		return fmt.Errorf("failed to link first version: %w", err)
	}
	doc.CurrentVersionID, doc.RequiredVersionID = first.ID, first.ID

	return tx.Commit()
}

func (r *sqliteDocumentRepository) getDocument(ctx context.Context, where string, arg any) (*models.Document, error) {
	d, err := scanDocument(r.db.QueryRowContext(ctx, `SELECT `+documentColumns+` FROM documents WHERE `+where+` LIMIT 1`, arg))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch document: %w", err)
	}
	return d, nil
}

func (r *sqliteDocumentRepository) GetDocumentByID(ctx context.Context, id int64) (*models.Document, error) {
	return r.getDocument(ctx, "id = ?", id)
}

func (r *sqliteDocumentRepository) GetDocumentByKey(ctx context.Context, key string) (*models.Document, error) {
	return r.getDocument(ctx, "doc_key = ?", key)
}

func (r *sqliteDocumentRepository) GetDocumentByOutlineID(ctx context.Context, outlineID string) (*models.Document, error) {
	return r.getDocument(ctx, "outline_id = ?", outlineID)
}

func (r *sqliteDocumentRepository) ListActiveDocuments(ctx context.Context) ([]models.Document, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+documentColumns+` FROM documents WHERE active = 1 ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("failed to list documents: %w", err)
	}
	defer rows.Close()
	var out []models.Document
	for rows.Next() {
		d, err := scanDocument(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

func (r *sqliteDocumentRepository) ListDocuments(ctx context.Context) ([]models.DocumentSummary, error) {
	// Per user, only the latest signature counts: valid if it is on the required
	// version or a later one, outdated otherwise.
	rows, err := r.db.QueryContext(ctx, `
	SELECT d.id, d.doc_key, d.outline_id, d.title, d.outline_url, d.collection_id,
	       d.current_version_id, d.required_version_id, d.embed_status, d.active, d.created_by, d.created_at, d.updated_at,
	       COALESCE(cv.version_no, 0), COALESCE(rv.version_no, 0),
	       (SELECT COUNT(*) FROM (
	           SELECT user_email, MAX(document_version_id) AS v FROM signatures
	           WHERE document_name = d.doc_key GROUP BY user_email
	       ) WHERE v >= d.required_version_id),
	       (SELECT COUNT(*) FROM (
	           SELECT user_email, MAX(document_version_id) AS v FROM signatures
	           WHERE document_name = d.doc_key GROUP BY user_email
	       ) WHERE v < d.required_version_id),
	       COALESCE((SELECT id FROM document_versions WHERE document_id = d.id AND decision = 'pending' ORDER BY id DESC LIMIT 1), 0),
	       COALESCE((SELECT version_no FROM document_versions WHERE document_id = d.id AND decision = 'pending' ORDER BY id DESC LIMIT 1), 0)
	FROM documents d
	LEFT JOIN document_versions cv ON cv.id = d.current_version_id
	LEFT JOIN document_versions rv ON rv.id = d.required_version_id
	ORDER BY d.active DESC, d.title COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("failed to list documents: %w", err)
	}
	defer rows.Close()

	var out []models.DocumentSummary
	for rows.Next() {
		var s models.DocumentSummary
		d := &s.Document
		if err := rows.Scan(&d.ID, &d.DocKey, &d.OutlineID, &d.Title, &d.OutlineURL, &d.CollectionID,
			&d.CurrentVersionID, &d.RequiredVersionID, &d.EmbedStatus, &d.Active, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
			&s.CurrentVersionNo, &s.RequiredVersionNo, &s.ValidSigners, &s.OutdatedSigners,
			&s.PendingVersionID, &s.PendingVersionNo); err != nil {
			return nil, fmt.Errorf("failed to scan document summary: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *sqliteDocumentRepository) AddVersion(ctx context.Context, documentID int64, v *models.DocumentVersion) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin version insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var next int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version_no), 0) + 1 FROM document_versions WHERE document_id = ?`, documentID,
	).Scan(&next); err != nil {
		return fmt.Errorf("failed to compute next version number: %w", err)
	}

	now := time.Now()
	v.DocumentID, v.VersionNo, v.CreatedAt = documentID, next, now
	if v.Decision == "" {
		v.Decision = models.DecisionPending
	}
	res, err := tx.ExecContext(ctx, `
	INSERT INTO document_versions (document_id, version_no, outline_revision, title, content_hash, content, decision, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		documentID, next, v.OutlineRevision, v.Title, v.ContentHash, v.Content, v.Decision, now)
	if err != nil {
		return fmt.Errorf("failed to insert document version: %w", err)
	}
	v.ID, _ = res.LastInsertId()

	if _, err := tx.ExecContext(ctx,
		`UPDATE documents SET current_version_id = ?, title = CASE WHEN ? <> '' THEN ? ELSE title END, updated_at = ? WHERE id = ?`,
		v.ID, v.Title, v.Title, now, documentID); err != nil {
		return fmt.Errorf("failed to update current version: %w", err)
	}
	return tx.Commit()
}

func (r *sqliteDocumentRepository) UpdateTitle(ctx context.Context, documentID int64, title, outlineURL string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE documents SET title = ?, outline_url = CASE WHEN ? <> '' THEN ? ELSE outline_url END, updated_at = ? WHERE id = ?`,
		title, outlineURL, outlineURL, time.Now(), documentID)
	if err != nil {
		return fmt.Errorf("failed to update document title: %w", err)
	}
	return nil
}

func (r *sqliteDocumentRepository) GetVersion(ctx context.Context, id int64) (*models.DocumentVersion, error) {
	v, err := scanVersion(r.db.QueryRowContext(ctx, `SELECT `+versionColumns+` FROM document_versions WHERE id = ?`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch document version: %w", err)
	}
	return v, nil
}

func (r *sqliteDocumentRepository) GetPreviousVersion(ctx context.Context, v *models.DocumentVersion) (*models.DocumentVersion, error) {
	prev, err := scanVersion(r.db.QueryRowContext(ctx,
		`SELECT `+versionColumns+` FROM document_versions WHERE document_id = ? AND version_no < ? ORDER BY version_no DESC LIMIT 1`,
		v.DocumentID, v.VersionNo))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch previous version: %w", err)
	}
	return prev, nil
}

func (r *sqliteDocumentRepository) ListVersions(ctx context.Context, documentID int64) ([]models.DocumentVersion, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+versionColumns+` FROM document_versions WHERE document_id = ? ORDER BY version_no DESC`, documentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}
	defer rows.Close()
	var out []models.DocumentVersion
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

func (r *sqliteDocumentRepository) DecideVersion(ctx context.Context, versionID int64, decision, decidedBy string) error {
	if decision != models.DecisionResign && decision != models.DecisionMinor {
		return fmt.Errorf("invalid decision %q", decision)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin decision: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var documentID int64
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT document_id, decision FROM document_versions WHERE id = ?`, versionID).
		Scan(&documentID, &current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrVersionNotPending
		}
		return fmt.Errorf("failed to load version: %w", err)
	}
	if current != models.DecisionPending {
		return ErrVersionNotPending
	}

	now := time.Now()
	if _, err := tx.ExecContext(ctx,
		`UPDATE document_versions SET decision = ?, decided_by = ?, decided_at = ? WHERE id = ?`,
		decision, decidedBy, now, versionID); err != nil {
		return fmt.Errorf("failed to record decision: %w", err)
	}

	// Deciding "minor" on a version also settles older pending versions as minor;
	// deciding "resign" supersedes them (the newest required version wins).
	if _, err := tx.ExecContext(ctx,
		`UPDATE document_versions SET decision = ?, decided_by = ?, decided_at = ?
		 WHERE document_id = ? AND id < ? AND decision = 'pending'`,
		models.DecisionMinor, decidedBy, now, documentID, versionID); err != nil {
		return fmt.Errorf("failed to settle older pending versions: %w", err)
	}

	if decision == models.DecisionResign {
		if _, err := tx.ExecContext(ctx,
			`UPDATE documents SET required_version_id = MAX(required_version_id, ?), updated_at = ? WHERE id = ?`,
			versionID, now, documentID); err != nil {
			return fmt.Errorf("failed to update required version: %w", err)
		}
	}
	return tx.Commit()
}

func (r *sqliteDocumentRepository) UpdateEmbedStatus(ctx context.Context, documentID int64, status string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE documents SET embed_status = ?, updated_at = ? WHERE id = ?`, status, time.Now(), documentID)
	if err != nil {
		return fmt.Errorf("failed to update embed status: %w", err)
	}
	return nil
}

func (r *sqliteDocumentRepository) SetActive(ctx context.Context, documentID int64, active bool) error {
	_, err := r.db.ExecContext(ctx, `UPDATE documents SET active = ?, updated_at = ? WHERE id = ?`, active, time.Now(), documentID)
	if err != nil {
		return fmt.Errorf("failed to update document status: %w", err)
	}
	return nil
}

func (r *sqliteDocumentRepository) AcceptPriorSignatures(ctx context.Context, documentID int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE documents SET required_version_id = 0, updated_at = ? WHERE id = ?`, time.Now(), documentID)
	if err != nil {
		return fmt.Errorf("failed to accept prior signatures: %w", err)
	}
	return nil
}
