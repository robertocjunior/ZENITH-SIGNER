package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"zenith-signer/internal/models"
)

// ErrAlreadySigned is returned when the user already signed this document version.
var ErrAlreadySigned = errors.New("document already signed by this user")

// GenesisHash is the PrevHash of the first record of the audit chain.
const GenesisHash = "GENESIS"

// SealFunc computes the tamper-evident hash of a record once its chain
// position (ChainSeq, PrevHash) has been assigned.
type SealFunc func(rec *models.SignatureRecord) string

// Repository defines data access operations for signatures.
type Repository interface {
	// Create inserts a record as-is (no audit chain). Kept for legacy flows and tests.
	Create(ctx context.Context, rec *models.SignatureRecord) error
	// CreateSealed appends the record to the audit chain: it assigns ChainSeq and
	// PrevHash, computes HashID with seal and inserts it atomically.
	CreateSealed(ctx context.Context, rec *models.SignatureRecord, seal SealFunc) error
	// GetByDocAndEmail returns the user's most recent signature of a document.
	GetByDocAndEmail(ctx context.Context, doc, email string) (*models.SignatureRecord, error)
	GetByHash(ctx context.Context, hash string) (*models.SignatureRecord, error)
	List(ctx context.Context, filter models.FilterCriteria) ([]models.SignatureRecord, error)
	Count(ctx context.Context, filter models.FilterCriteria) (int, error)
	// ListChain returns every chained record ordered by ChainSeq.
	ListChain(ctx context.Context) ([]models.SignatureRecord, error)
	Ping(ctx context.Context) error
}

type sqliteRepository struct {
	db *sql.DB
	// chainMu serialises appends to the audit chain (single-instance service).
	chainMu sync.Mutex
}

// NewRepository creates a new SQLite-backed repository.
func NewRepository(db *sql.DB) Repository {
	return &sqliteRepository{db: db}
}

func (r *sqliteRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

// documentTitleExpr resolves the registered document title for a signature row.
const documentTitleExpr = `COALESCE((SELECT title FROM documents WHERE doc_key = signatures.document_name), '')`

const signatureColumns = `id, hash_id, document_name, ` + documentTitleExpr + `, user_name, user_email,
	COALESCE(department, ''), COALESCE(job_title, ''), COALESCE(office_location, ''),
	signed_at, COALESCE(user_agent, ''), COALESCE(ip_address, ''),
	document_version_id, content_hash, prev_hash, COALESCE(chain_seq, 0)`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSignature(row rowScanner) (*models.SignatureRecord, error) {
	var rec models.SignatureRecord
	err := row.Scan(
		&rec.ID, &rec.HashID, &rec.DocumentName, &rec.DocumentTitle, &rec.UserName, &rec.UserEmail,
		&rec.Department, &rec.JobTitle, &rec.OfficeLocation,
		&rec.SignedAt, &rec.UserAgent, &rec.IPAddress,
		&rec.DocumentVersionID, &rec.ContentHash, &rec.PrevHash, &rec.ChainSeq,
	)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertSignature(ctx context.Context, ex execer, rec *models.SignatureRecord) error {
	rec.UserEmail = strings.ToLower(strings.TrimSpace(rec.UserEmail))

	var chainSeq any
	if rec.ChainSeq > 0 {
		chainSeq = rec.ChainSeq
	}

	res, err := ex.ExecContext(ctx, `
	INSERT INTO signatures (
		hash_id, document_name, user_name, user_email, department, job_title, office_location,
		signed_at, user_agent, ip_address, document_version_id, content_hash, prev_hash, chain_seq
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(document_name, user_email, document_version_id) DO NOTHING`,
		rec.HashID, rec.DocumentName, rec.UserName, rec.UserEmail, rec.Department, rec.JobTitle,
		rec.OfficeLocation, rec.SignedAt, rec.UserAgent, rec.IPAddress,
		rec.DocumentVersionID, rec.ContentHash, rec.PrevHash, chainSeq,
	)
	if err != nil {
		return fmt.Errorf("failed to insert signature record: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read insert result: %w", err)
	}
	if affected == 0 {
		return ErrAlreadySigned
	}
	if id, err := res.LastInsertId(); err == nil {
		rec.ID = id
	}
	return nil
}

func (r *sqliteRepository) Create(ctx context.Context, rec *models.SignatureRecord) error {
	return insertSignature(ctx, r.db, rec)
}

func (r *sqliteRepository) CreateSealed(ctx context.Context, rec *models.SignatureRecord, seal SealFunc) error {
	if seal == nil {
		return errors.New("seal function is required")
	}

	r.chainMu.Lock()
	defer r.chainMu.Unlock()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin chained insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var lastSeq int64
	var lastHash string
	err = tx.QueryRowContext(ctx,
		`SELECT chain_seq, hash_id FROM signatures WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1`,
	).Scan(&lastSeq, &lastHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		lastSeq, lastHash = 0, GenesisHash
	case err != nil:
		return fmt.Errorf("failed to read audit chain head: %w", err)
	}

	rec.UserEmail = strings.ToLower(strings.TrimSpace(rec.UserEmail))
	rec.ChainSeq = lastSeq + 1
	rec.PrevHash = lastHash
	rec.HashID = seal(rec)

	if err := insertSignature(ctx, tx, rec); err != nil {
		rec.ChainSeq, rec.PrevHash, rec.HashID = 0, "", ""
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit chained insert: %w", err)
	}
	return nil
}

func (r *sqliteRepository) GetByDocAndEmail(ctx context.Context, doc, email string) (*models.SignatureRecord, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+signatureColumns+` FROM signatures
		WHERE document_name = ? AND user_email = ?
		ORDER BY document_version_id DESC, id DESC
		LIMIT 1`,
		doc, strings.ToLower(strings.TrimSpace(email)),
	)
	rec, err := scanSignature(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch signature: %w", err)
	}
	return rec, nil
}

func (r *sqliteRepository) GetByHash(ctx context.Context, hash string) (*models.SignatureRecord, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+signatureColumns+` FROM signatures WHERE hash_id = ? LIMIT 1`,
		strings.TrimSpace(hash),
	)
	rec, err := scanSignature(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return r.getArchivedByHash(ctx, hash)
		}
		return nil, fmt.Errorf("failed to fetch signature by hash: %w", err)
	}
	return rec, nil
}

// getArchivedByHash looks up a hash among duplicate signatures archived by the
// unique-signature migration, so receipts already e-mailed remain verifiable.
func (r *sqliteRepository) getArchivedByHash(ctx context.Context, hash string) (*models.SignatureRecord, error) {
	var rec models.SignatureRecord
	err := r.db.QueryRowContext(ctx, `
	SELECT id, hash_id, document_name,
	       COALESCE((SELECT title FROM documents WHERE doc_key = signatures_duplicates.document_name), ''),
	       user_name, user_email,
	       COALESCE(department, ''), COALESCE(job_title, ''), COALESCE(office_location, ''),
	       signed_at, COALESCE(user_agent, ''), COALESCE(ip_address, '')
	FROM signatures_duplicates
	WHERE hash_id = ?
	LIMIT 1`, strings.TrimSpace(hash)).Scan(
		&rec.ID, &rec.HashID, &rec.DocumentName, &rec.DocumentTitle, &rec.UserName, &rec.UserEmail,
		&rec.Department, &rec.JobTitle, &rec.OfficeLocation, &rec.SignedAt, &rec.UserAgent, &rec.IPAddress,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch archived signature by hash: %w", err)
	}
	return &rec, nil
}

func (r *sqliteRepository) buildFilterQuery(baseSQL string, filter models.FilterCriteria) (string, []interface{}) {
	var sb strings.Builder
	sb.WriteString(baseSQL)
	sb.WriteString(" WHERE 1=1")

	var args []interface{}

	if doc := strings.TrimSpace(filter.Document); doc != "" {
		// Matches the doc= identifier or the registered document title.
		sb.WriteString(" AND (document_name LIKE ? OR document_name IN (SELECT doc_key FROM documents WHERE title LIKE ?))")
		args = append(args, "%"+doc+"%", "%"+doc+"%")
	}
	if user := strings.TrimSpace(filter.User); user != "" {
		sb.WriteString(" AND (user_email LIKE ? OR user_name LIKE ?)")
		args = append(args, "%"+user+"%", "%"+user+"%")
	}
	if dept := strings.TrimSpace(filter.Dept); dept != "" {
		sb.WriteString(" AND department LIKE ?")
		args = append(args, "%"+dept+"%")
	}
	if job := strings.TrimSpace(filter.Job); job != "" {
		sb.WriteString(" AND job_title LIKE ?")
		args = append(args, "%"+job+"%")
	}
	if hash := strings.TrimSpace(filter.Hash); hash != "" {
		sb.WriteString(" AND hash_id LIKE ?")
		args = append(args, "%"+hash+"%")
	}
	if ip := strings.TrimSpace(filter.IP); ip != "" {
		sb.WriteString(" AND ip_address LIKE ?")
		args = append(args, "%"+ip+"%")
	}
	if df := strings.TrimSpace(filter.DateFrom); df != "" {
		if t, err := time.ParseInLocation("2006-01-02", df, time.Local); err == nil {
			sb.WriteString(" AND signed_at >= ?")
			args = append(args, t)
		}
	}
	if dt := strings.TrimSpace(filter.DateTo); dt != "" {
		if t, err := time.ParseInLocation("2006-01-02", dt, time.Local); err == nil {
			sb.WriteString(" AND signed_at < ?")
			args = append(args, t.Add(24*time.Hour))
		}
	}

	return sb.String(), args
}

func (r *sqliteRepository) queryList(ctx context.Context, query string, args ...any) ([]models.SignatureRecord, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list signatures: %w", err)
	}
	defer rows.Close()

	records := make([]models.SignatureRecord, 0)
	for rows.Next() {
		rec, err := scanSignature(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan signature row: %w", err)
		}
		records = append(records, *rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}
	return records, nil
}

func (r *sqliteRepository) List(ctx context.Context, filter models.FilterCriteria) ([]models.SignatureRecord, error) {
	query, args := r.buildFilterQuery(`SELECT `+signatureColumns+` FROM signatures`, filter)
	return r.queryList(ctx, query+" ORDER BY signed_at DESC", args...)
}

func (r *sqliteRepository) ListChain(ctx context.Context) ([]models.SignatureRecord, error) {
	return r.queryList(ctx, `SELECT `+signatureColumns+` FROM signatures WHERE chain_seq IS NOT NULL ORDER BY chain_seq ASC`)
}

func (r *sqliteRepository) Count(ctx context.Context, filter models.FilterCriteria) (int, error) {
	query, args := r.buildFilterQuery(`SELECT COUNT(*) FROM signatures`, filter)
	var count int
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count signatures: %w", err)
	}
	return count, nil
}
