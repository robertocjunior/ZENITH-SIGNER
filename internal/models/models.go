package models

import (
	"encoding/xml"
	"time"
)

// UserProfile represents the user data returned by Microsoft Graph API.
type UserProfile struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
	Department        string `json:"department"`
	JobTitle          string `json:"jobTitle"`
	OfficeLocation    string `json:"officeLocation"`
}

// EffectiveEmail returns the best available email for the user.
func (u *UserProfile) EffectiveEmail() string {
	if u.Mail != "" {
		return u.Mail
	}
	return u.UserPrincipalName
}

// SignatureRecord represents a completed electronic document confirmation.
type SignatureRecord struct {
	ID           int64  `xml:"id" json:"id"`
	HashID       string `xml:"hash_id" json:"hash_id"`
	DocumentName string `xml:"document_name" json:"document_name"`
	// DocumentTitle is the display name from the document registry (empty when
	// the doc is not registered). Not part of the audit seal.
	DocumentTitle  string    `xml:"document_title,omitempty" json:"document_title,omitempty"`
	UserName       string    `xml:"user_name" json:"user_name"`
	UserEmail      string    `xml:"user_email" json:"user_email"`
	Department     string    `xml:"department" json:"department"`
	JobTitle       string    `xml:"job_title" json:"job_title"`
	OfficeLocation string    `xml:"office_location" json:"office_location"`
	SignedAt       time.Time `xml:"signed_at" json:"signed_at"`
	UserAgent      string    `xml:"user_agent" json:"user_agent"`
	IPAddress      string    `xml:"ip_address" json:"ip_address"`

	// DocumentVersionID links the signature to the exact document version read
	// (0 for documents not registered from Outline and for legacy records).
	DocumentVersionID int64 `xml:"document_version_id" json:"document_version_id"`
	// ContentHash is the SHA-256 of the normalised document text that was signed.
	ContentHash string `xml:"content_hash,omitempty" json:"content_hash,omitempty"`
	// PrevHash and ChainSeq place the record in the tamper-evident audit chain
	// (empty/zero for legacy records created before the chain existed).
	PrevHash string `xml:"prev_hash,omitempty" json:"prev_hash,omitempty"`
	ChainSeq int64  `xml:"chain_seq,omitempty" json:"chain_seq,omitempty"`
}

// XMLSignatures wraps multiple signature records for XML export.
type XMLSignatures struct {
	XMLName xml.Name          `xml:"assinaturas"`
	Records []SignatureRecord `xml:"assinatura"`
}

// FilterCriteria defines filtering options for querying signature records.
type FilterCriteria struct {
	Document string
	User     string
	Dept     string
	Job      string
	Hash     string
	IP       string
	DateFrom string
	DateTo   string
}

// HealthResponse represents system health and liveness state for 24/7 monitoring.
type HealthResponse struct {
	Status    string            `json:"status"`
	Uptime    string            `json:"uptime"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]string `json:"checks"`
}

// Embed status values for registered documents.
const (
	EmbedInserted = "inserted" // inserted at the top of the Outline page and rendered as an embed
	EmbedLink     = "link"     // inserted via API but Outline rendered it as a plain link
	EmbedExisting = "existing" // the page already contained the widget URL
	EmbedManual   = "manual"   // not inserted: the admin must paste the URL with /embed
)

// Version decision values.
const (
	DecisionInitial = "initial" // first version captured at registration (signature required)
	DecisionPending = "pending" // content changed; waiting for an admin decision
	DecisionResign  = "resign"  // admin required everyone to sign this version again
	DecisionMinor   = "minor"   // admin marked the change as minor; previous signatures stay valid
)

// Document is a document registered from Outline.
type Document struct {
	ID                int64
	DocKey            string // value used in /assinar?doc=
	OutlineID         string
	Title             string
	OutlineURL        string
	CollectionID      string
	CurrentVersionID  int64 // latest captured content
	RequiredVersionID int64 // signatures on versions older than this one are outdated
	EmbedStatus       string
	Active            bool
	CreatedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// DocumentVersion is a snapshot of a registered document's content.
type DocumentVersion struct {
	ID              int64
	DocumentID      int64
	VersionNo       int
	OutlineRevision int
	Title           string
	ContentHash     string
	Content         string
	Decision        string
	DecidedBy       string
	DecidedAt       *time.Time
	CreatedAt       time.Time
}

// DocumentSummary is a registered document with signature statistics for the admin panel.
type DocumentSummary struct {
	Document
	CurrentVersionNo  int
	RequiredVersionNo int
	ValidSigners      int   // distinct users with a signature on the required version or later
	OutdatedSigners   int   // distinct users whose latest signature predates the required version
	PendingVersionID  int64 // latest version awaiting a decision (0 if none)
	PendingVersionNo  int
}
