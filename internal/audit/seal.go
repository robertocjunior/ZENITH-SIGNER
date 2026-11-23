// Package audit seals signature records into a tamper-evident chain.
//
// Each new signature gets a sequence number, the hash of the previous record
// (PrevHash) and its own hash (HashID): an HMAC-SHA256, keyed with a server
// secret, over every audited field. Without the key the hash cannot be
// recomputed, and changing, inserting or deleting a chained record breaks the
// chain from that point on.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"zenith-signer/internal/models"
)

const sealVersion = "zenith-signer/seal/v1"

// Sealer computes record hashes with a secret key.
type Sealer struct {
	key []byte
}

// NewSealer creates a Sealer. The key must stay the same forever, otherwise
// existing records can no longer be verified.
func NewSealer(key []byte) *Sealer {
	k := make([]byte, len(key))
	copy(k, key)
	return &Sealer{key: k}
}

// canonical serialises the audited fields unambiguously (length-prefixed),
// so no combination of field values can collide with another.
func canonical(rec *models.SignatureRecord) []byte {
	fields := []string{
		sealVersion,
		strconv.FormatInt(rec.ChainSeq, 10),
		rec.PrevHash,
		rec.DocumentName,
		strconv.FormatInt(rec.DocumentVersionID, 10),
		rec.ContentHash,
		strings.ToLower(strings.TrimSpace(rec.UserEmail)),
		rec.UserName,
		rec.Department,
		rec.JobTitle,
		rec.OfficeLocation,
		rec.SignedAt.UTC().Format(time.RFC3339Nano),
		rec.IPAddress,
		rec.UserAgent,
	}
	var b strings.Builder
	for _, f := range fields {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// Seal returns the hex HMAC-SHA256 of rec's audited fields.
func (s *Sealer) Seal(rec *models.SignatureRecord) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(canonical(rec))
	return hex.EncodeToString(mac.Sum(nil))
}

// Issue describes a broken link found while verifying the chain.
type Issue struct {
	ChainSeq int64
	RecordID int64
	Hash     string
	Problem  string
}

// Report is the result of verifying the audit chain.
type Report struct {
	Checked int
	Issues  []Issue
}

// OK reports whether the whole chain verified.
func (r Report) OK() bool { return len(r.Issues) == 0 }

// Verify checks records (ordered by ChainSeq) for gaps, broken links and
// hashes that do not match their content. genesis is the PrevHash expected
// for the first record.
func (s *Sealer) Verify(records []models.SignatureRecord, genesis string) Report {
	rep := Report{Checked: len(records)}
	expectedSeq := int64(1)
	expectedPrev := genesis

	for i := range records {
		rec := &records[i]
		issue := func(problem string) {
			rep.Issues = append(rep.Issues, Issue{ChainSeq: rec.ChainSeq, RecordID: rec.ID, Hash: rec.HashID, Problem: problem})
		}

		if rec.ChainSeq != expectedSeq {
			issue(fmt.Sprintf("sequência inesperada: esperado %d, encontrado %d (registro removido ou inserido fora da cadeia)", expectedSeq, rec.ChainSeq))
		}
		if rec.PrevHash != expectedPrev {
			issue("hash anterior não confere com o registro precedente (registro anterior alterado ou removido)")
		}
		if !hmac.Equal([]byte(s.Seal(rec)), []byte(rec.HashID)) {
			issue("conteúdo do registro não confere com o selo (dados alterados após a assinatura)")
		}

		expectedSeq = rec.ChainSeq + 1
		expectedPrev = rec.HashID
	}
	return rep
}
