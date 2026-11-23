package audit

import (
	"strings"
	"testing"
	"time"

	"zenith-signer/internal/models"
)

const genesis = "GENESIS"

func buildChain(s *Sealer, n int) []models.SignatureRecord {
	recs := make([]models.SignatureRecord, n)
	prev := genesis
	base := time.Date(2026, 11, 23, 10, 0, 0, 123456789, time.FixedZone("BRT", -3*3600))
	for i := range recs {
		recs[i] = models.SignatureRecord{
			ID: int64(i + 1), ChainSeq: int64(i + 1), PrevHash: prev,
			DocumentName: "Politica", DocumentVersionID: 7, ContentHash: "abc",
			UserEmail: "user@empresa.com", UserName: "Usuário", SignedAt: base.Add(time.Duration(i) * time.Minute),
			IPAddress: "10.0.0.1", UserAgent: "Mozilla",
		}
		recs[i].HashID = s.Seal(&recs[i])
		prev = recs[i].HashID
	}
	return recs
}

func TestSealDeterministicAndKeyed(t *testing.T) {
	rec := buildChain(NewSealer([]byte("k1")), 1)[0]
	a := NewSealer([]byte("k1")).Seal(&rec)
	if a != rec.HashID || len(a) != 64 {
		t.Fatalf("seal must be deterministic 64-hex, got %q", a)
	}
	if NewSealer([]byte("k2")).Seal(&rec) == a {
		t.Errorf("seal must depend on the key")
	}
	// Same instant in another time zone seals identically.
	other := rec
	other.SignedAt = rec.SignedAt.UTC()
	if NewSealer([]byte("k1")).Seal(&other) != a {
		t.Errorf("seal must be time-zone independent")
	}
}

func TestSealCoversEveryField(t *testing.T) {
	s := NewSealer([]byte("k"))
	base := buildChain(s, 1)[0]
	mutations := map[string]func(r *models.SignatureRecord){
		"doc":        func(r *models.SignatureRecord) { r.DocumentName = "Outra" },
		"version":    func(r *models.SignatureRecord) { r.DocumentVersionID = 8 },
		"content":    func(r *models.SignatureRecord) { r.ContentHash = "def" },
		"email":      func(r *models.SignatureRecord) { r.UserEmail = "x@empresa.com" },
		"name":       func(r *models.SignatureRecord) { r.UserName = "Outro" },
		"dept":       func(r *models.SignatureRecord) { r.Department = "TI" },
		"job":        func(r *models.SignatureRecord) { r.JobTitle = "Gerente" },
		"location":   func(r *models.SignatureRecord) { r.OfficeLocation = "Matriz" },
		"time":       func(r *models.SignatureRecord) { r.SignedAt = r.SignedAt.Add(time.Nanosecond) },
		"ip":         func(r *models.SignatureRecord) { r.IPAddress = "10.0.0.2" },
		"user agent": func(r *models.SignatureRecord) { r.UserAgent = "curl" },
		"seq":        func(r *models.SignatureRecord) { r.ChainSeq = 2 },
		"prev":       func(r *models.SignatureRecord) { r.PrevHash = "x" },
		// Field boundaries are length-prefixed: moving text between fields must change the seal.
		"boundary": func(r *models.SignatureRecord) { r.UserName = "Usuário" + "Mozilla"; r.UserAgent = "" },
	}
	for name, mutate := range mutations {
		r := base
		mutate(&r)
		if s.Seal(&r) == base.HashID {
			t.Errorf("changing %s did not change the seal", name)
		}
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	s := NewSealer([]byte("segredo"))

	if rep := s.Verify(buildChain(s, 5), genesis); !rep.OK() || rep.Checked != 5 {
		t.Fatalf("intact chain must verify: %+v", rep)
	}
	if rep := s.Verify(nil, genesis); !rep.OK() {
		t.Fatalf("empty chain must verify")
	}

	cases := map[string]func([]models.SignatureRecord) []models.SignatureRecord{
		"field edited": func(c []models.SignatureRecord) []models.SignatureRecord {
			c[2].IPAddress = "1.2.3.4"
			return c
		},
		"record deleted": func(c []models.SignatureRecord) []models.SignatureRecord {
			return append(c[:2], c[3:]...)
		},
		"record re-sealed with another key": func(c []models.SignatureRecord) []models.SignatureRecord {
			c[1].UserName = "Fraude"
			c[1].HashID = NewSealer([]byte("outra")).Seal(&c[1])
			return c
		},
		"first record removed": func(c []models.SignatureRecord) []models.SignatureRecord {
			return c[1:]
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			rep := s.Verify(tamper(buildChain(s, 5)), genesis)
			if rep.OK() {
				t.Fatalf("tampering not detected")
			}
			if !strings.Contains(rep.Issues[0].Problem, " ") {
				t.Errorf("issue must carry a description")
			}
		})
	}

	if rep := NewSealer([]byte("chave-errada")).Verify(buildChain(s, 3), genesis); rep.OK() {
		t.Errorf("verification with a different key must fail")
	}
}
