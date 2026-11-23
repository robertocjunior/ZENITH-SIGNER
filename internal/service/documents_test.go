package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"zenith-signer/internal/audit"
	"zenith-signer/internal/config"
	"zenith-signer/internal/database"
	"zenith-signer/internal/models"
	"zenith-signer/internal/outline"
)

// fakeOutline is an in-memory Outline used by service tests.
type fakeOutline struct {
	mu          sync.Mutex
	docs        map[string]*outline.Document
	renderEmbed bool  // whether prepended "[url](url)" becomes an embed node
	prependErr  error // forced error for Prepend
	prepends    int
}

func newFakeOutline() *fakeOutline {
	return &fakeOutline{docs: map[string]*outline.Document{}, renderEmbed: true}
}

func (f *fakeOutline) add(id, urlID, title, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs[id] = &outline.Document{ID: id, URLID: urlID, Title: title, Text: text, URL: "/doc/x-" + urlID, Revision: 1}
}

func (f *fakeOutline) edit(id, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.docs[id]
	d.Text = text
	d.Revision++
}

func (f *fakeOutline) find(id string) *outline.Document {
	if d, ok := f.docs[id]; ok {
		return d
	}
	for _, d := range f.docs {
		if d.URLID == id {
			return d
		}
	}
	return nil
}

func (f *fakeOutline) Info(_ context.Context, id string) (*outline.Document, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.find(id)
	if d == nil {
		return nil, outline.ErrNotFound
	}
	cp := *d
	return &cp, nil
}

func (f *fakeOutline) InfoStructured(ctx context.Context, id string) (*outline.Document, error) {
	d, err := f.Info(ctx, id)
	if err != nil {
		return nil, err
	}
	nodeType := "paragraph"
	if f.renderEmbed {
		nodeType = "embed"
	}
	var hrefs []map[string]any
	for _, line := range strings.Split(d.Text, "\n") {
		if strings.HasPrefix(line, "[http") {
			href := line[1:strings.Index(line, "]")]
			hrefs = append(hrefs, map[string]any{"type": nodeType, "attrs": map[string]any{"href": href}})
		}
	}
	d.Data, _ = json.Marshal(map[string]any{"type": "doc", "content": hrefs})
	return d, nil
}

func (f *fakeOutline) SearchTitles(_ context.Context, q string, _ int) ([]outline.Document, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []outline.Document
	for _, d := range f.docs {
		if strings.Contains(strings.ToLower(d.Title), strings.ToLower(q)) {
			out = append(out, *d)
		}
	}
	return out, nil
}

func (f *fakeOutline) Prepend(_ context.Context, id, md string) (*outline.Document, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prependErr != nil {
		return nil, f.prependErr
	}
	d := f.find(id)
	if d == nil {
		return nil, outline.ErrNotFound
	}
	d.Text = md + d.Text
	d.Revision++
	f.prepends++
	cp := *d
	return &cp, nil
}

const appURL = "https://assinador.empresa.com"

type docFixture struct {
	repo    database.Repository
	docRepo database.DocumentRepository
	docs    *DocumentService
	signer  SignerService
	sealer  *audit.Sealer
	outline *fakeOutline
	sender  *countingSender
}

func newDocFixture(t *testing.T) *docFixture {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := database.Open(config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "docs.db"), BusyTimeoutMs: 5000}, logger)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.Migrate(context.Background(), db, logger); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	f := &docFixture{
		repo:    database.NewRepository(db),
		docRepo: database.NewDocumentRepository(db),
		outline: newFakeOutline(),
		sealer:  audit.NewSealer([]byte("chave")),
		sender:  &countingSender{},
	}
	f.docs = NewDocumentService(f.docRepo, f.outline, "https://wiki.empresa.com.br", appURL, logger)
	f.signer = NewSignerService(f.repo, f.sender, logger, WithDocuments(f.docRepo), WithSealer(f.sealer))
	return f
}

func (f *docFixture) sign(t *testing.T, doc, email string, expectedVersion int64) (*models.SignatureRecord, error) {
	t.Helper()
	return f.signer.SignDocument(context.Background(), SignRequest{Doc: doc, UserEmail: email, UserName: "U", ExpectedVersionID: expectedVersion})
}

func TestParseOutlineRef(t *testing.T) {
	cases := map[string]string{
		"AbC123": "AbC123",
		"https://wiki.empresa.com.br/doc/politica-de-ferias-AbC123":       "AbC123",
		"https://wiki.empresa.com.br/doc/politica-de-ferias-AbC123/edit":  "AbC123",
		"https://wiki.empresa.com.br/s/share/doc/politica-AbC123#heading": "AbC123",
		"  uuid-1234  ": "uuid-1234",
	}
	for in, want := range cases {
		if got := ParseOutlineRef(in); got != want {
			t.Errorf("ParseOutlineRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegisterInsertsEmbedAtTop(t *testing.T) {
	f := newDocFixture(t)
	f.outline.add("uuid-1", "AbC123", "Política de Férias", "# Política\n\nTexto original.")

	res, err := f.docs.Register(context.Background(), RegisterInput{OutlineRef: "https://wiki.empresa.com.br/doc/politica-AbC123", InsertEmbed: true, Admin: "admin@empresa.com"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if res.Document.DocKey != "AbC123" || res.Document.EmbedStatus != models.EmbedInserted {
		t.Errorf("unexpected document: %+v", res.Document)
	}
	if res.WidgetURL != appURL+"/assinar?doc=AbC123" {
		t.Errorf("widget url: %s", res.WidgetURL)
	}
	d, _ := f.outline.Info(context.Background(), "uuid-1")
	if !strings.HasPrefix(d.Text, "["+res.WidgetURL+"]("+res.WidgetURL+")\n\n# Política") {
		t.Errorf("embed must be prepended at the top, got %q", d.Text)
	}

	// Inserting the embed must not create a new version on the next sync.
	changed, err := f.docs.SyncDocument(context.Background(), res.Document)
	if err != nil || changed {
		t.Errorf("embed insertion must not count as content change (changed=%v err=%v)", changed, err)
	}

	// Registering again is rejected (same Outline doc or same key).
	if _, err := f.docs.Register(context.Background(), RegisterInput{OutlineRef: "uuid-1"}); !errors.Is(err, database.ErrDocumentExists) {
		t.Errorf("duplicate registration must fail, got %v", err)
	}
}

func TestRegisterEmbedOutcomes(t *testing.T) {
	ctx := context.Background()

	t.Run("rendered as link", func(t *testing.T) {
		f := newDocFixture(t)
		f.outline.renderEmbed = false
		f.outline.add("u", "K1", "Doc", "texto")
		res, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u", InsertEmbed: true})
		if err != nil || res.Document.EmbedStatus != models.EmbedLink {
			t.Fatalf("expected link status, got %+v %v", res, err)
		}
	})

	t.Run("cannot confirm rendering (older Outline)", func(t *testing.T) {
		f := newDocFixture(t)
		f.outline.add("u", "K1", "Doc", "texto")
		noData := &noStructuredOutline{f.outline}
		f.docs = NewDocumentService(f.docRepo, noData, "", appURL, slog.New(slog.NewTextHandler(io.Discard, nil)))
		res, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u", InsertEmbed: true})
		if err != nil || res.Document.EmbedStatus != models.EmbedLink || !strings.Contains(res.EmbedError, "confira a página") {
			t.Fatalf("expected unverified warning, got %+v %v", res, err)
		}
	})

	t.Run("already present", func(t *testing.T) {
		f := newDocFixture(t)
		f.outline.add("u", "K1", "Doc", "texto\n\n["+appURL+"/assinar?doc=K1]("+appURL+"/assinar?doc=K1)")
		res, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u", InsertEmbed: true})
		if err != nil || res.Document.EmbedStatus != models.EmbedExisting || f.outline.prepends != 0 {
			t.Fatalf("existing embed must be detected and not duplicated: %+v prepends=%d err=%v", res, f.outline.prepends, err)
		}
	})

	t.Run("not requested", func(t *testing.T) {
		f := newDocFixture(t)
		f.outline.add("u", "K1", "Doc", "texto")
		res, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u", InsertEmbed: false})
		if err != nil || res.Document.EmbedStatus != models.EmbedManual || f.outline.prepends != 0 {
			t.Fatalf("expected manual without touching Outline: %+v %v", res, err)
		}
	})

	t.Run("prepend fails", func(t *testing.T) {
		f := newDocFixture(t)
		f.outline.prependErr = errors.New("forbidden")
		f.outline.add("u", "K1", "Doc", "texto")
		res, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u", InsertEmbed: true})
		if err != nil || res.Document.EmbedStatus != models.EmbedManual || res.EmbedError == "" {
			t.Fatalf("expected manual with error message (registration still succeeds): %+v %v", res, err)
		}
	})

	t.Run("custom key and unknown doc", func(t *testing.T) {
		f := newDocFixture(t)
		f.outline.add("u", "K1", "Doc", "texto")
		res, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u", DocKey: "POLITICA-2026"})
		if err != nil || res.Document.DocKey != "POLITICA-2026" {
			t.Fatalf("custom key not applied: %+v %v", res, err)
		}
		if _, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "nao-existe"}); err == nil {
			t.Errorf("unknown Outline doc must fail")
		}
		if _, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u", DocKey: "bad\nkey"}); err == nil {
			t.Errorf("invalid key must fail")
		}
	})
}

func TestVersioningAndResignFlow(t *testing.T) {
	f := newDocFixture(t)
	ctx := context.Background()
	f.outline.add("u", "POL", "Política", "Versão 1 do texto")
	res, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u", InsertEmbed: true})
	if err != nil {
		t.Fatal(err)
	}
	v1 := res.Document.CurrentVersionID

	// Maria signs v1.
	sig1, err := f.sign(t, "POL", "maria@empresa.com", v1)
	if err != nil || sig1.DocumentVersionID != v1 || sig1.ContentHash == "" || sig1.ChainSeq != 1 {
		t.Fatalf("sign v1: %+v %v", sig1, err)
	}

	// Text changes in Outline -> sync creates v2 pending; Maria's signature stays valid.
	f.outline.edit("u", "["+appURL+"/assinar?doc=POL]("+appURL+"/assinar?doc=POL)\n\nVersão 2 do texto")
	changed, err := f.docs.SyncByOutlineID(ctx, "u")
	if err != nil || !changed {
		t.Fatalf("change not detected: %v %v", changed, err)
	}
	doc, _ := f.docRepo.GetDocumentByKey(ctx, "POL")
	v2 := doc.CurrentVersionID
	if v2 == v1 || doc.RequiredVersionID != v1 {
		t.Fatalf("v2 must be current but not required yet: %+v", doc)
	}
	st, _ := f.signer.GetStatus(ctx, "POL", "maria@empresa.com")
	if !st.Valid || st.Outdated {
		t.Errorf("pending change must not invalidate signatures: %+v", st)
	}

	// A stale widget (still showing v1) cannot sign anymore.
	if _, err := f.sign(t, "POL", "joao@empresa.com", v1); !errors.Is(err, ErrDocumentChanged) {
		t.Errorf("signing a stale version must fail with ErrDocumentChanged, got %v", err)
	}
	// João signs v2 (what he actually read).
	sigJoao, err := f.sign(t, "POL", "joao@empresa.com", v2)
	if err != nil || sigJoao.DocumentVersionID != v2 {
		t.Fatalf("joão sign v2: %+v %v", sigJoao, err)
	}

	// Minor decision keeps everything valid.
	pending, _ := f.docRepo.ListDocuments(ctx)
	if pending[0].PendingVersionID != v2 {
		t.Fatalf("v2 must be pending: %+v", pending[0])
	}

	// Admin requires re-signing v2.
	if err := f.docs.Decide(ctx, v2, models.DecisionResign, "admin@empresa.com"); err != nil {
		t.Fatal(err)
	}
	st, _ = f.signer.GetStatus(ctx, "POL", "maria@empresa.com")
	if st.Valid || !st.Outdated {
		t.Errorf("after resign decision Maria must be outdated: %+v", st)
	}
	st, _ = f.signer.GetStatus(ctx, "POL", "joao@empresa.com")
	if !st.Valid {
		t.Errorf("João signed v2 and must stay valid: %+v", st)
	}
	if err := f.docs.Decide(ctx, v2, models.DecisionMinor, "admin@empresa.com"); !errors.Is(err, database.ErrVersionNotPending) {
		t.Errorf("deciding twice must fail, got %v", err)
	}

	// Maria re-signs: new record on v2, old v1 record kept for history.
	sig2, err := f.sign(t, "POL", "maria@empresa.com", v2)
	if err != nil || sig2.ID == sig1.ID || sig2.DocumentVersionID != v2 {
		t.Fatalf("re-sign: %+v %v", sig2, err)
	}
	summary, _ := f.docRepo.ListDocuments(ctx)
	if summary[0].ValidSigners != 2 || summary[0].OutdatedSigners != 0 || summary[0].PendingVersionID != 0 {
		t.Errorf("unexpected summary: %+v", summary[0])
	}

	// Signing again is idempotent.
	again, err := f.sign(t, "POL", "maria@empresa.com", v2)
	if err != nil || again.ID != sig2.ID {
		t.Errorf("idempotent re-sign failed: %+v %v", again, err)
	}

	// Every signature is in an intact audit chain.
	chain, _ := f.repo.ListChain(ctx)
	if len(chain) != 3 {
		t.Fatalf("expected 3 chained records, got %d", len(chain))
	}
	if rep := f.sealer.Verify(chain, database.GenesisHash); !rep.OK() {
		t.Errorf("chain must verify: %+v", rep.Issues)
	}
	if hash, _ := f.repo.GetByHash(ctx, sig1.HashID); hash == nil {
		t.Errorf("old receipts must remain verifiable")
	}
}

func TestMinorDecisionKeepsSignaturesValid(t *testing.T) {
	f := newDocFixture(t)
	ctx := context.Background()
	f.outline.add("u", "POL", "Política", "texto 1")
	res, _ := f.docs.Register(ctx, RegisterInput{OutlineRef: "u"})
	if _, err := f.sign(t, "POL", "maria@empresa.com", 0); err != nil {
		t.Fatal(err)
	}
	f.outline.edit("u", "texto 1 (corrigido)")
	_, _ = f.docs.SyncDocument(ctx, res.Document)
	doc, _ := f.docRepo.GetDocumentByKey(ctx, "POL")
	if err := f.docs.Decide(ctx, doc.CurrentVersionID, models.DecisionMinor, "admin"); err != nil {
		t.Fatal(err)
	}
	st, _ := f.signer.GetStatus(ctx, "POL", "maria@empresa.com")
	if !st.Valid {
		t.Errorf("minor change must keep signature valid: %+v", st)
	}
}

func TestAcceptPriorSignaturesAndInactive(t *testing.T) {
	f := newDocFixture(t)
	ctx := context.Background()

	// Signature made before the document was registered (legacy widget, version 0).
	legacy, err := f.sign(t, "POLITICA-2026", "maria@empresa.com", 0)
	if err != nil || legacy.DocumentVersionID != 0 {
		t.Fatalf("legacy sign: %+v %v", legacy, err)
	}

	f.outline.add("u", "AbC", "Política 2026", "texto")
	if _, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u", DocKey: "POLITICA-2026", AcceptPrior: true}); err != nil {
		t.Fatal(err)
	}
	st, _ := f.signer.GetStatus(ctx, "POLITICA-2026", "maria@empresa.com")
	if !st.Valid || st.Document == nil {
		t.Errorf("prior signature must stay valid with AcceptPrior: %+v", st)
	}

	// Without AcceptPrior the legacy signature is outdated.
	f.outline.add("u2", "XyZ", "Outra", "texto")
	if _, err := f.sign(t, "OUTRA", "maria@empresa.com", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.docs.Register(ctx, RegisterInput{OutlineRef: "u2", DocKey: "OUTRA"}); err != nil {
		t.Fatal(err)
	}
	st, _ = f.signer.GetStatus(ctx, "OUTRA", "maria@empresa.com")
	if st.Valid || !st.Outdated {
		t.Errorf("prior signature must be outdated without AcceptPrior: %+v", st)
	}

	// Inactive documents refuse new signatures.
	doc, _ := f.docRepo.GetDocumentByKey(ctx, "OUTRA")
	_ = f.docRepo.SetActive(ctx, doc.ID, false)
	if _, err := f.sign(t, "OUTRA", "joao@empresa.com", 0); !errors.Is(err, ErrDocumentInactive) {
		t.Errorf("inactive doc must refuse signatures, got %v", err)
	}
}

func TestSyncUpdatesTitleWithoutNewVersion(t *testing.T) {
	f := newDocFixture(t)
	ctx := context.Background()
	f.outline.add("u", "POL", "Título antigo", "texto")
	res, _ := f.docs.Register(ctx, RegisterInput{OutlineRef: "u"})
	f.outline.mu.Lock()
	f.outline.docs["u"].Title = "Título novo"
	f.outline.mu.Unlock()
	changed, err := f.docs.SyncDocument(ctx, res.Document)
	if err != nil || changed {
		t.Fatalf("title-only change must not create a version: %v %v", changed, err)
	}
	doc, _ := f.docRepo.GetDocumentByKey(ctx, "POL")
	if doc.Title != "Título novo" || doc.CurrentVersionID != res.Document.CurrentVersionID {
		t.Errorf("title not updated: %+v", doc)
	}
}

func TestDocumentServiceDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewDocumentService(nil, nil, "", appURL, logger)
	if s.Enabled() {
		t.Fatal("must be disabled without client")
	}
	if _, err := s.Register(context.Background(), RegisterInput{OutlineRef: "x"}); !errors.Is(err, ErrOutlineDisabled) {
		t.Errorf("expected ErrOutlineDisabled, got %v", err)
	}
	s.QueueSync("x") // must be a no-op
}

// noStructuredOutline simulates an Outline version that ignores x-api-version 3.
type noStructuredOutline struct{ *fakeOutline }

func (n *noStructuredOutline) InfoStructured(ctx context.Context, id string) (*outline.Document, error) {
	return n.Info(ctx, id)
}
