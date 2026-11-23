package email

import (
	"context"
	"io"
	"log/slog"
	"mime"
	"net/mail"
	"strings"
	"testing"

	"zenith-signer/internal/config"
)

func TestBuildReceiptMessage(t *testing.T) {
	cfg := config.SMTPConfig{
		FromEmail:  "Assinador <nfe@empresa.com>",
		ReplyEmail: "nfe@empresa.com",
	}
	to := "colaborador@empresa.com"
	name := "Colaborador Teste"
	doc := "Regulamento-Interno.pdf"
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	date := "29/09/2026 às 10:00:00"

	subject, msg := BuildReceiptMessage(cfg, to, name, doc, hash, date)

	if !strings.Contains(subject, "Regulamento-Interno.pdf") {
		t.Errorf("subject should contain doc name, got: %s", subject)
	}
	if !strings.Contains(msg, "Content-Type: text/html; charset=UTF-8") {
		t.Errorf("msg should use text/html content type")
	}
	if !strings.Contains(msg, "To: colaborador@empresa.com") {
		t.Errorf("msg should contain recipient email")
	}
	if !strings.Contains(msg, hash) {
		t.Errorf("msg should contain hash")
	}
	if !strings.Contains(msg, "background-color: #8BC74B;") {
		t.Errorf("msg should use default accent color #8BC74B")
	}
	if !strings.Contains(msg, "<strong>Zenith Signer</strong>") {
		t.Errorf("msg should use default signature name Zenith Signer")
	}
	if !strings.Contains(msg, "ZENITH-SIGNER") {
		t.Errorf("msg should contain ZENITH-SIGNER footer")
	}
	if strings.Contains(msg, "<img ") {
		t.Errorf("msg should not render logo img when LogoURL is empty")
	}
}

func TestBuildReceiptMessageCustomBranding(t *testing.T) {
	cfg := config.SMTPConfig{
		FromEmail:     "Assinador <nfe@empresa.com>",
		ReplyEmail:    "nfe@empresa.com",
		LogoURL:       "https://api.lipetral.com.br:5030/portalrh/Contents/images/default/masterpage/Logos/GRUPO_LIPETRAL.PNG",
		AccentColor:   "C4A54E",
		SignatureName: "STI - Grupo Lipetral",
	}

	_, msg := BuildReceiptMessage(cfg, "col@empresa.com", "Maria", "Doc.pdf", "abc123", "19/11/2026 17:00")

	if !strings.Contains(msg, `src="https://api.lipetral.com.br:5030/portalrh/Contents/images/default/masterpage/Logos/GRUPO_LIPETRAL.PNG"`) {
		t.Errorf("msg should contain configured logo URL")
	}
	if !strings.Contains(msg, "background-color: #C4A54E;") {
		t.Errorf("msg should normalize and use custom accent color #C4A54E")
	}
	if !strings.Contains(msg, "<strong>STI - Grupo Lipetral</strong>") {
		t.Errorf("msg should use custom signature name")
	}
}

func TestSenderIncompleteConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sender := NewSender(config.SMTPConfig{}, logger)

	// Incomplete config should gracefully return nil without crashing
	err := sender.SendReceipt(context.Background(), "test@empresa.com", "Test", "Doc.pdf", "hash", "date")
	if err != nil {
		t.Errorf("expected no error when SMTP is unconfigured, got: %v", err)
	}
}

func parseHeaders(t *testing.T, raw string) mail.Header {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("message is not a valid RFC 5322 message: %v", err)
	}
	return msg.Header
}

func TestBuildReceiptMessageHeaderInjection(t *testing.T) {
	cfg := config.SMTPConfig{
		FromEmail:  "Assinador <nfe@empresa.com>\r\nBcc: from-inject@evil.com",
		ReplyEmail: "nfe@empresa.com\nX-Injected: 1",
	}
	evilDoc := "Politica\r\nBcc: atacante@evil.com\r\n\r\n<h1>corpo falso</h1>"
	evilTo := "col@empresa.com\r\nCc: cc-inject@evil.com"

	subject, msg := BuildReceiptMessage(cfg, evilTo, "Nome\r\nX-Name: 1", evilDoc, "hash", "data")

	if strings.ContainsAny(subject, "\r\n") {
		t.Errorf("subject must not contain line breaks: %q", subject)
	}

	headerBlock := msg[:strings.Index(msg, "\r\n\r\n")]
	for _, line := range strings.Split(headerBlock, "\r\n") {
		name := strings.ToLower(strings.SplitN(line, ":", 2)[0])
		switch name {
		case "from", "to", "reply-to", "subject", "mime-version", "content-type":
		default:
			t.Errorf("unexpected header line (injection?): %q", line)
		}
	}

	h := parseHeaders(t, msg)
	for _, forbidden := range []string{"Bcc", "Cc", "X-Injected", "X-Name"} {
		if v := h.Get(forbidden); v != "" {
			t.Errorf("injected header %s present: %q", forbidden, v)
		}
	}
	if strings.Count(msg, "\r\n\r\n") < 1 || strings.Index(msg, "\r\n\r\n") != len(headerBlock) {
		t.Errorf("header/body separator misplaced")
	}
	decodedSubject, err := new(mime.WordDecoder).DecodeHeader(h.Get("Subject"))
	if err != nil {
		t.Fatalf("subject not decodable: %v", err)
	}
	if !strings.Contains(decodedSubject, "Bcc: atacante@evil.com") {
		t.Errorf("injected text should be neutralised inside the Subject value, got %q", decodedSubject)
	}
}

func TestBuildReceiptMessageEncodesUTF8Subject(t *testing.T) {
	cfg := config.SMTPConfig{FromEmail: "nfe@empresa.com"}
	doc := "Política de Férias"
	_, msg := BuildReceiptMessage(cfg, "col@empresa.com", "Maria", doc, "hash", "data")

	h := parseHeaders(t, msg)
	raw := h.Get("Subject")
	for _, r := range raw {
		if r > 127 {
			t.Fatalf("Subject header must be 7-bit (RFC 2047), got %q", raw)
		}
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(raw)
	if err != nil {
		t.Fatalf("subject not decodable: %v", err)
	}
	if decoded != "Confirmação de Leitura: "+doc {
		t.Errorf("unexpected decoded subject: %q", decoded)
	}
	if h.Get("Reply-To") != "" {
		t.Errorf("empty Reply-To should be omitted")
	}
}

func TestSendReceiptRejectsRecipientWithLineBreak(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Unreachable host: the check must fail before any network dial.
	sender := NewSender(config.SMTPConfig{Host: "127.0.0.1", Port: 1, Username: "u", Password: "p", MaxRetries: 1}, logger)
	err := sender.SendReceipt(context.Background(), "a@b.com\r\nBcc: x@evil.com", "N", "Doc", "h", "d")
	if err == nil || !strings.Contains(err.Error(), "invalid recipient") {
		t.Errorf("expected invalid recipient error, got %v", err)
	}
}
