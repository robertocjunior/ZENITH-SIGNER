package email

import (
	"context"
	"io"
	"log/slog"
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
