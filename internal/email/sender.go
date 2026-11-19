package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/smtp"
	"strings"
	"time"

	"zenith-signer/internal/config"
)

// Sender defines operations for sending emails.
type Sender interface {
	SendReceipt(ctx context.Context, toEmail, toName, docName, hashID, dateStr string) error
}

type office365Sender struct {
	cfg    config.SMTPConfig
	logger *slog.Logger
}

// NewSender creates an email sender configured for Office 365 / standard SMTP.
func NewSender(cfg config.SMTPConfig, logger *slog.Logger) Sender {
	return &office365Sender{
		cfg:    cfg,
		logger: logger,
	}
}

// loginAuth implements the AUTH LOGIN mechanism required by Office 365 and some corporate SMTP relays.
type loginAuth struct {
	username, password string
}

func newLoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username: username, password: password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		prompt := strings.ToLower(string(fromServer))
		switch {
		case strings.Contains(prompt, "username"):
			return []byte(a.username), nil
		case strings.Contains(prompt, "password"):
			return []byte(a.password), nil
		default:
			return nil, errors.New("unknown SMTP auth prompt: " + string(fromServer))
		}
	}
	return nil, nil
}

const receiptHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Confirmação de Leitura - {{.SignatureName}}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #ffffff; margin-top: 20px; margin-bottom: 20px; border-collapse: collapse;">
        <!-- Barra Superior -->
        <tr>
            <td style="background-color: {{.AccentColor}}; height: 10px; font-size: 0; line-height: 0;">&nbsp;</td>
        </tr>
        {{if .LogoURL}}<!-- Cabeçalho com Logo -->
        <tr>
            <td align="center" style="padding: 30px 20px 20px 20px; background-color: #ffffff;">
                <img src="{{.LogoURL}}" alt="{{.SignatureName}}" width="180" style="display: block; border: 0;">
            </td>
        </tr>
        {{end}}<!-- Conteúdo Principal -->
        <tr>
            <td style="padding: 20px 30px 30px 30px; color: #333333; font-size: 16px; line-height: 24px;">
                <h2 style="color: #5cb85c; margin-top: 0; font-size: 22px;">Confirmação de Leitura Registrada</h2>
                <p>Olá{{if .ToName}}, <strong>{{.ToName}}</strong>{{end}},</p>
                <p>Confirmamos que você leu e aceitou eletronicamente o documento corporativo abaixo:</p>
                
                <!-- Caixa de Sucesso -->
                <table width="100%" border="0" cellspacing="0" cellpadding="10" style="margin-top: 20px; margin-bottom: 20px; background-color: #f4fdf4; border-left: 4px solid #5cb85c;">
                    <tr>
                        <td style="font-size: 14px; color: #555555;">
                            <strong>Documento:</strong> {{.DocName}}<br>
                            <strong>Data/Hora da Assinatura:</strong> {{.DateStr}}<br>
                            <strong>Código Único (Hash):</strong> <span style="font-family: monospace; word-break: break-all;">{{.HashID}}</span>
                        </td>
                    </tr>
                </table>

                <p style="margin-bottom: 0; color: #777777; font-size: 14px;">Atenciosamente,<br><strong>{{.SignatureName}}</strong></p>
            </td>
        </tr>
        <!-- Barra Inferior -->
        <tr>
            <td style="background-color: {{.AccentColor}}; height: 10px; font-size: 0; line-height: 0;">&nbsp;</td>
        </tr>
        <!-- Rodapé -->
        <tr>
            <td align="center" style="padding: 15px; background-color: #eeeeee; color: #777777; font-size: 12px;">
                Este é um e-mail automático enviado pelo sistema. Por favor, não responda.<br>
                <span style="font-size: 12px; color: #999999;">ZENITH-SIGNER</span>
            </td>
        </tr>
    </table>
</body>
</html>`

var parsedReceiptTmpl = template.Must(template.New("receipt").Parse(receiptHTMLTemplate))

type receiptTemplateData struct {
	ToName        string
	DocName       string
	HashID        string
	DateStr       string
	LogoURL       string
	AccentColor   string
	SignatureName string
}

func BuildReceiptMessage(cfg config.SMTPConfig, toEmail, toName, docName, hashID, dateStr string) (string, string) {
	subject := fmt.Sprintf("Confirmação de Leitura: %s", docName)

	accentColor := strings.TrimSpace(cfg.AccentColor)
	if accentColor == "" {
		accentColor = "#8BC74B"
	} else if !strings.HasPrefix(accentColor, "#") {
		accentColor = "#" + accentColor
	}

	signatureName := strings.TrimSpace(cfg.SignatureName)
	if signatureName == "" {
		signatureName = "Zenith Signer"
	}

	var htmlBuf bytes.Buffer
	_ = parsedReceiptTmpl.Execute(&htmlBuf, receiptTemplateData{
		ToName:        strings.TrimSpace(toName),
		DocName:       docName,
		HashID:        hashID,
		DateStr:       dateStr,
		LogoURL:       strings.TrimSpace(cfg.LogoURL),
		AccentColor:   accentColor,
		SignatureName: signatureName,
	})

	msg := "From: " + cfg.FromEmail + "\r\n" +
		"To: " + toEmail + "\r\n" +
		"Reply-To: " + cfg.ReplyEmail + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		htmlBuf.String()

	return subject, msg
}

func (s *office365Sender) SendReceipt(ctx context.Context, toEmail, toName, docName, hashID, dateStr string) error {
	if s.cfg.Host == "" || s.cfg.Username == "" || s.cfg.Password == "" {
		s.logger.Warn("SMTP configuration incomplete; skipping email dispatch",
			slog.String("to", toEmail),
			slog.String("doc", docName),
		)
		return nil
	}

	_, msg := BuildReceiptMessage(s.cfg, toEmail, toName, docName, hashID, dateStr)
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	var lastErr error
	maxRetries := s.cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 1
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := s.dialAndSend(addr, toEmail, msg)
		if err == nil {
			s.logger.Info("receipt email sent successfully",
				slog.String("to", toEmail),
				slog.String("doc", docName),
				slog.String("hash", hashID),
				slog.Int("attempt", attempt),
			)
			return nil
		}

		lastErr = err
		s.logger.Warn("temporary error sending email, retrying...",
			slog.String("to", toEmail),
			slog.Int("attempt", attempt),
			slog.Int("max_attempts", maxRetries),
			slog.String("error", err.Error()),
		)

		if attempt < maxRetries {
			delay := s.cfg.RetryDelay * time.Duration(attempt)
			time.Sleep(delay)
		}
	}

	s.logger.Error("failed to send receipt email after retries",
		slog.String("to", toEmail),
		slog.String("doc", docName),
		slog.String("error", lastErr.Error()),
	)
	return lastErr
}

func (s *office365Sender) dialAndSend(addr, toEmail, msg string) error {
	tlsConfig := &tls.Config{
		ServerName:         s.cfg.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}

	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial failed (%s): %w", addr, err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("starttls negotiation failed: %w", err)
		}
	} else {
		return errors.New("server does not support STARTTLS")
	}

	auth := newLoginAuth(s.cfg.Username, s.cfg.Password)
	if err = c.Auth(auth); err != nil {
		return fmt.Errorf("login authentication failed: %w", err)
	}

	if err = c.Mail(s.cfg.Username); err != nil {
		return fmt.Errorf("mail from failed: %w", err)
	}

	if err = c.Rcpt(toEmail); err != nil {
		return fmt.Errorf("rcpt to failed: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data command failed: %w", err)
	}

	if _, err = w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("failed to write message content: %w", err)
	}

	if err = w.Close(); err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return c.Quit()
}
