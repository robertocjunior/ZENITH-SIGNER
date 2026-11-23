// Package outline is a minimal client for the Outline wiki API
// (https://www.getoutline.com/developers) plus helpers to fingerprint
// document content and verify webhook signatures.
package outline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrNotFound is returned when Outline reports the document does not exist
// or the API key cannot access it.
var ErrNotFound = errors.New("outline: document not found or not accessible")

// Document is the subset of Outline's document model used by the signer.
type Document struct {
	ID           string    `json:"id"`
	URLID        string    `json:"urlId"`
	Title        string    `json:"title"`
	Text         string    `json:"text"`
	URL          string    `json:"url"`
	CollectionID string    `json:"collectionId"`
	Revision     int       `json:"revision"`
	UpdatedAt    time.Time `json:"updatedAt"`
	// Data is the ProseMirror JSON (only present when requested with API version 3).
	Data json.RawMessage `json:"data,omitempty"`
}

// Client calls the Outline API with an API key.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewClient creates a client for the Outline instance at baseURL.
func NewClient(baseURL, apiKey string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: timeout},
	}
}

// BaseURL returns the Outline instance URL.
func (c *Client) BaseURL() string { return c.baseURL }

// APIError is a non-2xx answer from Outline.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("outline API error %d (%s): %s", e.Status, e.Code, e.Message)
}

// call POSTs body to /api/<method> and decodes the "data" field into out.
// apiVersion > 0 sends the x-api-version header.
func (c *Client) call(ctx context.Context, method string, body any, out any, apiVersion int) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/"+method, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if apiVersion > 0 {
		req.Header.Set("x-api-version", fmt.Sprint(apiVersion))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("outline %s request failed: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return fmt.Errorf("outline %s: failed to read response: %w", method, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("%w: %s", ErrNotFound, (&APIError{resp.StatusCode, e.Error, e.Message}).Error())
		}
		return &APIError{Status: resp.StatusCode, Code: e.Error, Message: e.Message}
	}

	if out == nil {
		return nil
	}
	envelope := struct {
		Data json.RawMessage `json:"data"`
	}{}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("outline %s: invalid JSON response: %w", method, err)
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return fmt.Errorf("outline %s: unexpected response shape: %w", method, err)
	}
	return nil
}

// Info fetches a document (id may be the UUID or the urlId) with its markdown text.
func (c *Client) Info(ctx context.Context, id string) (*Document, error) {
	var d Document
	if err := c.call(ctx, "documents.info", map[string]string{"id": id}, &d, 0); err != nil {
		return nil, err
	}
	return &d, nil
}

// InfoStructured fetches a document with its ProseMirror JSON (API version 3),
// used to check how Outline rendered content (e.g. embed vs. link).
func (c *Client) InfoStructured(ctx context.Context, id string) (*Document, error) {
	var d Document
	if err := c.call(ctx, "documents.info", map[string]string{"id": id}, &d, 3); err != nil {
		return nil, err
	}
	return &d, nil
}

// SearchTitles searches documents by title.
func (c *Client) SearchTitles(ctx context.Context, query string, limit int) ([]Document, error) {
	if limit <= 0 || limit > 50 {
		limit = 15
	}
	var docs []Document
	if err := c.call(ctx, "documents.search_titles", map[string]any{"query": query, "limit": limit}, &docs, 0); err != nil {
		return nil, err
	}
	return docs, nil
}

// Prepend inserts markdown at the top of a document.
func (c *Client) Prepend(ctx context.Context, id, markdown string) (*Document, error) {
	var d Document
	body := map[string]any{"id": id, "text": markdown, "editMode": "prepend", "publish": true}
	if err := c.call(ctx, "documents.update", body, &d, 0); err != nil {
		return nil, err
	}
	return &d, nil
}

// ContainsEmbed reports whether the ProseMirror JSON has an embed node whose
// href contains urlFragment.
func ContainsEmbed(data json.RawMessage, urlFragment string) bool {
	if len(data) == 0 {
		return false
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return false
	}
	var walk func(n any) bool
	walk = func(n any) bool {
		switch v := n.(type) {
		case map[string]any:
			if v["type"] == "embed" {
				if attrs, ok := v["attrs"].(map[string]any); ok {
					if href, ok := attrs["href"].(string); ok && strings.Contains(unescapeHref(href), urlFragment) {
						return true
					}
				}
			}
			for _, child := range v {
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range v {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(root)
}

// unescapeHref reverts the "_" -> "%5F" escaping Outline applies to embed hrefs.
func unescapeHref(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "%5F", "_"), "%5f", "_")
}
