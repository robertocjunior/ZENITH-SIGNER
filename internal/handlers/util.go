package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

var errBodyTooLarge = errors.New("request body too large")

// readLimited reads at most limit bytes of the request body.
func readLimited(r *http.Request, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errBodyTooLarge
	}
	return b, nil
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
