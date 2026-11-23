package handlers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// ---------------------------------------------------------------------------
// Client IP resolution (trusted reverse proxies)
// ---------------------------------------------------------------------------

const clientIPKey ctxKey = "client_ip"

// ClientIPResolver determines the real client IP of a request.
//
// X-Forwarded-For / X-Real-IP are only honoured when the TCP peer is one of
// the configured trusted proxies; otherwise any client could forge the IP
// recorded in the signature audit trail.
type ClientIPResolver struct {
	trusted []netip.Prefix
}

// NewClientIPResolver parses a list of IPs or CIDRs (e.g. "10.0.0.0/8", "172.17.0.1").
func NewClientIPResolver(entries []string) (*ClientIPResolver, error) {
	res := &ClientIPResolver{}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid TRUSTED_PROXIES entry %q: %w", entry, err)
			}
			res.trusted = append(res.trusted, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXIES entry %q: %w", entry, err)
		}
		addr = addr.Unmap()
		res.trusted = append(res.trusted, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return res, nil
}

func (c *ClientIPResolver) isTrusted(addr netip.Addr) bool {
	for _, p := range c.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func parseIP(raw string) (netip.Addr, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

func remoteAddrIP(r *http.Request) (netip.Addr, bool) {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	return parseIP(host)
}

// Resolve returns the client IP for r.
func (c *ClientIPResolver) Resolve(r *http.Request) string {
	remote, ok := remoteAddrIP(r)
	if !ok {
		return r.RemoteAddr
	}
	if !c.isTrusted(remote) {
		return remote.String()
	}

	// Walk X-Forwarded-For from right (closest hop) to left, skipping trusted proxies.
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	if len(hops) > 0 {
		last := remote
		for i := len(hops) - 1; i >= 0; i-- {
			addr, ok := parseIP(hops[i])
			if !ok {
				// Malformed entry: stop and keep the last address we could verify.
				return last.String()
			}
			if !c.isTrusted(addr) {
				return addr.String()
			}
			last = addr
		}
		return last.String()
	}

	if addr, ok := parseIP(r.Header.Get("X-Real-IP")); ok {
		return addr.String()
	}
	return remote.String()
}

// ClientIP resolves the client IP once per request and stores it in the context.
func ClientIP(resolver *ClientIPResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolver.Resolve(r)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey, ip)))
		})
	}
}

// extractClientIP returns the IP resolved by the ClientIP middleware, falling
// back to the TCP peer address (never to client-controlled headers).
func extractClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok && ip != "" {
		return ip
	}
	if addr, ok := remoteAddrIP(r); ok {
		return addr.String()
	}
	return r.RemoteAddr
}

// ---------------------------------------------------------------------------
// Framing policy (clickjacking protection)
// ---------------------------------------------------------------------------

// embedPath is the only route that may be rendered inside third-party iframes.
const embedPath = "/assinar"

// ParseEmbedOrigins validates ALLOWED_EMBED_ORIGINS entries and returns them
// normalised as scheme://host[:port]. Wildcard subdomains ("https://*.empresa.com")
// are accepted, as supported by CSP frame-ancestors.
func ParseEmbedOrigins(entries []string) ([]string, error) {
	var out []string
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.ContainsAny(entry, " ;,'\"\t\r\n") {
			return nil, fmt.Errorf("invalid ALLOWED_EMBED_ORIGINS entry %q: unexpected character", entry)
		}

		wildcard := false
		parseable := entry
		if i := strings.Index(entry, "://*."); i != -1 {
			wildcard = true
			parseable = entry[:i+3] + "wildcard." + entry[i+5:]
		}

		u, err := url.Parse(parseable)
		if err != nil {
			return nil, fmt.Errorf("invalid ALLOWED_EMBED_ORIGINS entry %q: %w", entry, err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "https" && scheme != "http" {
			return nil, fmt.Errorf("invalid ALLOWED_EMBED_ORIGINS entry %q: scheme must be http or https", entry)
		}
		if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("invalid ALLOWED_EMBED_ORIGINS entry %q: expected scheme://host[:port]", entry)
		}

		host := strings.ToLower(u.Host)
		if wildcard {
			host = "*." + strings.TrimPrefix(host, "wildcard.")
		}
		out = append(out, scheme+"://"+host)
	}
	return out, nil
}

// anonymousEmbedPolicy is sent on /assinar when the request carries no session.
//
// Without a session the widget only shows a "sign in" link that navigates the
// top window, so there is nothing to clickjack. Allowing any ancestor here is
// required by Outline: when an embed is created it checks the URL server-side
// (POST /urls.checkEmbed, no cookies) and refuses any frame-ancestors list that
// names specific origins without "*".
const anonymousEmbedPolicy = "frame-ancestors *"

// SecurityHeaders sets baseline security headers and the framing policy:
//   - /assinar with a session (the user can sign): only the application itself
//     and the configured embed origins may frame it;
//   - /assinar without a session: may be framed anywhere (see anonymousEmbedPolicy);
//   - every other route (admin, auth, home...) cannot be framed.
func SecurityHeaders(embedOrigins []string) func(http.Handler) http.Handler {
	embedPolicy := "frame-ancestors 'self'"
	if len(embedOrigins) > 0 {
		embedPolicy += " " + strings.Join(embedOrigins, " ")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			if r.URL.Path == embedPath {
				if hasSessionCookie(r) {
					h.Set("Content-Security-Policy", embedPolicy)
				} else {
					h.Set("Content-Security-Policy", anonymousEmbedPolicy)
				}
			} else {
				h.Set("Content-Security-Policy", "frame-ancestors 'none'")
				h.Set("X-Frame-Options", "DENY")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// hasSessionCookie reports whether the request carries a session cookie at all.
// Any value (even an invalid one) selects the restrictive policy, erring on the safe side.
func hasSessionCookie(r *http.Request) bool {
	_, err := r.Cookie("user_email")
	return err == nil
}
