package httpapi

// CORS for the prekey bundle API (S-50): a browser app served from another
// origin sends its bearer token in the Authorization header, which makes
// every call a non-simple cross-origin request with an OPTIONS preflight.
// Allowed origins are auth.allowed_origins, matched the way /ws matches
// them (coder/websocket OriginPatterns). No credentials are allowed: the
// token is a header, never a cookie.

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// corsAllowHeaders are the request headers an allowed origin may send.
const corsAllowHeaders = "Authorization, Content-Type"

// cors wraps h, which serves method, for cross-origin calls from patterns.
// It returns h and the preflight handler for the route's OPTIONS.
func cors(patterns []string, method string, h http.HandlerFunc) (http.HandlerFunc, http.HandlerFunc) {
	actual := func(w http.ResponseWriter, r *http.Request) {
		allowOrigin(w, r, patterns)
		h(w, r)
	}
	preflight := func(w http.ResponseWriter, r *http.Request) {
		if allowOrigin(w, r, patterns) {
			w.Header().Set("Access-Control-Allow-Methods", method)
			w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
		}
		w.WriteHeader(http.StatusNoContent)
	}
	return actual, preflight
}

// allowOrigin sets Vary: Origin and, when the request's Origin matches
// patterns, Access-Control-Allow-Origin. It reports whether it matched.
func allowOrigin(w http.ResponseWriter, r *http.Request, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	w.Header().Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	if origin == "" || !originAllowed(origin, patterns) {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	return true
}

// originAllowed matches origin against patterns as coder/websocket's
// authenticateOrigin does: path.Match, case-insensitive, against the host,
// or against "scheme://host" when the pattern has a scheme.
func originAllowed(origin string, patterns []string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	for _, p := range patterns {
		target := u.Host
		if strings.Contains(p, "://") {
			target = u.Scheme + "://" + u.Host
		}
		if ok, _ := path.Match(strings.ToLower(p), strings.ToLower(target)); ok {
			return true
		}
	}
	return false
}
