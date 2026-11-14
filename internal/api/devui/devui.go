// Package devui serves the browser test client, an embedded single-page app
// that speaks the same wire protocol and E2EE format as the Go reference
// client. It exists for manual and interoperability testing only: it is
// mounted only when env is dev (cmdServe, alongside the dev /ws
// authenticator), it never ships to any other env, and nothing in it is
// part of the server's client surface.
//
// The browser must be served from the klacks origin: the /ws endpoint
// rejects cross-origin upgrades, so a page on another port cannot connect.
// Serving the app from the server itself keeps every request same-origin —
// the prekey REST calls need no CORS and the upgrade needs no Origin
// exception.
package devui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web
var embedded embed.FS

// New returns the dev UI's handler: the embedded web directory at /devui,
// with index.html at /devui and every asset under /devui/....
// http.FileServer's directory handling serves index.html for the root.
func New() (http.Handler, error) {
	web, err := fs.Sub(embedded, "web")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServerFS(web)
	return http.StripPrefix("/devui", serveRootAsIndex(noDirListing(fileServer))), nil
}

// serveRootAsIndex maps the bare /devui request (empty path after the
// prefix strip) to the directory root, which FileServer answers with
// index.html.
func serveRootAsIndex(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		next.ServeHTTP(w, r)
	})
}

// noDirListing turns directory requests (other than the root, which
// FileServer serves as index.html) into 404s, so /devui/js/ does not
// enumerate the app's files.
func noDirListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && len(r.URL.Path) > 0 && r.URL.Path[len(r.URL.Path)-1] == '/' {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
