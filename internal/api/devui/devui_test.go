package devui

// The handler serves the app's files from the embedded FS, answers the bare
// /devui request with index.html, and refuses directory listings.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(h)
}

func TestServesIndexAtRoot(t *testing.T) {
	for _, path := range []string{"/devui", "/devui/"} {
		t.Run(path, func(t *testing.T) {
			srv := newServer(t)
			defer srv.Close()
			resp, err := http.Get(srv.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), "klacks dev UI") {
				t.Fatal("index.html not served")
			}
		})
	}
}

func TestServesModules(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/devui/js/app.mjs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/javascript") {
		t.Fatalf("content type %q", ct)
	}
}

func TestDirectoryListingRefused(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/devui/js/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
}
