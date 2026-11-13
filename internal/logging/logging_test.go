package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONAndLevel(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, "warn", "json")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("dropped")
	log.Warn("kept", "k", 1)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines: %q", len(lines), buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["msg"] != "kept" || rec["k"] != float64(1) {
		t.Fatalf("record = %v", rec)
	}
}

func TestText(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, "debug", "text")
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("hello", "k", "v")
	if !strings.Contains(buf.String(), "msg=hello k=v") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestRejects(t *testing.T) {
	if _, err := New(&bytes.Buffer{}, "loud", "text"); err == nil {
		t.Error("expected level error")
	}
	if _, err := New(&bytes.Buffer{}, "info", "xml"); err == nil {
		t.Error("expected format error")
	}
}
