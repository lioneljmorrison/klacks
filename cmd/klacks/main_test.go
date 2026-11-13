package main

import (
	"bytes"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, env(nil), &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
	if got := strings.TrimSpace(out.String()); got != version {
		t.Fatalf("version = %q, want %q", got, version)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"nope"}, env(nil), &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestRunConfigRedacts(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"config"}, env(map[string]string{
		"KLACKS_POSTGRES_DSN": "postgres://u:hunter2@localhost/db",
		"KLACKS_SCYLLA_HOSTS": "localhost:9042",
	}), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, errOut.String())
	}
	if strings.Contains(out.String(), "hunter2") {
		t.Fatalf("password leaked: %s", out.String())
	}
	if !strings.Contains(out.String(), `"addr": ":8080"`) {
		t.Fatalf("output = %s", out.String())
	}
}

func TestRunConfigInvalid(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"config"}, env(nil), &out, &errOut); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "postgres.dsn") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}
