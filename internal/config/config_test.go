package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var required = map[string]string{
	"KLACKS_POSTGRES_DSN": "postgres://klacks:secret@localhost:5432/klacks",
	"KLACKS_SCYLLA_HOSTS": "localhost:9042",
}

func TestLoadDefaultsWithRequiredEnv(t *testing.T) {
	cfg, err := Load("", env(required))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":8080" || cfg.Log.Format != "text" || cfg.Scylla.Keyspace != "klacks" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadRequiresStores(t *testing.T) {
	_, err := Load("", env(nil))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"postgres.dsn", "scylla.hosts"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestProdDefaultsToJSONLogs(t *testing.T) {
	m := map[string]string{"KLACKS_ENV": "prod"}
	for k, v := range required {
		m[k] = v
	}
	cfg, err := Load("", env(m))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.Format != "json" {
		t.Fatalf("format = %q, want json", cfg.Log.Format)
	}
}

func TestFileThenEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "klacks.json")
	file := `{
		"http": {"addr": ":9000", "shutdown_timeout": "3s"},
		"scylla": {"hosts": ["a:9042", "b:9042"], "keyspace": "fromfile"},
		"postgres": {"dsn": "postgres://file"}
	}`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, env(map[string]string{
		"KLACKS_SCYLLA_KEYSPACE": "fromenv",
		"KLACKS_LOG_LEVEL":       "debug",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":9000" || cfg.HTTP.ShutdownTimeout.D() != 3*time.Second {
		t.Errorf("file values not applied: %+v", cfg.HTTP)
	}
	if cfg.Scylla.Keyspace != "fromenv" || cfg.Log.Level != "debug" {
		t.Errorf("env did not override: keyspace=%q level=%q", cfg.Scylla.Keyspace, cfg.Log.Level)
	}
	if len(cfg.Scylla.Hosts) != 2 {
		t.Errorf("hosts = %v", cfg.Scylla.Hosts)
	}
}

func TestFileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "klacks.json")
	if err := os.WriteFile(path, []byte(`{"htpp": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, env(required)); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]map[string]string{
		"bad level":    {"KLACKS_LOG_LEVEL": "loud"},
		"bad env":      {"KLACKS_ENV": "staging"},
		"bad addr":     {"KLACKS_HTTP_ADDR": "8080"},
		"bad duration": {"KLACKS_HTTP_IDLE_TIMEOUT": "soon"},
		"zero timeout": {"KLACKS_SCYLLA_TIMEOUT": "0s"},
		"bad keyspace": {"KLACKS_SCYLLA_KEYSPACE": "drop table;"},
		"bad rf":       {"KLACKS_SCYLLA_REPLICATION_FACTOR": "0"},
		"neg drain":    {"KLACKS_HTTP_DRAIN_DELAY": "-1s"},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range required {
				m[k] = v
			}
			for k, v := range extra {
				m[k] = v
			}
			if _, err := Load("", env(m)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRedactDSN(t *testing.T) {
	cases := map[string]string{
		"postgres://u:secret@h:5432/db":          "postgres://u:xxxxx@h:5432/db",
		"host=h user=u password=secret dbname=d": "host=h user=u password=xxxxx dbname=d",
		"host=h password='se cret' dbname=d":     "host=h password=xxxxx dbname=d",
	}
	for in, want := range cases {
		if got := RedactDSN(in); got != want {
			t.Errorf("RedactDSN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactedDoesNotAliasHosts(t *testing.T) {
	cfg := Default()
	cfg.Scylla.Hosts = []string{"a"}
	r := cfg.Redacted()
	r.Scylla.Hosts[0] = "b"
	if cfg.Scylla.Hosts[0] != "a" {
		t.Fatal("Redacted aliased the hosts slice")
	}
}
