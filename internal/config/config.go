// Package config loads klacks configuration.
//
// Values are layered: built-in defaults, then an optional JSON file, then
// KLACKS_* environment variables. The result is validated before use.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Environment names.
const (
	EnvDev  = "dev"
	EnvProd = "prod"
)

// Config is the full klacks configuration.
type Config struct {
	// Env is "dev" or "prod". It picks defaults, such as the log format.
	Env      string   `json:"env"`
	Log      Log      `json:"log"`
	HTTP     HTTP     `json:"http"`
	Postgres Postgres `json:"postgres"`
	Scylla   Scylla   `json:"scylla"`
	Auth     Auth     `json:"auth"`
}

// Auth configures client authentication.
type Auth struct {
	JWT JWT `json:"jwt"`
}

// JWT configures verification of client bearer tokens (S-31): Ed25519
// (EdDSA) tokens issued by the embedder's identity provider. With no public
// key file, JWT auth is off: env dev falls back to the dev stub, and any
// other env serves no client endpoints.
type JWT struct {
	PublicKeyFile string `json:"public_key_file"` // PEM "PUBLIC KEY" (PKIX) Ed25519
	Issuer        string `json:"issuer"`          // required iss
	Audience      string `json:"audience"`        // required aud
}

// Enabled reports whether JWT auth is configured.
func (j JWT) Enabled() bool { return j.PublicKeyFile != "" }

// Log configures structured logging.
type Log struct {
	Level  string `json:"level"`  // debug, info, warn, error
	Format string `json:"format"` // text or json; empty picks by Env
}

// HTTP configures the HTTP server.
type HTTP struct {
	Addr              string   `json:"addr"`
	ReadHeaderTimeout Duration `json:"read_header_timeout"`
	ReadTimeout       Duration `json:"read_timeout"`
	WriteTimeout      Duration `json:"write_timeout"`
	IdleTimeout       Duration `json:"idle_timeout"`
	ShutdownTimeout   Duration `json:"shutdown_timeout"`
	// DrainDelay is how long /readyz reports "draining" before the listener
	// closes, so load balancers can stop routing new traffic. 0 disables it.
	DrainDelay   Duration `json:"drain_delay"`
	ReadyTimeout Duration `json:"ready_timeout"` // per-store /readyz check
}

// Postgres configures the relational store.
type Postgres struct {
	DSN string `json:"dsn"`
}

// Scylla configures the message stream store.
type Scylla struct {
	Hosts             []string `json:"hosts"`
	Keyspace          string   `json:"keyspace"`
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	ReplicationFactor int      `json:"replication_factor"` // used when migrate creates the keyspace
	Timeout           Duration `json:"timeout"`
}

// Duration is a time.Duration that reads from JSON as a string such as "5s".
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Default returns the built-in defaults, which suit local development against
// the Docker Compose stack.
func Default() Config {
	return Config{
		Env: EnvDev,
		Log: Log{Level: "info"},
		HTTP: HTTP{
			Addr:              ":8080",
			ReadHeaderTimeout: Duration(5 * time.Second),
			ReadTimeout:       Duration(15 * time.Second),
			WriteTimeout:      Duration(15 * time.Second),
			IdleTimeout:       Duration(60 * time.Second),
			ShutdownTimeout:   Duration(20 * time.Second),
			ReadyTimeout:      Duration(2 * time.Second),
		},
		Scylla: Scylla{
			Keyspace:          "klacks",
			ReplicationFactor: 1,
			Timeout:           Duration(5 * time.Second),
		},
	}
}

// Load builds the configuration from defaults, the JSON file at path (skipped
// when path is empty) and the environment, then validates it.
func Load(path string, getenv func(string) string) (Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path) //nolint:gosec // path comes from the operator
		if err != nil {
			return Config{}, fmt.Errorf("config: read %s: %w", path, err)
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}
	if err := applyEnv(&cfg, getenv); err != nil {
		return Config{}, err
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = "text"
		if cfg.Env == EnvProd {
			cfg.Log.Format = "json"
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config, getenv func(string) string) error {
	var errs []error
	str := func(key string, dst *string) {
		if v := getenv(key); v != "" {
			*dst = v
		}
	}
	dur := func(key string, dst *Duration) {
		if v := getenv(key); v != "" {
			if err := dst.UnmarshalText([]byte(v)); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
			}
		}
	}
	str("KLACKS_ENV", &cfg.Env)
	str("KLACKS_LOG_LEVEL", &cfg.Log.Level)
	str("KLACKS_LOG_FORMAT", &cfg.Log.Format)
	str("KLACKS_HTTP_ADDR", &cfg.HTTP.Addr)
	dur("KLACKS_HTTP_READ_HEADER_TIMEOUT", &cfg.HTTP.ReadHeaderTimeout)
	dur("KLACKS_HTTP_READ_TIMEOUT", &cfg.HTTP.ReadTimeout)
	dur("KLACKS_HTTP_WRITE_TIMEOUT", &cfg.HTTP.WriteTimeout)
	dur("KLACKS_HTTP_IDLE_TIMEOUT", &cfg.HTTP.IdleTimeout)
	dur("KLACKS_HTTP_SHUTDOWN_TIMEOUT", &cfg.HTTP.ShutdownTimeout)
	dur("KLACKS_HTTP_DRAIN_DELAY", &cfg.HTTP.DrainDelay)
	dur("KLACKS_HTTP_READY_TIMEOUT", &cfg.HTTP.ReadyTimeout)
	str("KLACKS_POSTGRES_DSN", &cfg.Postgres.DSN)
	if v := getenv("KLACKS_SCYLLA_HOSTS"); v != "" {
		cfg.Scylla.Hosts = splitList(v)
	}
	str("KLACKS_SCYLLA_KEYSPACE", &cfg.Scylla.Keyspace)
	str("KLACKS_SCYLLA_USERNAME", &cfg.Scylla.Username)
	str("KLACKS_SCYLLA_PASSWORD", &cfg.Scylla.Password)
	if v := getenv("KLACKS_SCYLLA_REPLICATION_FACTOR"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("KLACKS_SCYLLA_REPLICATION_FACTOR: %w", err))
		}
		cfg.Scylla.ReplicationFactor = n
	}
	dur("KLACKS_SCYLLA_TIMEOUT", &cfg.Scylla.Timeout)
	str("KLACKS_AUTH_JWT_PUBLIC_KEY_FILE", &cfg.Auth.JWT.PublicKeyFile)
	str("KLACKS_AUTH_JWT_ISSUER", &cfg.Auth.JWT.Issuer)
	str("KLACKS_AUTH_JWT_AUDIENCE", &cfg.Auth.JWT.Audience)
	if len(errs) > 0 {
		return fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// keyspaceRE matches names CQL accepts unquoted. Keyspace names are spliced
// into CQL statements, so nothing else is allowed.
var keyspaceRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,47}$`)

// Validate reports every problem with the configuration at once.
func (c Config) Validate() error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Env != EnvDev && c.Env != EnvProd {
		bad("env must be %q or %q, got %q", EnvDev, EnvProd, c.Env)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		bad("log.level must be debug, info, warn or error, got %q", c.Log.Level)
	}
	if c.Log.Format != "text" && c.Log.Format != "json" {
		bad("log.format must be text or json, got %q", c.Log.Format)
	}
	if _, _, err := net.SplitHostPort(c.HTTP.Addr); err != nil {
		bad("http.addr %q: %v", c.HTTP.Addr, err)
	}
	for name, d := range map[string]Duration{
		"http.read_header_timeout": c.HTTP.ReadHeaderTimeout,
		"http.read_timeout":        c.HTTP.ReadTimeout,
		"http.write_timeout":       c.HTTP.WriteTimeout,
		"http.idle_timeout":        c.HTTP.IdleTimeout,
		"http.shutdown_timeout":    c.HTTP.ShutdownTimeout,
		"http.ready_timeout":       c.HTTP.ReadyTimeout,
		"scylla.timeout":           c.Scylla.Timeout,
	} {
		if d <= 0 {
			bad("%s must be positive", name)
		}
	}
	if c.HTTP.DrainDelay < 0 {
		bad("http.drain_delay must not be negative")
	}
	if c.Postgres.DSN == "" {
		bad("postgres.dsn is required (KLACKS_POSTGRES_DSN)")
	}
	if len(c.Scylla.Hosts) == 0 {
		bad("scylla.hosts is required (KLACKS_SCYLLA_HOSTS)")
	}
	if !keyspaceRE.MatchString(c.Scylla.Keyspace) {
		bad("scylla.keyspace %q must be a letter followed by up to 47 letters, digits or underscores", c.Scylla.Keyspace)
	}
	if c.Scylla.ReplicationFactor < 1 {
		bad("scylla.replication_factor must be at least 1")
	}
	if c.Auth.JWT.Enabled() {
		if c.Auth.JWT.Issuer == "" {
			bad("auth.jwt.issuer is required with auth.jwt.public_key_file (KLACKS_AUTH_JWT_ISSUER)")
		}
		if c.Auth.JWT.Audience == "" {
			bad("auth.jwt.audience is required with auth.jwt.public_key_file (KLACKS_AUTH_JWT_AUDIENCE)")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return nil
}

// Redacted returns a copy with secrets masked, safe to log or print.
func (c Config) Redacted() Config {
	c.Postgres.DSN = RedactDSN(c.Postgres.DSN)
	if c.Scylla.Password != "" {
		c.Scylla.Password = "xxxxx"
	}
	c.Scylla.Hosts = append([]string(nil), c.Scylla.Hosts...)
	return c
}

var kvPasswordRE = regexp.MustCompile(`(?i)(password\s*=\s*)('(?:[^'\\]|\\.)*'|\S+)`)

// RedactDSN masks the password in a Postgres URL or key=value DSN.
func RedactDSN(dsn string) string {
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "<unparseable dsn>"
		}
		if q := u.Query(); q.Has("password") {
			q.Set("password", "xxxxx")
			u.RawQuery = q.Encode()
		}
		return u.Redacted()
	}
	return kvPasswordRE.ReplaceAllString(dsn, "${1}xxxxx")
}
