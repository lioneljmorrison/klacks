// Command klacks runs the klacks messaging server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/lioneljmorrison/klacks/internal/config"
	"github.com/lioneljmorrison/klacks/internal/logging"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("klacks", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	configPath := fs.String("config", getenv("KLACKS_CONFIG"), "path to a JSON config file (env: KLACKS_CONFIG)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	args = fs.Args()
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	load := func() (config.Config, bool) {
		cfg, err := config.Load(*configPath, getenv)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return config.Config{}, false
		}
		return cfg, true
	}

	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "config":
		cfg, ok := load()
		if !ok {
			return 1
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(cfg.Redacted()); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "serve", "migrate":
		cfg, ok := load()
		if !ok {
			return 1
		}
		log, err := logging.New(stderr, cfg.Log.Level, cfg.Log.Format)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if args[0] == "migrate" {
			return cmdMigrate(ctx, cfg, log, args[1:], stdout, stderr)
		}
		if len(args) > 1 {
			fmt.Fprintf(stderr, "klacks serve: unexpected arguments %q\n", args[1:])
			return 2
		}
		if err := cmdServe(ctx, cfg, log); err != nil {
			log.Error("serve failed", "err", err)
			return 1
		}
		return 0
	case "help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "klacks: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: klacks [-config file.json] <command>

Commands:
  serve      Run the server (HTTP: /healthz, /readyz)
  migrate    Apply schema migrations to PostgreSQL and ScyllaDB
             (klacks migrate -h for actions)
  config     Validate and print the effective configuration (secrets redacted)
  version    Print the version
  help       Show this help

Configuration comes from defaults, then the optional JSON file, then KLACKS_*
environment variables. See .env.example.
`)
}
