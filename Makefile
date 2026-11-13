# klacks — run `make` or `make help` to list targets.

SHELL := /bin/bash
.DEFAULT_GOAL := help

BIN_DIR   := bin
BINARY    := $(BIN_DIR)/klacks
PKG       := ./...
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)

# Local settings: copy .env.example to .env. Its KLACKS_* variables are
# exported to every recipe (klacks, migrate, integration tests).
-include .env
export $(filter KLACKS_%,$(.VARIABLES))

# Tools are installed into bin/ with the project's Go toolchain, so they always
# understand the go.mod language version.
GOLANGCI_LINT_VERSION := v2.15.0
GOLANGCI_LINT         := $(BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Build

.PHONY: build
build: ## Build the klacks binary into bin/
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/klacks

.PHONY: run
run: build ## Build and run `klacks serve`
	$(BINARY) serve

.PHONY: config
config: build ## Validate and print the effective configuration
	$(BINARY) config

.PHONY: env
env: ## Create .env from .env.example (keeps an existing .env)
	@if [ -e .env ]; then echo ".env exists; leaving it alone"; else cp .env.example .env && echo "created .env"; fi

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN_DIR) coverage.out

##@ Local stack (Docker Compose: PostgreSQL + ScyllaDB)

.PHONY: up
up: ## Start Postgres and ScyllaDB and wait until healthy (~30s cold)
	docker compose up -d --wait

.PHONY: down
down: ## Stop the stack (keeps data)
	docker compose down

.PHONY: nuke
nuke: ## Stop the stack and DELETE its data volumes
	docker compose down -v

.PHONY: ps
ps: ## Show stack status
	docker compose ps

.PHONY: logs
logs: ## Follow stack logs (SERVICE=postgres|scylla to pick one)
	docker compose logs -f $(SERVICE)

.PHONY: psql
psql: ## Open psql on the local Postgres
	docker compose exec postgres psql -U klacks -d klacks

.PHONY: cqlsh
cqlsh: ## Open cqlsh on the local ScyllaDB
	docker compose exec scylla cqlsh

##@ Migrations (STORE=all|postgres|scylla)

STORE ?= all
N     ?= 1

.PHONY: migrate-up
migrate-up: build ## Apply pending migrations
	$(BINARY) migrate -store $(STORE) up

.PHONY: migrate-down
migrate-down: build ## Roll back N (default 1) migrations; needs STORE
	$(BINARY) migrate -store $(STORE) down $(N)

.PHONY: migrate-version
migrate-version: build ## Show applied versions
	$(BINARY) migrate -store $(STORE) version

.PHONY: migrate-force
migrate-force: build ## After a manual repair, mark TO applied and clean; needs STORE
	@test -n "$(TO)" || { echo "usage: make migrate-force STORE=postgres|scylla TO=<version>"; exit 2; }
	$(BINARY) migrate -store $(STORE) force $(TO)

.PHONY: migrate-create
migrate-create: ## New empty migration pair: STORE=postgres|scylla NAME=short_name
	@scripts/new-migration.sh $(STORE) $(NAME)

##@ Quality

.PHONY: fmt
fmt: ## Format the code
	gofmt -s -w .

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	go mod tidy

.PHONY: vet
vet: ## Run go vet
	go vet -tags integration $(PKG)

.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run golangci-lint
	$(GOLANGCI_LINT) run $(PKG)

$(GOLANGCI_LINT):
	@mkdir -p $(BIN_DIR)
	GOBIN=$(abspath $(BIN_DIR)) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	mv $(BIN_DIR)/golangci-lint $@

.PHONY: test
test: ## Run unit tests (no databases needed)
	go test -race -count=1 $(PKG)

.PHONY: test-integration
test-integration: ## Unit + integration tests against the local stack (run `make up` first)
	KLACKS_TEST_POSTGRES_DSN="$${KLACKS_TEST_POSTGRES_DSN:-$$KLACKS_POSTGRES_DSN}" \
	KLACKS_TEST_SCYLLA_HOSTS="$${KLACKS_TEST_SCYLLA_HOSTS:-$$KLACKS_SCYLLA_HOSTS}" \
	go test -race -count=1 -tags integration $(PKG)

.PHONY: cover
cover: ## Run unit tests with a coverage report
	go test -race -count=1 -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out | tail -1

.PHONY: check
check: vet lint test ## vet + lint + unit tests (what CI runs)
