.PHONY: build install test-up test-reset test-down test-logs tidy vet

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/MaximeWewer/openldap-cli/internal/cli.version=$(VERSION)

build: ## compile the CLI (static, stripped)
	CGO_ENABLED=0 go build -trimpath -tags netgo -ldflags "$(LDFLAGS)" -o openldap-cli ./cmd/openldap-cli

install: ## go install into GOBIN
	CGO_ENABLED=0 go install -trimpath -tags netgo -ldflags "$(LDFLAGS)" ./cmd/openldap-cli

tidy:
	go mod tidy

vet:
	go vet ./cmd/... ./internal/...

lint: ## run golangci-lint (install: https://golangci-lint.run)
	golangci-lint run ./cmd/... ./internal/...

security: ## run gosec (install: go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec -quiet ./cmd/... ./internal/...

unit: ## run unit tests (pure logic, no server needed)
	go test ./internal/...

integration: ## run integration tests against the test LDAP (make test-up first)
	go test -tags integration ./internal/ldapx/

e2e: ## end-to-end CLI tests: build the binary + drive every command (make test-up first)
	go test -tags e2e -count=1 -v ./tests/

test-up: ## start the test OpenLDAP (idempotent)
	cd tests && ./bootstrap.sh

test-reset: ## wipe + rebuild the test OpenLDAP
	cd tests && ./bootstrap.sh --reset

test-down: ## stop the test OpenLDAP
	cd tests && docker compose down

test-logs:
	cd tests && docker compose logs -f openldap
