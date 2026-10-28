# Tasks for synthwerk-identity. CI runs the same commands (.github/workflows/ci.yml).
set shell := ["bash", "-euo", "pipefail", "-c"]

# Lint and test.
default: lint test

zizmor_version := "1.30.1"

# gofmt, golangci-lint, actionlint + zizmor.
lint:
    test -z "$(gofmt -l .)"
    golangci-lint run ./...
    actionlint .github/workflows/*.yml
    uvx zizmor@{{ zizmor_version }} --offline .github/workflows

# Unit tests.
test:
    go test -race ./...

# Integration tests against real Postgres (needs Docker).
test-int:
    go test -tags integration -race -count=1 ./tests/integration/...

# Container image as CI builds it.
image:
    docker build --build-arg COMMIT="$(git rev-parse HEAD)" -t synthwerk-identity:local .
