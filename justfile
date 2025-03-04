# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

# Run default recipe
@_default:
    just -l

# Remove generated artifacts
@clean:
    go clean

# Run tests
@test:
    go test ./...

# Run `golangci-lint run`
@golangci-lint:
    go tool golangci-lint run -E gofmt,goimports

# Run the formatter
fmt: gofmt goimports

# Run `go fmt`
@gofmt:
    go fmt ./...

# Run `goimports`
@goimports:
    fd -e go -x go tool goimports -w

# Run the linter
lint: vet staticcheck

# Run `go vet`
@vet:
    go vet ./...

# Run `staticcheck`
@staticcheck:
    go tool staticcheck ./...

# Run `pkgsite`
@pkgsite:
    go tool pkgsite -http "0.0.0.0:8080"

# Build `encrypt` example
@build-encrypt-example $CGO_ENABLED="0":
    go build ./examples/encrypt

# Build `decrypt` example
@build-decrypt-example $CGO_ENABLED="0":
    go build ./examples/decrypt

# Build `info` example
@build-info-example $CGO_ENABLED="0":
    go build ./examples/info

# Build the examples
@build-examples $CGO_ENABLED="0":
    go build -o . ./examples/{decrypt,encrypt,info}

# Run the linter for GitHub Actions workflow files
@lint-github-actions:
    actionlint -verbose

# Run the formatter for the README
@fmt-readme:
    npx prettier -w README.md

# Increment the version
@bump part:
    bump-my-version bump {{ part }}
