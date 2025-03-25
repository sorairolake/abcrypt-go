# SPDX-FileCopyrightText: 2024 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

alias fmt := golangci-lint-fmt
alias lint := golangci-lint-run

# Run default recipe
_default:
    just -l

# Remove generated artifacts
clean:
    go clean

# Run tests
test:
    go test ./...

# Run `golangci-lint`
golangci-lint: golangci-lint-fmt golangci-lint-run

# Run the formatter
golangci-lint-fmt:
    go tool golangci-lint fmt

# Run the linter
golangci-lint-run:
    go tool golangci-lint run

# Run `pkgsite`
pkgsite:
    go tool pkgsite -http "0.0.0.0:8080"

# Build `encrypt` example
build-encrypt-example $CGO_ENABLED="0":
    go build ./examples/encrypt

# Build `decrypt` example
build-decrypt-example $CGO_ENABLED="0":
    go build ./examples/decrypt

# Build `info` example
build-info-example $CGO_ENABLED="0":
    go build ./examples/info

# Build the examples
build-examples $CGO_ENABLED="0":
    go build -o . ./examples/{decrypt,encrypt,info}

# Run the linter for GitHub Actions workflow files
lint-github-actions:
    actionlint -verbose

# Run the formatter for the README
fmt-readme:
    npx prettier -w README.md

# Increment the version
bump part:
    bump-my-version bump {{ part }}
