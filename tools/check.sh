#!/bin/sh
# Pre-PR checks. Run before pushing; the pre-push hook runs it too.
set -eu
cd "$(dirname "$0")/.."

golangci-lint run
govulncheck ./...
go vet ./...
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "gofmt needed:" >&2
	echo "$unformatted" >&2
	exit 1
fi
go test -race ./...
