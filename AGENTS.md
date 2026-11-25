## Agent skills

### Issue tracker

Issues live in GitHub Issues for sollie/sslcheck (via `gh`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one root `GLOSSARY.md` plus `docs/adr/`. See `docs/agents/domain.md`.

## Workflow

- One ticket = one branch = one PR. Dependent tickets are stacked on their blocker's branch (`gh stack`), so changes land as a stack of PRs. Independent tickets may be worked in parallel as side-stacks off the stack base. Use short-lived branches and PRs; never commit to `main` directly.
- Before opening or updating a PR, run all of: `golangci-lint run`, `govulncheck ./...`, `go vet ./...`, `gofmt -l .` (must print nothing), `go test ./...`, and a code review of the changes (the `code-review` skill or agent). Fix findings before pushing.
- Tests go through the single CLI seam (`run`); see issue #1.
