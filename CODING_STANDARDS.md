# Coding standards

Judgement calls for review. Anything tooling enforces (`tools/check.sh`) is not repeated here.

- **One type per domain term.** A term in `GLOSSARY.md` (Evidence, Verdict, Target) maps to one Go type. A second type for the same term needs a different name.
- **One home per outbound HTTP rule.** Redirects, size limits, trust roots and destination blocking live in `internal/httppolicy`. Callers pick a named policy; they do not build clients.
- **Behaviour changes carry a test.** Any change a user can observe (a refusal, an error message, a limit) gets a test through the CLI seam (`run`), even inside a refactor. A refactor that changes behaviour says so in the PR body.
- **Tests drive `run`.** Assert on exit code, stdout and stderr only; do not call internal modules from tests.
- **Reports stay stable.** No change to a flag, exit code or Report field without a `schema_version` decision.
- **Judge owns Verdicts.** Verdict rules live in `internal/verify`. Scan builds Evidence and renders results; it does not adjust Verdicts.
