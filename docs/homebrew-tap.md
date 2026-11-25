# Homebrew tap

Each release renders `Formula/sslcheck.rb` and pushes it to
[`sollie/homebrew-tap`](https://github.com/sollie/homebrew-tap), so
`brew install sollie/tap/sslcheck` works on macOS and Linux.

## One-time setup: `TAP_TOKEN`

The default `GITHUB_TOKEN` cannot write to another repository, so the release
workflow uses a repo-scoped secret:

1. Create the `sollie/homebrew-tap` repository (public, with a default branch).
2. Create a fine-grained personal access token with **only** the
   `sollie/homebrew-tap` repository selected and **Contents: Read and write**.
3. Add it to `sollie/sslcheck` as the Actions secret `TAP_TOKEN`
   (Settings → Secrets and variables → Actions).

Rotate the token before it expires; a missing or expired token fails the
goreleaser step of the release.

## Notes

- Goreleaser's `brews` section is used because `homebrew_casks` is macOS-only.
  `goreleaser check` therefore reports a `brews` deprecation warning.
- Prerelease tags (`skip_upload: auto`) do not update the tap.
