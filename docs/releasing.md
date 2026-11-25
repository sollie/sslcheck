# Releasing

The version is the git tag; no file holds it.

1. Merge to `main` and confirm CI is green.
2. Tag and push: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`. Use a minor bump for new behaviour, a patch bump for fixes.
3. The tag triggers `.github/workflows/release.yaml`: git-cliff release notes, GoReleaser binaries, the GHCR image and the Homebrew formula (see `homebrew-tap.md`).
4. Check the workflow run and the GitHub release page.
