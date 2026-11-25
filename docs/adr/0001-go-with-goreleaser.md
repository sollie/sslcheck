# Go, with GoReleaser inside a tag-triggered release workflow

sslcheck is written in Go. Releases are built by GoReleaser, run from a single `v*` tag workflow on one Linux runner. The workflow set (ci, audit, SARIF analysis, release with a git-cliff changelog) mirrors `sollie/argon-tool`.

Go gives trivial static cross-compilation, including ARMv6, and a standard library that tolerates the broken certificates a scanner must inspect. `argon-tool` builds each target on a native runner with a hand-written matrix; we depart from that because GoReleaser also produces the archives, Docker images and Homebrew formula that this project needs and `argon-tool` does not.
