# A Scan completes even when the chain is untrusted

The handshake is made without verification. The Presented chain is captured, then verified separately against each Trust store, so expired, self-signed and untrusted servers still produce a full report. Failed Verdicts affect the exit status only with `--strict`.

A browser-style strict handshake would abort on exactly the servers a scanner exists to inspect.
