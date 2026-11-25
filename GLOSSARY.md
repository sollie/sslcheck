# sslcheck

A small command-line scanner that connects to TLS endpoints and reports on the certificates they present.

## Language

**Target**:
A host, port and optional SNI name to be scanned, given as `host`, `host:port` or an `https://` URL.
_Avoid_: Server, endpoint, site

**Presented chain**:
The certificates a Target sends during the handshake, in the order received.
_Avoid_: Certificate chain (ambiguous with a verified path)

**Evidence**:
Everything one Scan observed on a Target's handshake that a Verdict is judged from: the Presented chain, any stapled OCSP response, SCTs, the TLS version and the negotiated cipher suite.
_Avoid_: Handshake result, capture

**Trust store**:
A set of root certificates a Presented chain is verified against. Either the embedded Mozilla bundle or the system store.
_Avoid_: CA bundle, root store

**Verdict**:
The result of verifying a Presented chain against one Trust store. A Target gets one Verdict per Trust store.
_Avoid_: Validation result, status

**Scan**:
One run against a Target. It always completes and reports, even when the chain is expired, self-signed or untrusted. Its outcome is either an error (no Presented chain was obtained) or one Verdict per Trust store.
_Avoid_: Check, probe

**Embedded data**:
The Mozilla bundle and CT log list compiled into the binary. A refreshed copy in the cache directory replaces it only when newer.
_Avoid_: Built-in data, bundled data

**Report**:
The rendered output of one or more Scans, in pretty, json, yaml or toml form.
_Avoid_: Output, result (a Scan's outcome is not its Report)

**Revocation status**:
Whether a certificate in the Presented chain is `good`, `revoked` or `unknown`, from a staple, OCSP or CRL. `unknown` never fails a Verdict.
_Avoid_: Revocation check, CRL result

**SCT**:
A signed certificate timestamp from a Certificate Transparency log, taken from the certificate, the TLS extension or the stapled OCSP response.
_Avoid_: CT proof, log entry

**Finding**:
A single problem or notice raised in a Verdict. It is either a failure or a warning.
_Avoid_: Issue, error
