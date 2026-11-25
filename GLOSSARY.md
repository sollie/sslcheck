# sslcheck

A small command-line scanner that connects to TLS endpoints and reports on the certificates they present.

## Language

**Target**:
A host, port and optional SNI name to be scanned, given as `host`, `host:port` or an `https://` URL.
_Avoid_: Server, endpoint, site

**Presented chain**:
The certificates a Target sends during the handshake, in the order received.
_Avoid_: Certificate chain (ambiguous with a verified path)

**Trust store**:
A set of root certificates a Presented chain is verified against. Either the embedded Mozilla bundle or the system store.
_Avoid_: CA bundle, root store

**Verdict**:
The result of verifying a Presented chain against one Trust store. A Target gets one Verdict per Trust store.
_Avoid_: Validation result, status

**Scan**:
One run against a Target. It always completes and reports, even when the chain is expired, self-signed or untrusted.
_Avoid_: Check, probe

**Revocation status**:
Whether a certificate in the Presented chain is `good`, `revoked` or `unknown`, from a staple, OCSP or CRL. `unknown` never fails a Verdict.
_Avoid_: Revocation check, CRL result

**SCT**:
A signed certificate timestamp from a Certificate Transparency log, taken from the certificate, the TLS extension or the stapled OCSP response.
_Avoid_: CT proof, log entry

**Finding**:
A single problem or notice raised in a Verdict. It is either a failure or a warning.
_Avoid_: Issue, error
