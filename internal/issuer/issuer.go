// Package issuer finds the issuing certificate of a certificate in a Presented
// chain. Revocation and CT share it so they cannot disagree about issuers.
package issuer

import (
	"bytes"
	"crypto/x509"
	"time"
)

// Find returns the issuer of chain[i], or nil when it cannot be determined.
// The issuer is looked up anywhere in the Presented chain by name and
// signature. The last presented certificate, which usually has its issuer
// left out, falls back to the verified path through roots.
func Find(chain []*x509.Certificate, i int, roots []*x509.CertPool, now time.Time) *x509.Certificate {
	c := chain[i]
	for j, cand := range chain {
		if j != i && bytes.Equal(c.RawIssuer, cand.RawSubject) && c.CheckSignatureFrom(cand) == nil {
			return cand
		}
	}
	if i != len(chain)-1 {
		return nil
	}
	for _, pool := range roots {
		if pool == nil {
			continue
		}
		paths, _ := c.Verify(x509.VerifyOptions{
			Roots:       pool,
			CurrentTime: now,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		for _, p := range paths {
			if len(p) > 1 {
				return p[1]
			}
		}
	}
	return nil
}
