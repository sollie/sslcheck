// Package testutil provides fakes for driving sslcheck end to end in tests:
// generated certificates and an in-process TLS server.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// Cert is a generated certificate together with its private key.
type Cert struct {
	DER  []byte
	Key  *ecdsa.PrivateKey
	Leaf *x509.Certificate
}

// PEM returns the certificate PEM-encoded.
func (c *Cert) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER})
}

// CertOpts customises a generated certificate. Zero times give a certificate
// valid from an hour ago until 24 hours from now.
type CertOpts struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	NotBefore  time.Time
	NotAfter   time.Time
	// OCSPServer and CRLDistributionPoints are the revocation URLs embedded in the certificate.
	OCSPServer            []string
	CRLDistributionPoints []string
}

// Expired returns o with a validity window that ended yesterday.
func Expired(o CertOpts) CertOpts {
	o.NotBefore = time.Now().Add(-48 * time.Hour)
	o.NotAfter = time.Now().Add(-24 * time.Hour)
	return o
}

// CA is a certificate authority able to issue certificates.
type CA struct {
	Cert
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func build(t testing.TB, o CertOpts, isCA bool, parent *Cert) Cert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: o.CommonName, Organization: []string{"sslcheck test"}},
		NotBefore:             o.NotBefore,
		NotAfter:              o.NotAfter,
		DNSNames:              o.DNSNames,
		IPAddresses:           o.IPs,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		OCSPServer:            o.OCSPServer,
		CRLDistributionPoints: o.CRLDistributionPoints,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.Leaf, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Cert{DER: der, Key: key, Leaf: leaf}
}

// NewCA generates a self-signed root CA.
func NewCA(t testing.TB, commonName string) *CA {
	t.Helper()
	return &CA{Cert: build(t, CertOpts{CommonName: commonName}, true, nil)}
}

// NewIntermediate issues an intermediate CA signed by ca.
func (ca *CA) NewIntermediate(t testing.TB, commonName string) *CA {
	t.Helper()
	return &CA{Cert: build(t, CertOpts{CommonName: commonName}, true, &ca.Cert)}
}

// NewIntermediateWith issues an intermediate CA signed by ca using o.
func (ca *CA) NewIntermediateWith(t testing.TB, o CertOpts) *CA {
	t.Helper()
	return &CA{Cert: build(t, o, true, &ca.Cert)}
}

// Issue issues a leaf certificate signed by ca.
func (ca *CA) Issue(t testing.TB, o CertOpts) *Cert {
	t.Helper()
	c := build(t, o, false, &ca.Cert)
	return &c
}

// SelfSigned generates a self-signed leaf certificate.
func SelfSigned(t testing.TB, o CertOpts) *Cert {
	t.Helper()
	c := build(t, o, false, nil)
	return &c
}
