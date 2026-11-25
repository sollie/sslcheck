package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// CTLog is a fake Certificate Transparency log able to sign SCTs.
type CTLog struct {
	Name string
	Key  *ecdsa.PrivateKey
	spki []byte
	id   [32]byte
}

// NewCTLog generates a fake log.
func NewCTLog(t testing.TB, name string) *CTLog {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &CTLog{Name: name, Key: key, spki: spki, id: sha256.Sum256(spki)}
}

func (l *CTLog) sign(t testing.TB, ts time.Time, entry func(b *cryptobyte.Builder)) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint8(0)
	b.AddUint8(0)
	b.AddUint64(uint64(ts.UnixMilli())) //nolint:gosec // test timestamps are positive
	entry(&b)
	b.AddUint16(0)
	signed, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, l.Key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var out cryptobyte.Builder
	out.AddUint8(0)
	out.AddBytes(l.id[:])
	out.AddUint64(uint64(ts.UnixMilli())) //nolint:gosec // test timestamps are positive
	out.AddUint16(0)
	out.AddUint8(4)
	out.AddUint8(3)
	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sig) })
	res, err := out.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// SignX509 returns an SCT for c as an x509 entry, as served in the TLS
// extension or a stapled OCSP response.
func (l *CTLog) SignX509(t testing.TB, c *Cert) []byte {
	t.Helper()
	return l.sign(t, time.Now().Add(-time.Minute), func(b *cryptobyte.Builder) {
		b.AddUint16(0)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(c.DER) })
	})
}

func (l *CTLog) signPrecert(t testing.TB, issuerSPKI, tbs []byte) []byte {
	t.Helper()
	keyHash := sha256.Sum256(issuerSPKI)
	return l.sign(t, time.Now().Add(-time.Minute), func(b *cryptobyte.Builder) {
		b.AddUint16(1)
		b.AddBytes(keyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(tbs) })
	})
}

// SCTListExtension encodes scts as an extension value (a DER OCTET STRING
// holding a TLS SignedCertificateTimestampList).
func SCTListExtension(t testing.TB, scts ...[]byte) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, s := range scts {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(s) })
		}
	})
	list, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// LogListJSON renders a v3 log list dated date holding logs.
func LogListJSON(t testing.TB, date time.Time, logs ...*CTLog) []byte {
	t.Helper()
	type entry struct {
		Description string `json:"description"`
		LogID       string `json:"log_id"`
		Key         string `json:"key"`
	}
	var entries []entry
	for _, l := range logs {
		entries = append(entries, entry{l.Name, base64.StdEncoding.EncodeToString(l.id[:]), base64.StdEncoding.EncodeToString(l.spki)})
	}
	data, err := json.Marshal(map[string]any{
		"log_list_timestamp": date.UTC().Format(time.RFC3339),
		"operators":          []any{map[string]any{"name": "Fake Operator", "logs": entries}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// WriteLogList writes a log list holding logs to a temporary file and returns its path.
func WriteLogList(t testing.TB, logs ...*CTLog) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log_list.json")
	if err := os.WriteFile(path, LogListJSON(t, time.Now(), logs...), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
