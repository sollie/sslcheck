package ct

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ocsp"
)

// MinSCTs is how many valid SCTs from distinct logs a certificate should carry.
const MinSCTs = 2

// Where an SCT was found.
const (
	SourceCertificate = "certificate"
	SourceTLS         = "tls-extension"
	SourceOCSP        = "ocsp"
)

var (
	oidEmbeddedSCTs = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidOCSPSCTs     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}
)

// SCT is one signed certificate timestamp and the outcome of verifying it.
type SCT struct {
	Source    string
	LogID     string // base64, as in the log list
	Log       string // log description, empty when the log is unknown
	Timestamp time.Time
	Valid     bool
	// Detail explains why an SCT is not valid.
	Detail string
}

// Result holds every SCT found for a Presented chain.
type Result struct {
	SCTs []SCT
	// Valid is the number of distinct logs with a valid SCT.
	Valid int
	// LogList describes the log list used.
	LogList string
}

type rawSCT struct {
	source    string
	embedded  bool
	timestamp uint64
	logID     [32]byte
	hash, alg byte
	sig       []byte
	exts      []byte
}

// Verify collects the SCTs from the leaf certificate, the TLS extension
// (tlsSCTs, one SCT per element) and the stapled OCSP response, and verifies
// each against list. now is used to reject timestamps from the future.
func Verify(list LogList, chain []*x509.Certificate, tlsSCTs [][]byte, staple []byte, now time.Time) Result {
	res := Result{LogList: list.Description()}
	if len(chain) == 0 {
		return res
	}
	leaf := chain[0]
	var raws []rawSCT
	add := func(source string, embedded bool, scts [][]byte) {
		for _, b := range scts {
			r, err := parseSCT(b)
			if err != nil {
				res.SCTs = append(res.SCTs, SCT{Source: source, Detail: err.Error()})
				continue
			}
			r.source, r.embedded = source, embedded
			raws = append(raws, r)
		}
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidEmbeddedSCTs) {
			add(SourceCertificate, true, splitList(res.fail(SourceCertificate), ext.Value))
		}
	}
	add(SourceTLS, false, tlsSCTs)
	if len(staple) > 0 {
		if resp, err := ocsp.ParseResponse(staple, nil); err == nil {
			for _, ext := range resp.Extensions {
				if ext.Id.Equal(oidOCSPSCTs) {
					add(SourceOCSP, false, splitList(res.fail(SourceOCSP), ext.Value))
				}
			}
		}
	}

	var issuer *x509.Certificate
	for _, c := range chain[1:] {
		if bytes.Equal(leaf.RawIssuer, c.RawSubject) && leaf.CheckSignatureFrom(c) == nil {
			issuer = c
			break
		}
	}
	good := map[[32]byte]bool{}
	for _, r := range raws {
		s := SCT{
			Source:    r.source,
			LogID:     base64.StdEncoding.EncodeToString(r.logID[:]),
			Timestamp: time.UnixMilli(int64(r.timestamp)).UTC(), //nolint:gosec // millisecond timestamps fit in int64
		}
		if err := r.check(list, leaf, issuer, now); err != nil {
			s.Detail = err.Error()
		} else {
			s.Valid = true
			good[r.logID] = true
		}
		if l, ok := list.Logs[r.logID]; ok {
			s.Log = l.Description
		}
		res.SCTs = append(res.SCTs, s)
	}
	res.Valid = len(good)
	return res
}

// fail returns a callback recording an unparseable SCT list from source.
func (r *Result) fail(source string) func(error) {
	return func(err error) { r.SCTs = append(r.SCTs, SCT{Source: source, Detail: err.Error()}) }
}

// splitList unwraps an extension value (a DER OCTET STRING) holding a TLS
// SignedCertificateTimestampList into its SCTs.
func splitList(onErr func(error), extValue []byte) [][]byte {
	var inner []byte
	if rest, err := asn1.Unmarshal(extValue, &inner); err != nil || len(rest) != 0 {
		onErr(errors.New("malformed SCT list extension"))
		return nil
	}
	in := cryptobyte.String(inner)
	var list cryptobyte.String
	if !in.ReadUint16LengthPrefixed(&list) || !in.Empty() {
		onErr(errors.New("malformed SCT list"))
		return nil
	}
	var out [][]byte
	for !list.Empty() {
		var sct cryptobyte.String
		if !list.ReadUint16LengthPrefixed(&sct) {
			onErr(errors.New("malformed SCT list"))
			return out
		}
		out = append(out, sct)
	}
	return out
}

func parseSCT(b []byte) (rawSCT, error) {
	r := rawSCT{}
	s := cryptobyte.String(b)
	var version uint8
	var id, sig, exts cryptobyte.String
	if !s.ReadUint8(&version) {
		return r, errors.New("malformed SCT")
	}
	if version != 0 {
		return r, fmt.Errorf("unsupported SCT version %d", version)
	}
	if !s.ReadBytes((*[]byte)(&id), 32) || !s.ReadUint64(&r.timestamp) ||
		!s.ReadUint16LengthPrefixed(&exts) || !s.ReadUint8(&r.hash) || !s.ReadUint8(&r.alg) ||
		!s.ReadUint16LengthPrefixed(&sig) || !s.Empty() {
		return r, errors.New("malformed SCT")
	}
	copy(r.logID[:], id)
	r.sig, r.exts = sig, exts
	return r, nil
}

func (r rawSCT) check(list LogList, leaf, issuer *x509.Certificate, now time.Time) error {
	log, ok := list.Logs[r.logID]
	if !ok {
		return errors.New("log is not in the log list")
	}
	if time.UnixMilli(int64(r.timestamp)).After(now) { //nolint:gosec // millisecond timestamps fit in int64
		return errors.New("timestamp is in the future")
	}
	var b cryptobyte.Builder
	b.AddUint8(0) // sct version v1
	b.AddUint8(0) // certificate_timestamp
	b.AddUint64(r.timestamp)
	if r.embedded {
		if issuer == nil {
			return errors.New("issuer not in the Presented chain, cannot rebuild the precertificate")
		}
		tbs, err := tbsWithoutSCTs(leaf.RawTBSCertificate)
		if err != nil {
			return err
		}
		keyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		b.AddUint16(1) // precert_entry
		b.AddBytes(keyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(tbs) })
	} else {
		b.AddUint16(0) // x509_entry
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(leaf.Raw) })
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(r.exts) })
	signed, err := b.Bytes()
	if err != nil {
		return err
	}
	if r.hash != 4 { // sha256
		return fmt.Errorf("unsupported SCT hash algorithm %d", r.hash)
	}
	digest := sha256.Sum256(signed)
	switch key := log.Key.(type) {
	case *ecdsa.PublicKey:
		if r.alg != 3 || !ecdsa.VerifyASN1(key, digest[:], r.sig) {
			return errors.New("signature does not verify")
		}
	case *rsa.PublicKey:
		if r.alg != 1 || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], r.sig) != nil {
			return errors.New("signature does not verify")
		}
	default:
		return errors.New("unsupported log key type")
	}
	return nil
}

// tbsWithoutSCTs returns tbs with the embedded SCT list extension removed,
// which is what a log signed when it issued the SCT for the precertificate.
func tbsWithoutSCTs(tbs []byte) ([]byte, error) {
	bad := errors.New("malformed TBSCertificate")
	in := cryptobyte.String(tbs)
	var body cryptobyte.String
	if !in.ReadASN1(&body, cbasn1.SEQUENCE) {
		return nil, bad
	}
	extTag := cbasn1.Tag(3).ContextSpecific().Constructed()
	var b cryptobyte.Builder
	var buildErr error
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for !body.Empty() {
			var el cryptobyte.String
			var tag cbasn1.Tag
			if !body.ReadAnyASN1Element(&el, &tag) {
				buildErr = bad
				return
			}
			if tag != extTag {
				b.AddBytes(el)
				continue
			}
			var wrapper, exts cryptobyte.String
			if !el.ReadASN1(&wrapper, extTag) || !wrapper.ReadASN1(&exts, cbasn1.SEQUENCE) {
				buildErr = bad
				return
			}
			b.AddASN1(extTag, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for !exts.Empty() {
						var ext cryptobyte.String
						if !exts.ReadAnyASN1Element(&ext, nil) {
							buildErr = bad
							return
						}
						probe := ext
						var seq cryptobyte.String
						var oid asn1.ObjectIdentifier
						if !probe.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&oid) {
							buildErr = bad
							return
						}
						if !oid.Equal(oidEmbeddedSCTs) {
							b.AddBytes(ext)
						}
					}
				})
			})
		}
	})
	if buildErr != nil {
		return nil, buildErr
	}
	return b.Bytes()
}
