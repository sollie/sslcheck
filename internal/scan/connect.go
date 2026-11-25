package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/sollie/sslcheck/internal/starttls"
	"github.com/sollie/sslcheck/internal/verify"
)

// connectOptions control how a Target is connected to.
type connectOptions struct {
	network  string
	sni      string
	startTLS string
}

// connect completes an unverified handshake with t (ADR-0002), upgrading
// in-band first when a STARTTLS protocol applies, and returns the Evidence.
// ctx bounds the whole connection; cancelling it closes the plaintext
// connection. at is the Scan's single clock reading.
func connect(ctx context.Context, t Target, opts connectOptions, at time.Time) (verify.Evidence, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // scanner inspects untrusted chains by design, see ADR-0002
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       scanCipherSuites(),
	}
	if net.ParseIP(opts.sni) == nil {
		cfg.ServerName = opts.sni
	}
	proto := opts.startTLS
	if proto == "" {
		proto = starttls.Infer(t.Port)
	}
	var tlsConn *tls.Conn
	if proto == "" || proto == starttls.None {
		dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
		conn, err := dialer.DialContext(ctx, opts.network, t.Address())
		if err != nil {
			return verify.Evidence{}, err
		}
		tlsConn = conn.(*tls.Conn)
	} else {
		conn, err := (&net.Dialer{}).DialContext(ctx, opts.network, t.Address())
		if err != nil {
			return verify.Evidence{}, fmt.Errorf("STARTTLS %s: %w", proto, err)
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(dl)
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		if err := starttls.Upgrade(conn, proto); err != nil {
			_ = conn.Close()
			return verify.Evidence{}, err
		}
		tlsConn = tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return verify.Evidence{}, err
		}
	}
	defer func() { _ = tlsConn.Close() }()

	state := tlsConn.ConnectionState()
	return verify.Evidence{
		Chain:        state.PeerCertificates,
		Name:         opts.sni,
		OCSPResponse: state.OCSPResponse,
		SCTs:         state.SignedCertificateTimestamps,
		TLSVersion:   tls.VersionName(state.Version),
		CipherSuite:  state.CipherSuite,
		At:           at,
	}, nil
}

// scanCipherSuites lists every suite Go implements, including those it
// excludes by default, so legacy Targets can still be inspected (ADR-0002).
// Only the scanning handshake uses it.
func scanCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}
