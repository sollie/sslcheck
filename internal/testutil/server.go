package testutil

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"testing"
)

// Server is an in-process TLS server presenting a fixed chain.
type Server struct {
	Addr string // 127.0.0.1:port, usable directly as a Target
	Host string
	Port int

	ln net.Listener
}

// Close stops the server; it is also called automatically at test end.
func (s *Server) Close() { _ = s.ln.Close() }

// StartTLS starts a TLS server on 127.0.0.1 presenting leaf followed by rest,
// in exactly that order. It is closed when the test ends.
func StartTLS(t testing.TB, leaf *Cert, rest ...*Cert) *Server {
	t.Helper()
	return StartTLSStapled(t, nil, leaf, rest...)
}

// StartTLSStapled is StartTLS with staple as the stapled OCSP response.
func StartTLSStapled(t testing.TB, staple []byte, leaf *Cert, rest ...*Cert) *Server {
	t.Helper()
	return StartTLSSCTs(t, staple, nil, leaf, rest...)
}

// StartTLSSCTs is StartTLSStapled that also sends scts in the TLS SCT extension.
func StartTLSSCTs(t testing.TB, staple []byte, scts [][]byte, leaf *Cert, rest ...*Cert) *Server {
	t.Helper()
	return startTLS(t, nil, staple, scts, leaf, rest...)
}

// StartTLSCiphers is StartTLS limited to TLS 1.2 and the given cipher suites,
// including ones Go does not offer by default.
func StartTLSCiphers(t testing.TB, suites []uint16, leaf *Cert, rest ...*Cert) *Server {
	t.Helper()
	return startTLS(t, suites, nil, nil, leaf, rest...)
}

func startTLS(t testing.TB, suites []uint16, staple []byte, scts [][]byte, leaf *Cert, rest ...*Cert) *Server {
	t.Helper()
	chain := [][]byte{leaf.DER}
	for _, c := range rest {
		chain = append(chain, c.DER)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leaf.Signer(), OCSPStaple: staple, SignedCertificateTimestamps: scts}},
		MinVersion:   tls.VersionTLS12,
	}
	if suites != nil {
		cfg.CipherSuites = suites
		cfg.MaxVersion = tls.VersionTLS12
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return &Server{Addr: ln.Addr().String(), Host: host, Port: p, ln: ln}
}

// StartTLSDual starts two TLS servers on the same port, one on 127.0.0.1
// presenting v4 and one on [::1] presenting v6, so that localhost:Port has two
// addresses. It skips the test when IPv6 loopback or such a port is unavailable.
func StartTLSDual(t testing.TB, v4, v6 *Cert) int {
	t.Helper()
	first := startTLS(t, nil, nil, nil, v4)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{v6.DER}, PrivateKey: v6.Signer()}},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(first.Port)), cfg)
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return first.Port
}

// StartTLSV4HangingV6 is StartTLSDual where the [::1] side accepts
// connections and never answers the handshake.
func StartTLSV4HangingV6(t testing.TB, v4 *Cert) int {
	t.Helper()
	first := startTLS(t, nil, nil, nil, v4)
	ln, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(first.Port)))
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	return first.Port
}
