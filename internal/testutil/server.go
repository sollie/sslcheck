package testutil

import (
	"crypto/tls"
	"net"
	"strconv"
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
	chain := [][]byte{leaf.DER}
	for _, c := range rest {
		chain = append(chain, c.DER)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leaf.Key, OCSPStaple: staple}},
		MinVersion:   tls.VersionTLS12,
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
