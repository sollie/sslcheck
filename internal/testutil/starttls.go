package testutil

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

// StartSTARTTLS starts a fake mail server on 127.0.0.1 speaking proto
// ("smtp", "imap" or "pop3") in plaintext and upgrading to TLS, presenting
// leaf followed by rest, once the client issues STARTTLS. With refuse set the
// server declines the upgrade. A client that starts a TLS handshake without
// upgrading first gets no certificates.
func StartSTARTTLS(t testing.TB, proto string, refuse bool, leaf *Cert, rest ...*Cert) *Server {
	t.Helper()
	chain := [][]byte{leaf.DER}
	for _, c := range rest {
		chain = append(chain, c.DER)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leaf.Key}},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			go serveSTARTTLS(conn, proto, refuse, cfg)
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return &Server{Addr: ln.Addr().String(), Host: host, Port: p, ln: ln}
}

func serveSTARTTLS(conn net.Conn, proto string, refuse bool, cfg *tls.Config) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	say := func(format string, a ...any) { _, _ = fmt.Fprintf(conn, format+"\r\n", a...) }
	upgrade := func() {
		tc := tls.Server(conn, cfg)
		_ = tc.Handshake()
	}

	switch proto {
	case "smtp":
		say("220 fake.test ESMTP ready")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				if refuse {
					say("250-fake.test\r\n250 8BITMIME")
				} else {
					say("250-fake.test\r\n250-8BITMIME\r\n250 STARTTLS")
				}
			case cmd == "STARTTLS":
				if refuse {
					say("502 5.5.1 STARTTLS not supported")
					continue
				}
				say("220 2.0.0 Ready to start TLS")
				upgrade()
				return
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("500 unrecognised")
			}
		}
	case "imap":
		say("* OK [CAPABILITY IMAP4rev1 STARTTLS] fake ready")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			tag, cmd, _ := strings.Cut(strings.TrimSpace(line), " ")
			switch strings.ToUpper(cmd) {
			case "STARTTLS":
				if refuse {
					say("%s NO STARTTLS disabled", tag)
					continue
				}
				say("%s OK Begin TLS negotiation now", tag)
				upgrade()
				return
			case "LOGOUT":
				say("* BYE")
				say("%s OK done", tag)
				return
			default:
				say("%s BAD unknown command", tag)
			}
		}
	case "pop3":
		say("+OK fake POP3 ready")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			switch strings.ToUpper(strings.TrimSpace(line)) {
			case "STLS":
				if refuse {
					say("-ERR STLS not supported")
					continue
				}
				say("+OK Begin TLS negotiation")
				upgrade()
				return
			case "QUIT":
				say("+OK bye")
				return
			default:
				say("-ERR unknown")
			}
		}
	}
}
