// Package starttls upgrades a plaintext SMTP, IMAP or POP3 connection to TLS
// in-band, ready for a handshake.
package starttls

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Protocols accepted by Upgrade, besides None.
var Protocols = []string{"smtp", "imap", "pop3"}

// None explicitly disables STARTTLS, overriding port inference.
const None = "none"

// Infer returns the STARTTLS protocol conventionally spoken on port, or ""
// for implicit TLS and unknown ports.
func Infer(port int) string {
	switch port {
	case 25, 587:
		return "smtp"
	case 143:
		return "imap"
	case 110:
		return "pop3"
	}
	return ""
}

// Valid reports whether p is a protocol name accepted by the --starttls flag.
func Valid(p string) bool {
	if p == "" || p == None {
		return true
	}
	for _, v := range Protocols {
		if p == v {
			return true
		}
	}
	return false
}

// Bounds on what a server may send during the plaintext dialogue.
const (
	maxLineBytes  = 4096
	maxReplyLines = 100
	maxTotalBytes = 64 * 1024
)

// Upgrade runs the STARTTLS exchange for proto on conn. On success the next
// bytes on conn are the TLS handshake.
func Upgrade(conn net.Conn, proto string) error {
	br := &reader{Reader: bufio.NewReader(conn)}
	var err error
	switch proto {
	case "smtp":
		err = smtp(conn, br)
	case "imap":
		err = imap(conn, br)
	case "pop3":
		err = pop3(conn, br)
	default:
		err = fmt.Errorf("unsupported protocol")
	}
	if err == nil && br.Buffered() > 0 {
		err = errors.New("unexpected data after STARTTLS go-ahead")
	}
	if err != nil {
		return fmt.Errorf("STARTTLS %s: %w", proto, err)
	}
	return nil
}

// reader bounds the bytes a server can make us read during the dialogue.
type reader struct {
	*bufio.Reader
	total int
}

func line(br *reader) (string, error) {
	var buf []byte
	for {
		frag, err := br.ReadSlice('\n')
		buf = append(buf, frag...)
		br.total += len(frag)
		switch {
		case br.total > maxTotalBytes:
			return "", fmt.Errorf("reply exceeds %d bytes", maxTotalBytes)
		case len(buf) > maxLineBytes:
			return "", fmt.Errorf("reply line exceeds %d bytes", maxLineBytes)
		case err == nil:
			return strings.TrimRight(string(buf), "\r\n"), nil
		case !errors.Is(err, bufio.ErrBufferFull):
			return "", fmt.Errorf("reading reply: %w", err)
		}
	}
}

// smtpReply reads a possibly multi-line reply and returns its code and lines.
func smtpReply(br *reader) (string, []string, error) {
	var lines []string
	for {
		l, err := line(br)
		if err != nil {
			return "", nil, err
		}
		if len(l) < 3 || (len(l) > 3 && l[3] != '-' && l[3] != ' ') {
			return "", nil, fmt.Errorf("malformed reply %q", l)
		}
		lines = append(lines, l)
		if len(l) == 3 || l[3] != '-' {
			return l[:3], lines, nil
		}
		if len(lines) >= maxReplyLines {
			return "", nil, fmt.Errorf("reply exceeds %d lines", maxReplyLines)
		}
	}
}

func smtp(conn net.Conn, br *reader) error {
	if code, lines, err := smtpReply(br); err != nil {
		return err
	} else if code != "220" {
		return fmt.Errorf("unexpected greeting %q", lines[len(lines)-1])
	}
	if _, err := fmt.Fprint(conn, "EHLO sslcheck.invalid\r\n"); err != nil {
		return err
	}
	code, lines, err := smtpReply(br)
	if err != nil {
		return err
	}
	if code != "250" {
		return fmt.Errorf("EHLO rejected: %q", lines[len(lines)-1])
	}
	offered := false
	for _, l := range lines[1:] {
		if len(l) < 4 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(l[4:]), "STARTTLS") {
			offered = true
		}
	}
	if !offered {
		return fmt.Errorf("server does not offer STARTTLS")
	}
	if _, err := fmt.Fprint(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	if code, lines, err = smtpReply(br); err != nil {
		return err
	} else if code != "220" {
		return fmt.Errorf("server refused: %q", lines[len(lines)-1])
	}
	return nil
}

func imap(conn net.Conn, br *reader) error {
	greeting, err := line(br)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(greeting, "* OK") && !strings.HasPrefix(greeting, "* PREAUTH") {
		return fmt.Errorf("unexpected greeting %q", greeting)
	}
	if _, err := fmt.Fprint(conn, "sslcheck1 STARTTLS\r\n"); err != nil {
		return err
	}
	for {
		l, err := line(br)
		if err != nil {
			return err
		}
		if rest, ok := strings.CutPrefix(l, "sslcheck1 "); ok {
			if !strings.HasPrefix(strings.ToUpper(rest), "OK") {
				return fmt.Errorf("server refused: %q", l)
			}
			return nil
		}
	}
}

func pop3(conn net.Conn, br *reader) error {
	greeting, err := line(br)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return fmt.Errorf("unexpected greeting %q", greeting)
	}
	if _, err := fmt.Fprint(conn, "STLS\r\n"); err != nil {
		return err
	}
	reply, err := line(br)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, "+OK") {
		return fmt.Errorf("server refused: %q", reply)
	}
	return nil
}
