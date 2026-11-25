// Package starttls upgrades a plaintext SMTP, IMAP or POP3 connection to TLS
// in-band, ready for a handshake.
package starttls

import (
	"bufio"
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

// Upgrade runs the STARTTLS exchange for proto on conn. On success the next
// bytes on conn are the TLS handshake.
func Upgrade(conn net.Conn, proto string) error {
	br := bufio.NewReader(conn)
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
	if err != nil {
		return fmt.Errorf("STARTTLS %s: %w", proto, err)
	}
	return nil
}

func line(br *bufio.Reader) (string, error) {
	s, err := br.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading reply: %w", err)
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// smtpReply reads a possibly multi-line reply and returns its code and lines.
func smtpReply(br *bufio.Reader) (string, []string, error) {
	var lines []string
	for {
		l, err := line(br)
		if err != nil {
			return "", nil, err
		}
		if len(l) < 3 {
			return "", nil, fmt.Errorf("malformed reply %q", l)
		}
		lines = append(lines, l)
		if len(l) == 3 || l[3] != '-' {
			return l[:3], lines, nil
		}
	}
}

func smtp(conn net.Conn, br *bufio.Reader) error {
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

func imap(conn net.Conn, br *bufio.Reader) error {
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

func pop3(conn net.Conn, br *bufio.Reader) error {
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
