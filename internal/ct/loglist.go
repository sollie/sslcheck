// Package ct reads SCTs from a Presented chain and verifies their signatures
// against a Certificate Transparency log list.
package ct

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sollie/sslcheck/internal/refresh"
)

const (
	// EnvLogList names a log list file that replaces the embedded and cached
	// lists. It lets tests inject a fake log.
	EnvLogList = "SSLCHECK_CT_LOG_LIST"
	// EnvLogListURL overrides the log list download URL.
	EnvLogListURL = "SSLCHECK_CT_LOG_LIST_URL"

	// DefaultLogListURL is where the log list is published.
	DefaultLogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
	// LogListFile is the cached log list's name inside the cache directory.
	LogListFile = "log_list.json"
)

//go:embed log_list.json
var embeddedList []byte

// Log is one Certificate Transparency log.
type Log struct {
	ID          [32]byte
	Description string
	Operator    string
	Key         crypto.PublicKey
}

// LogList is a set of known logs keyed by log ID.
type LogList struct {
	Logs map[[32]byte]Log
	// Source says where the list came from, for example "embedded".
	Source string
	// Date is the list's own timestamp.
	Date time.Time
}

// Description returns the source and date of the list for reports.
func (l LogList) Description() string {
	if l.Date.IsZero() {
		return l.Source
	}
	return l.Source + ", " + l.Date.UTC().Format(time.DateOnly)
}

type listFile struct {
	Timestamp string `json:"log_list_timestamp"`
	Operators []struct {
		Name      string    `json:"name"`
		Logs      []logJSON `json:"logs"`
		TiledLogs []logJSON `json:"tiled_logs"`
	} `json:"operators"`
}

type logJSON struct {
	Description string `json:"description"`
	LogID       string `json:"log_id"`
	Key         string `json:"key"`
}

// Parse reads a v3 log list. Logs whose key does not match their ID are rejected.
func Parse(data []byte) (LogList, error) {
	var f listFile
	if err := json.Unmarshal(data, &f); err != nil {
		return LogList{}, fmt.Errorf("parse CT log list: %w", err)
	}
	ts, err := time.Parse(time.RFC3339, f.Timestamp)
	if err != nil {
		return LogList{}, fmt.Errorf("CT log list has no valid log_list_timestamp: %w", err)
	}
	list := LogList{Logs: map[[32]byte]Log{}, Date: ts}
	for _, op := range f.Operators {
		for _, l := range append(append([]logJSON{}, op.Logs...), op.TiledLogs...) {
			der, err := base64.StdEncoding.DecodeString(l.Key)
			if err != nil {
				return LogList{}, fmt.Errorf("CT log %q: bad key encoding: %w", l.Description, err)
			}
			pub, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				return LogList{}, fmt.Errorf("CT log %q: %w", l.Description, err)
			}
			id := sha256.Sum256(der)
			if want, err := base64.StdEncoding.DecodeString(l.LogID); err != nil || string(want) != string(id[:]) {
				return LogList{}, fmt.Errorf("CT log %q: log_id does not match its key", l.Description)
			}
			list.Logs[id] = Log{ID: id, Description: l.Description, Operator: op.Name, Key: pub}
		}
	}
	if len(list.Logs) == 0 {
		return LogList{}, errors.New("CT log list holds no logs")
	}
	return list, nil
}

// Embedded returns the log list compiled into the binary.
func Embedded() (LogList, error) {
	l, err := Parse(embeddedList)
	if err != nil {
		return LogList{}, fmt.Errorf("embedded CT log list: %w", err)
	}
	l.Source = "embedded"
	return l, nil
}

// Load returns the log list to verify against: the file named by EnvLogList
// when set, otherwise a cached list in the cache directory when it is newer
// than the embedded one, otherwise the embedded list.
func Load(env map[string]string) (LogList, error) {
	if path := env[EnvLogList]; path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied by design
		if err != nil {
			return LogList{}, fmt.Errorf("read %s: %w", EnvLogList, err)
		}
		l, err := Parse(data)
		if err != nil {
			return LogList{}, fmt.Errorf("%s: %w", EnvLogList, err)
		}
		l.Source = "file " + path
		return l, nil
	}
	emb, err := Embedded()
	if err != nil {
		return LogList{}, err
	}
	parse := func(data []byte) (LogList, time.Time, error) {
		l, err := Parse(data)
		return l, l.Date, err
	}
	if l, path, ok := refresh.Cached(env, LogListFile, emb.Date, parse); ok {
		l.Source = "cache " + path
		return l, nil
	}
	return emb, nil
}

// Update downloads the log list, validates it and stores it in the cache
// directory. Nothing is written unless the list parses and is newer than the
// embedded one. The list's own signature is not checked; it only decides which
// logs may raise warnings, never a failure. A nil client uses http.DefaultClient;
// pass truststore.HTTPClient() where the system may have no root certificates.
func Update(ctx context.Context, env map[string]string, client *http.Client) (refresh.Result, error) {
	emb, err := Embedded()
	if err != nil {
		return refresh.Result{}, err
	}
	return refresh.Update(ctx, env, client, refresh.Dataset{
		Name:         "CT log list",
		File:         LogListFile,
		URLEnv:       EnvLogListURL,
		DefaultURL:   DefaultLogListURL,
		EmbeddedDate: emb.Date,
		Parse: func(data []byte) (refresh.Info, error) {
			l, err := Parse(data)
			return refresh.Info{Date: l.Date, Count: len(l.Logs)}, err
		},
	})
}
