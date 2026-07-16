// Package keep is the Go SDK for keep — the passive custodian for a small
// fleet of services (keepcentral.com): deployment status reports, leased
// secrets, and SQLite database backups. All calls authenticate via mTLS
// with the identity's Ed25519 key; the registered public-key fingerprint
// alone identifies a principal.
//
// The endpoint is built in: this SDK talks to the keepcentral.com
// deployment (design S9). There is nothing to configure but the identity.
package keep

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// defaultBaseURL is the one keep server this SDK talks to (design S9).
const defaultBaseURL = "https://api.keepcentral.com"

type Client struct {
	// BaseURL is set by New and exists as a seam for the test suite —
	// it is not a configuration knob (design S9).
	BaseURL string
	HTTP    *http.Client
}

// New builds a client from an identity directory (cert.pem + key.pem, as
// written by `keep keygen`).
func New(identityDir string) (*Client, error) {
	cert, err := loadClientCert(identityDir)
	if err != nil {
		return nil, fmt.Errorf("load identity from %s: %w", identityDir, err)
	}
	return &Client{
		BaseURL: defaultBaseURL,
		HTTP: &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
			},
		},
	}, nil
}

type apiError struct {
	Code int
	Msg  string
}

func (e *apiError) Error() string { return fmt.Sprintf("http %d: %s", e.Code, e.Msg) }

func (c *Client) do(method, path string, body io.Reader, contentType string, out any) error {
	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &apiError{Code: resp.StatusCode, Msg: e.Error}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) doJSON(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	return c.do(method, path, body, "application/json", out)
}

// ---- deployment operations ----

type Status struct {
	Health          string            `json:"health"`
	RunningRevision string            `json:"running_revision,omitempty"`
	StartedAt       string            `json:"started_at,omitempty"`
	ClientVersion   string            `json:"client_version,omitempty"`
	HostMetadata    map[string]string `json:"host_metadata,omitempty"`
}

// DefaultStatus fills a status report: revision and client version from
// build info, hostname from the OS, start time from the clock.
func DefaultStatus(health string) Status {
	st := Status{Health: health, StartedAt: time.Now().UTC().Format(time.RFC3339)}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				st.RunningRevision = s.Value
			}
		}
		st.ClientVersion = bi.Main.Version
	}
	host, _ := os.Hostname()
	st.HostMetadata = map[string]string{"hostname": host}
	return st
}

func (c *Client) PutStatus(st Status) error {
	return c.doJSON("PUT", "/v1/self/status", st, nil)
}

type Lease struct {
	Name           string          `json:"name"`
	Version        int64           `json:"version"`
	MediaType      *string         `json:"media_type"`
	IssuedAt       string          `json:"issued_at"`
	RefreshAfter   string          `json:"refresh_after"`
	SoftLeaseUntil string          `json:"soft_lease_until"`
	Payload        json.RawMessage `json:"payload"`
	PayloadBase64  string          `json:"payload_base64"`
}

// PayloadBytes returns the exact secret bytes.
func (l *Lease) PayloadBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(l.PayloadBase64)
}

func (c *Client) LeaseSecret(name string) (*Lease, error) {
	var l Lease
	if err := c.doJSON("POST", "/v1/self/secrets/"+url.PathEscape(name)+"/lease", nil, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// SecretInfo is secret metadata (never values).
type SecretInfo struct {
	Service   string  `json:"service"`
	Name      string  `json:"name"`
	Version   int64   `json:"version"`
	MediaType *string `json:"media_type,omitempty"`
	UpdatedAt string  `json:"updated_at"`
}

// ListSelfSecrets returns metadata for the secrets available to this
// deployment's service.
func (c *Client) ListSelfSecrets() ([]SecretInfo, error) {
	var out struct {
		Secrets []SecretInfo `json:"secrets"`
	}
	if err := c.doJSON("GET", "/v1/self/secrets", nil, &out); err != nil {
		return nil, err
	}
	return out.Secrets, nil
}

// SetDesiredRevision records the desired revision of this deployment's own
// service — the one deploy-time write this SDK carries (design S10). The
// server derives the service from the caller's identity; no other service
// can be named or touched. Typically called from a deploy script with the
// just-pushed commit hash.
func (c *Client) SetDesiredRevision(revision string) error {
	return c.doJSON("POST", "/v1/self/desired-revision",
		map[string]string{"revision": revision}, nil)
}

// sqliteMagic is the 16-byte header of every SQLite database file.
var sqliteMagic = []byte("SQLite format 3\x00")

// BackupResult is the server's backup record.
type BackupResult struct {
	ID                    string `json:"id"`
	Service               string `json:"service"`
	DatabaseName          string `json:"database_name"`
	State                 string `json:"state"`
	SizeBytes             int64  `json:"size_bytes"`
	UncompressedSizeBytes int64  `json:"uncompressed_size_bytes"`
	SHA256                string `json:"sha256"`
	ReceivedAt            string `json:"received_at"`
}

// BackupDatabase snapshots the SQLite database at srcPath (VACUUM INTO),
// validates the snapshot header, gzips it, and uploads it as dbName.
// All format validation happens here, client-side.
func (c *Client) BackupDatabase(dbName, srcPath string) (*BackupResult, error) {
	dir, err := os.MkdirTemp("", "keep-backup-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	// 1. Consistent snapshot of the live database.
	snap := filepath.Join(dir, "snap.sqlite3")
	if err := vacuumInto(srcPath, snap); err != nil {
		return nil, fmt.Errorf("snapshot %s: %w", srcPath, err)
	}

	// 2. Confirm the snapshot is a SQLite database.
	head := make([]byte, len(sqliteMagic))
	sf, err := os.Open(snap)
	if err != nil {
		return nil, err
	}
	_, err = io.ReadFull(sf, head)
	sf.Close()
	if err != nil || !bytes.Equal(head, sqliteMagic) {
		return nil, fmt.Errorf("snapshot is not a SQLite database")
	}
	snapInfo, err := os.Stat(snap)
	if err != nil {
		return nil, err
	}

	// 3. Gzip to a temp file (the digest must be known before the body is sent).
	gzPath := filepath.Join(dir, "snap.sqlite3.gz")
	if err := gzipFile(snap, gzPath); err != nil {
		return nil, err
	}

	// 4. Compressed SHA-256 doubles as the idempotency key: retrying
	// identical content can never duplicate a backup.
	sum, size, err := sha256File(gzPath)
	if err != nil {
		return nil, err
	}

	// 5. Upload.
	f, err := os.Open(gzPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	q := url.Values{
		"uncompressed_size": {fmt.Sprintf("%d", snapInfo.Size())},
		"created_at":        {time.Now().UTC().Format(time.RFC3339)},
	}
	req, err := http.NewRequest("POST",
		c.BaseURL+"/v1/self/databases/"+url.PathEscape(dbName)+"/backups?"+q.Encode(), f)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/vnd.sqlite3+gzip")
	req.Header.Set("Content-Digest", digestHeader(sum))
	req.Header.Set("Idempotency-Key", "sha256:"+sum)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("upload failed: http %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out BackupResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func vacuumInto(src, dst string) error {
	db, err := sql.Open("sqlite3", "file:"+src+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	quoted := strings.ReplaceAll(dst, "'", "''")
	_, err = db.Exec(fmt.Sprintf("VACUUM INTO '%s'", quoted))
	return err
}

func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	gz, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	if _, err := io.Copy(gz, in); err != nil {
		out.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func sha256File(path string) (hexsum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	size, err = io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func digestHeader(sha256hex string) string {
	raw, _ := hex.DecodeString(sha256hex)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(raw) + ":"
}
