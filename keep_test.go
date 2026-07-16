package keep

// The fake server below implements the wire contract (API.md) verbatim and
// doubles as an executable statement of it: mTLS with fingerprint-pinned
// Ed25519 client keys, the five /v1/self endpoints, the backup upload
// rules (declared Content-Length, Content-Digest, Idempotency-Key), and
// the JSON error envelope.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- fake server ----

type fakeServer struct {
	mu         sync.Mutex
	keyids     map[string]string // fingerprint -> service
	secrets    map[string][]byte // name -> payload
	statuses   []Status
	desired    string
	leaseCount map[string]int
	backups    []BackupResult
	idem       map[string]BackupResult // idempotency key -> completed record
	ts         *httptest.Server
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{
		keyids:     map[string]string{},
		secrets:    map[string][]byte{},
		leaseCount: map[string]int{},
		idem:       map[string]BackupResult{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/self/status", f.auth(f.putStatus))
	mux.HandleFunc("GET /v1/self/secrets", f.auth(f.listSecrets))
	mux.HandleFunc("POST /v1/self/secrets/{name}/lease", f.auth(f.lease))
	mux.HandleFunc("POST /v1/self/databases/{name}/backups", f.auth(f.uploadBackup))
	mux.HandleFunc("POST /v1/self/desired-revision", f.auth(f.setDesired))

	f.ts = httptest.NewUnstartedServer(mux)
	f.ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	f.ts.StartTLS()
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeServer) register(fingerprint, service string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keyids[fingerprint] = service
}

func (f *fakeServer) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			errJSON(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
		if !ok {
			errJSON(w, http.StatusUnauthorized, "ed25519 client certificate required")
			return
		}
		f.mu.Lock()
		_, known := f.keyids[Fingerprint(pub)]
		f.mu.Unlock()
		if !known {
			errJSON(w, http.StatusUnauthorized, "unknown or disabled client key")
			return
		}
		h(w, r)
	}
}

func (f *fakeServer) putStatus(w http.ResponseWriter, r *http.Request) {
	// Parity with the real server: 64 KiB cap (413), then any valid JSON
	// is accepted — the body is not required to be a Status shape.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		errJSON(w, http.StatusRequestEntityTooLarge, "status too large")
		return
	}
	if !json.Valid(body) {
		errJSON(w, http.StatusBadRequest, "status must be json")
		return
	}
	var st Status
	json.Unmarshal(body, &st) // best effort, for test assertions only
	f.mu.Lock()
	f.statuses = append(f.statuses, st)
	f.mu.Unlock()
	okJSON(w, map[string]string{"ok": "svc/dep"})
}

func (f *fakeServer) listSecrets(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	metas := []SecretInfo{}
	for name := range f.secrets {
		metas = append(metas, SecretInfo{
			Service: "svc", Name: name, Version: 1,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
	okJSON(w, map[string]any{"secrets": metas})
}

func (f *fakeServer) lease(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	f.mu.Lock()
	payload, ok := f.secrets[name]
	f.leaseCount[name]++
	f.mu.Unlock()
	if !ok {
		errJSON(w, http.StatusNotFound, "no such secret in this service")
		return
	}
	now := time.Now().UTC()
	resp := map[string]any{
		"name":             name,
		"version":          int64(1),
		"media_type":       nil,
		"issued_at":        now.Format(time.RFC3339),
		"refresh_after":    now.Add(12 * time.Hour).Format(time.RFC3339),
		"soft_lease_until": now.Add(24 * time.Hour).Format(time.RFC3339),
		"payload_base64":   base64.StdEncoding.EncodeToString(payload),
	}
	if json.Valid(payload) {
		resp["payload"] = json.RawMessage(payload)
	}
	okJSON(w, resp)
}

func (f *fakeServer) setDesired(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Revision string `json:"revision"`
	}
	// Parity with the real server: request bodies are strict — unknown
	// fields are rejected with 400.
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad json body: "+err.Error())
		return
	}
	if body.Revision == "" {
		errJSON(w, http.StatusBadRequest, "revision required")
		return
	}
	f.mu.Lock()
	f.desired = body.Revision
	f.mu.Unlock()
	okJSON(w, map[string]string{"service": "svc", "desired_revision": body.Revision})
}

func (f *fakeServer) uploadBackup(w http.ResponseWriter, r *http.Request) {
	// The contract's hard rule: a positive declared Content-Length.
	if r.ContentLength <= 0 {
		errJSON(w, http.StatusLengthRequired, "Content-Length required")
		return
	}
	declared, err := parseDigest(r.Header.Get("Content-Digest"))
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	idem := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idem == "" || len(idem) > 128 {
		errJSON(w, http.StatusBadRequest, "Idempotency-Key header required (<=128 bytes)")
		return
	}
	// Idempotent retry: a client that lost the response gets its backup back.
	f.mu.Lock()
	prev, seen := f.idem[idem]
	f.mu.Unlock()
	if seen {
		okJSON(w, prev)
		return
	}
	uncompressed, err := strconv.ParseInt(r.URL.Query().Get("uncompressed_size"), 10, 64)
	if err != nil || uncompressed <= 0 {
		errJSON(w, http.StatusBadRequest, "uncompressed_size query parameter required")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || int64(len(body)) != r.ContentLength {
		errJSON(w, http.StatusBadRequest, "body length mismatch")
		return
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != declared {
		errJSON(w, http.StatusBadRequest, "content digest mismatch")
		return
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		errJSON(w, http.StatusBadRequest, "not gzip")
		return
	}
	raw, err := io.ReadAll(gz)
	if err != nil || int64(len(raw)) != uncompressed {
		errJSON(w, http.StatusBadRequest, "uncompressed size mismatch")
		return
	}
	if !strings.HasPrefix(string(raw), "SQLite format 3\x00") {
		errJSON(w, http.StatusBadRequest, "not a sqlite database")
		return
	}
	f.mu.Lock()
	res := BackupResult{
		ID: fmt.Sprintf("test-backup-%d", len(f.backups)+1), Service: "svc",
		DatabaseName: r.PathValue("name"),
		State:        "available", SizeBytes: r.ContentLength,
		UncompressedSizeBytes: uncompressed, SHA256: declared,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
	}
	f.backups = append(f.backups, res)
	f.idem[idem] = res
	f.mu.Unlock()
	okJSON(w, res)
}

func parseDigest(h string) (string, error) {
	h = strings.TrimSpace(h)
	const pre = "sha-256=:"
	if !strings.HasPrefix(h, pre) || !strings.HasSuffix(h, ":") {
		return "", fmt.Errorf("want Content-Digest: sha-256=:BASE64:")
	}
	raw, err := base64.StdEncoding.DecodeString(h[len(pre) : len(h)-1])
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("bad sha-256 digest value")
	}
	return hex.EncodeToString(raw), nil
}

func okJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---- test wiring ----

// newIdentity generates a fresh identity dir and returns it with its keyid.
func newIdentity(t *testing.T) (dir, keyid string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "ident")
	keyid, _, err := GenerateIdentity(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	return dir, keyid
}

// newTestClient wires a Client to the fake server: BaseURL via the test
// seam, and an HTTP client that trusts the test server's certificate while
// presenting the identity's client certificate.
func newTestClient(t *testing.T, f *fakeServer, identityDir string) *Client {
	t.Helper()
	c, err := New(identityDir)
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://api.keepcentral.com" {
		t.Fatalf("default BaseURL = %q, want the built-in endpoint", c.BaseURL)
	}
	cert, err := loadClientCert(identityDir)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.ts.Certificate())
	c.BaseURL = f.ts.URL
	c.HTTP = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	return c
}

// ---- tests ----

func TestGenerateIdentity(t *testing.T) {
	dir, keyid := newIdentity(t)
	if len(keyid) != 64 {
		t.Fatalf("keyid %q is not a hex sha256", keyid)
	}
	for _, name := range []string{"cert.pem", "key.pem"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want 0600", name, fi.Mode().Perm())
		}
	}
	cert, err := loadClientCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := parsed.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("certificate key is %T, want ed25519", parsed.PublicKey)
	}
	if Fingerprint(pub) != keyid {
		t.Fatal("fingerprint of loaded cert does not match keygen's keyid")
	}
}

func TestAuthRejectsUnknownKey(t *testing.T) {
	f := newFakeServer(t)
	dir, _ := newIdentity(t) // never registered
	c := newTestClient(t, f, dir)
	err := c.PutStatus(DefaultStatus("healthy"))
	if err == nil || !strings.Contains(err.Error(), "http 401") {
		t.Fatalf("want http 401 for unregistered key, got %v", err)
	}
}

func TestStatusLeaseSecretsDesired(t *testing.T) {
	f := newFakeServer(t)
	dir, keyid := newIdentity(t)
	f.register(keyid, "svc")
	c := newTestClient(t, f, dir)

	// status
	st := DefaultStatus("healthy")
	if st.Health != "healthy" || st.StartedAt == "" || st.HostMetadata["hostname"] == "" {
		t.Fatalf("DefaultStatus incomplete: %+v", st)
	}
	if err := c.PutStatus(st); err != nil {
		t.Fatal(err)
	}

	// lease: payload_base64 authoritative, payload echoed for valid JSON
	f.secrets["db-creds"] = []byte(`{"user":"u","pass":"p"}`)
	l, err := c.LeaseSecret("db-creds")
	if err != nil {
		t.Fatal(err)
	}
	got, err := l.PayloadBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"user":"u","pass":"p"}` {
		t.Fatalf("payload = %q", got)
	}
	if len(l.Payload) == 0 {
		t.Fatal("payload (raw JSON echo) missing for a JSON secret")
	}
	if _, err := c.LeaseSecret("nope"); err == nil || !strings.Contains(err.Error(), "http 404") {
		t.Fatalf("want http 404 for unknown secret, got %v", err)
	}

	// list
	infos, err := c.ListSelfSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "db-creds" {
		t.Fatalf("ListSelfSecrets = %+v", infos)
	}

	// set-desired
	if err := c.SetDesiredRevision("abc123"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	desired := f.desired
	f.mu.Unlock()
	if desired != "abc123" {
		t.Fatalf("desired = %q", desired)
	}
}

func TestLeaseRenewed(t *testing.T) {
	f := newFakeServer(t)
	dir, keyid := newIdentity(t)
	f.register(keyid, "svc")
	c := newTestClient(t, f, dir)
	f.secrets["s"] = []byte("raw-bytes-not-json")

	r, err := c.LeaseRenewed(t.Context(), "s", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	v, version, stale := r.Value()
	if string(v) != "raw-bytes-not-json" || version != 1 || stale {
		t.Fatalf("Value = %q v%d stale=%v", v, version, stale)
	}
	// unreachable server at start is a synchronous error
	if _, err := c.LeaseRenewed(t.Context(), "missing", nil); err == nil {
		t.Fatal("want synchronous error for missing secret")
	}
}

func TestBackupDatabase(t *testing.T) {
	f := newFakeServer(t)
	dir, keyid := newIdentity(t)
	f.register(keyid, "svc")
	c := newTestClient(t, f, dir)

	dbPath := filepath.Join(t.TempDir(), "app.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('hello')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	res, err := c.BackupDatabase("main", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "available" || res.DatabaseName != "main" || res.SizeBytes <= 0 {
		t.Fatalf("BackupResult = %+v", res)
	}
	// idempotency key and digest are derived from the same compressed bytes
	if res.SHA256 == "" {
		t.Fatal("no sha256 recorded")
	}
	if _, err := c.BackupDatabase("main", filepath.Join(t.TempDir(), "nope.db")); err == nil {
		t.Fatal("want error for missing database file")
	}
}

func TestBackupRequiresContentLength(t *testing.T) {
	// Contract rule: chunked uploads (no declared length) get 411.
	f := newFakeServer(t)
	dir, keyid := newIdentity(t)
	f.register(keyid, "svc")
	c := newTestClient(t, f, dir)

	pr, pw := io.Pipe()
	go func() { pw.Write([]byte("x")); pw.Close() }()
	req, err := http.NewRequest("POST", c.BaseURL+"/v1/self/databases/main/backups?uncompressed_size=1", pr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.HTTP.Do(req) // ContentLength unknown -> chunked
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusLengthRequired {
		t.Fatalf("status = %d, want 411", resp.StatusCode)
	}
}

func TestBackupIdempotentRetry(t *testing.T) {
	// Contract rule: retrying identical content returns the original record
	// and never duplicates a backup.
	f := newFakeServer(t)
	dir, keyid := newIdentity(t)
	f.register(keyid, "svc")
	c := newTestClient(t, f, dir)

	raw := append([]byte("SQLite format 3\x00"), []byte("fake page data")...)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(raw)
	gz.Close()
	body := buf.Bytes()
	sum := sha256.Sum256(body)
	hexsum := hex.EncodeToString(sum[:])

	upload := func() BackupResult {
		req, err := http.NewRequest("POST",
			c.BaseURL+fmt.Sprintf("/v1/self/databases/main/backups?uncompressed_size=%d", len(raw)),
			bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "application/vnd.sqlite3+gzip")
		req.Header.Set("Content-Digest", digestHeader(hexsum))
		req.Header.Set("Idempotency-Key", "sha256:"+hexsum)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d: %s", resp.StatusCode, b)
		}
		var out BackupResult
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	first, second := upload(), upload()
	if first.ID != second.ID {
		t.Fatalf("retry created a new backup: %q vs %q", first.ID, second.ID)
	}
	f.mu.Lock()
	n := len(f.backups)
	f.mu.Unlock()
	if n != 1 {
		t.Fatalf("backups stored = %d, want 1", n)
	}
}

func TestDesiredRevisionStrictBody(t *testing.T) {
	// Contract rule: request bodies are strict — unknown fields get 400.
	f := newFakeServer(t)
	dir, keyid := newIdentity(t)
	f.register(keyid, "svc")
	c := newTestClient(t, f, dir)

	req, err := http.NewRequest("POST", c.BaseURL+"/v1/self/desired-revision",
		strings.NewReader(`{"revision":"abc","note":"nope"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown request field", resp.StatusCode)
	}
}

func TestStatusBodyCap(t *testing.T) {
	// Contract rule: status bodies over 64 KiB get 413.
	f := newFakeServer(t)
	dir, keyid := newIdentity(t)
	f.register(keyid, "svc")
	c := newTestClient(t, f, dir)

	big := `{"health":"` + strings.Repeat("x", 65<<10) + `"}`
	req, err := http.NewRequest("PUT", c.BaseURL+"/v1/self/status", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for oversized status", resp.StatusCode)
	}
}

func TestNewSDKBadIdentity(t *testing.T) {
	if _, err := NewSDK(filepath.Join(t.TempDir(), "no-such-dir")); err == nil {
		t.Fatal("want error for missing identity dir")
	}
}

func TestSDK(t *testing.T) {
	f := newFakeServer(t)
	dir, keyid := newIdentity(t)
	f.register(keyid, "svc")
	f.secrets["api"] = []byte(`{"key":"k"}`)

	// Constructed by hand (NewSDK's body, with the client wired to the fake
	// server first): NewSDK reports status immediately, and a unit test must
	// never let that first report reach the built-in production endpoint.
	ctx, cancel := context.WithCancel(context.Background())
	s := &SDK{
		c: newTestClient(t, f, dir), ctx: ctx, cancel: cancel,
		leases: map[string]*Renewed{},
		base:   DefaultStatus("healthy"),
	}
	go s.statusLoop()
	defer s.Close()

	// keep-alives: the first status report is immediate
	deadline := time.Now().Add(10 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.statuses)
		f.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no status report within 10s")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// FetchSecret leases once, then serves from memory
	v, err := s.FetchSecret("api")
	if err != nil {
		t.Fatal(err)
	}
	if v != `{"key":"k"}` {
		t.Fatalf("FetchSecret = %q", v)
	}
	if _, err := s.FetchSecret("api"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	leases := f.leaseCount["api"]
	f.mu.Unlock()
	if leases != 1 {
		t.Fatalf("lease count = %d, want 1 (cached after first fetch)", leases)
	}

	names, err := s.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "api" {
		t.Fatalf("ListSecrets = %v", names)
	}

	if err := s.Raw().SetDesiredRevision("deadbeef"); err != nil {
		t.Fatal(err)
	}
}
