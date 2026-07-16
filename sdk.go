package keep

// SDK is the high-level client: the recommended interface for services.
// Secrets fetched through it are leased once, then auto-renewed in the
// background for the life of the process (renew at refresh_after with
// jitter, back off on failure, serve the last good value past the soft
// lease). Callers just ask for current values — no lease bookkeeping on
// their side. All state is in memory: a restart simply re-leases on first
// use.

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

type SDK struct {
	c        *Client
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	leases   map[string]*Renewed
	healthMu sync.RWMutex
	healthFn func() string
	base     Status // captured once: start time, revision, host
}

// NewSDK builds the high-level client from an identity directory (as
// written by `keep keygen`) and immediately begins sending keep-alive
// status reports every 5 minutes (after 15 silent minutes the operator's
// dashboard shows the deployment offline). Health defaults to "healthy",
// meaning only "this process is up" — services that can genuinely
// self-assess should call SetHealth. Close stops the reports.
func NewSDK(identityDir string) (*SDK, error) {
	c, err := New(identityDir)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &SDK{
		c: c, ctx: ctx, cancel: cancel,
		leases: map[string]*Renewed{},
		base:   DefaultStatus("healthy"),
	}
	go s.statusLoop()
	return s, nil
}

// SetHealth installs the service's own health assessment, consulted at
// every keep-alive. Return "healthy" or "unhealthy".
func (s *SDK) SetHealth(fn func() string) {
	s.healthMu.Lock()
	s.healthFn = fn
	s.healthMu.Unlock()
}

// statusLoop reports immediately, then every 5 minutes ±1 minute of jitter
// (so a fleet of clients doesn't report in lockstep). Errors are swallowed:
// the next tick retries, and a persistent failure surfaces on the
// operator's dashboard as offline.
func (s *SDK) statusLoop() {
	for {
		st := s.base
		s.healthMu.RLock()
		if s.healthFn != nil {
			st.Health = s.healthFn()
		}
		s.healthMu.RUnlock()
		s.c.PutStatus(st)
		wait := 4*time.Minute + time.Duration(rand.Int63n(int64(2*time.Minute)))
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// ListSecrets returns the names of the secrets available to this
// deployment's service.
func (s *SDK) ListSecrets() ([]string, error) {
	infos, err := s.c.ListSelfSecrets()
	if err != nil {
		return nil, err
	}
	names := make([]string, len(infos))
	for i, in := range infos {
		names[i] = in.Name
	}
	return names, nil
}

// FetchSecret returns the current value of a named secret, leasing it on
// first use and auto-renewing thereafter. Safe (and cheap) to call per
// operation: after the first call it reads from memory, and a rotated value
// appears here within the renewal window (~12 h) with no restart.
//
// The value is the exact stored payload bytes as a string — by convention
// the provider's credential verbatim, usually plain text.
func (s *SDK) FetchSecret(name string) (string, error) {
	s.mu.Lock()
	r := s.leases[name]
	s.mu.Unlock()
	if r == nil {
		nr, err := s.c.LeaseRenewed(s.ctx, name, nil)
		if err != nil {
			return "", err
		}
		s.mu.Lock()
		if cur := s.leases[name]; cur != nil {
			s.mu.Unlock()
			nr.Stop() // lost a benign race; use the winner
			r = cur
		} else {
			s.leases[name] = nr
			s.mu.Unlock()
			r = nr
		}
	}
	v, _, _ := r.Value()
	return string(v), nil
}

// Backup snapshots and uploads a SQLite database (stateless; run it
// periodically — uploads are idempotent).
func (s *SDK) Backup(dbName, sqlitePath string) (*BackupResult, error) {
	return s.c.BackupDatabase(dbName, sqlitePath)
}

// Raw exposes the underlying low-level API client.
func (s *SDK) Raw() *Client { return s.c }

// Close stops keep-alives and all background renewals.
func (s *SDK) Close() { s.cancel() }
