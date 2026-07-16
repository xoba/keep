package keep

// Renewable leases: fetch at start, refresh after the server's
// refresh_after (~12 h) with jitter, exponential backoff on failure, stale
// past soft_lease_until (~24 h) while continuing to serve the last good
// value. This is the in-process mode; the CLI's exec mode is one-shot by
// nature (an environment variable cannot be refreshed after process start).

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

type Renewed struct {
	c      *Client
	name   string
	onNew  func(*Lease) // optional; called (not concurrently) when version changes
	mu     sync.RWMutex
	lease  *Lease
	value  []byte
	stale  bool
	cancel context.CancelFunc
}

// LeaseRenewed obtains the secret and keeps it fresh in the background until
// Stop (or ctx cancellation). The initial lease is synchronous: if keep is
// unreachable at startup, this returns an error (the documented cold-start
// behavior — decide at the call site whether to fail or proceed degraded).
//
// onNew, if non-nil, runs after the value changes version — install the new
// value into whatever actually uses it.
func (c *Client) LeaseRenewed(ctx context.Context, name string, onNew func(*Lease)) (*Renewed, error) {
	l, err := c.LeaseSecret(name)
	if err != nil {
		return nil, err
	}
	v, err := l.PayloadBytes()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &Renewed{c: c, name: name, onNew: onNew, lease: l, value: v, cancel: cancel}
	go r.loop(ctx)
	return r, nil
}

// Value returns the current secret bytes and whether they are stale (older
// than the soft lease and unrefreshable so far — still usable; the upstream
// credential does not expire with the lease).
func (r *Renewed) Value() (payload []byte, version int64, stale bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.value, r.lease.Version, r.stale
}

func (r *Renewed) Stop() { r.cancel() }

// The retry ladder starts at one second: secrets are often needed fast, and
// a failed renewal never blocks anyone — the previously leased value keeps
// being served from memory (Value never waits) while the loop retries in
// the background.
func (r *Renewed) loop(ctx context.Context) {
	const (
		retryMin = time.Second
		retryMax = 15 * time.Minute
	)
	retry := retryMin
	for {
		r.mu.RLock()
		l := r.lease
		r.mu.RUnlock()

		wait := timeUntil(l.RefreshAfter, 12*time.Hour)
		wait += time.Duration(rand.Int63n(int64(10 * time.Minute))) // jitter
		if r.isStale() || retry > retryMin {
			wait = retry // in trouble: retry cadence instead of lease cadence
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		nl, err := r.c.LeaseSecret(r.name)
		if err != nil {
			retry = min(retry*2, retryMax)
			r.updateStale()
			continue
		}
		nv, err := nl.PayloadBytes()
		if err != nil {
			retry = min(retry*2, retryMax)
			continue
		}
		retry = retryMin
		r.mu.Lock()
		changed := nl.Version != r.lease.Version
		r.lease, r.value, r.stale = nl, nv, false
		r.mu.Unlock()
		if changed && r.onNew != nil {
			r.onNew(nl)
		}
	}
}

func (r *Renewed) isStale() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.stale
}

// updateStale marks the value stale once soft_lease_until has passed.
func (r *Renewed) updateStale() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if until, err := time.Parse(time.RFC3339, r.lease.SoftLeaseUntil); err == nil {
		if time.Now().After(until) {
			r.stale = true
		}
	}
}

// timeUntil returns the duration until the RFC3339 timestamp t, or def when
// t is unparseable; never negative.
func timeUntil(t string, def time.Duration) time.Duration {
	ts, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return def
	}
	d := time.Until(ts)
	if d < 0 {
		return 0
	}
	return d
}
