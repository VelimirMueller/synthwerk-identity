package orgs

import (
	"sync"
	"time"
)

// Invite limits (synthwerk#37): an admin cannot mass-invite or probe emails.
const (
	InvitesPerCaller = 10
	InvitesPerOrg    = 30
	InviteWindow     = time.Hour
)

// InviteLimiter is a fixed-window limit per caller and per org, in memory. Each
// identity process counts on its own; with N processes the real limit is N times.
type InviteLimiter struct {
	PerCaller, PerOrg int
	Window            time.Duration
	// Now is the clock; nil = time.Now.
	Now func() time.Time

	mu      sync.Mutex
	windows map[string]window
}

type window struct {
	start time.Time
	n     int
}

// NewInviteLimiter returns the default limit: 10 per caller and 30 per org per hour.
func NewInviteLimiter() *InviteLimiter {
	return &InviteLimiter{PerCaller: InvitesPerCaller, PerOrg: InvitesPerOrg, Window: InviteWindow}
}

// Allow counts one invite of caller in org. It counts only when both limits
// allow it; else it returns false and the time until the next invite.
func (l *InviteLimiter) Allow(orgID, caller string) (bool, time.Duration) {
	now := time.Now()
	if l.Now != nil {
		now = l.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windows == nil {
		l.windows = map[string]window{}
	}
	if len(l.windows) > 4096 {
		for k, w := range l.windows {
			if now.Sub(w.start) >= l.Window {
				delete(l.windows, k)
			}
		}
	}
	keys := []struct {
		key   string
		limit int
	}{{"c:" + orgID + ":" + caller, l.PerCaller}, {"o:" + orgID, l.PerOrg}}
	var wait time.Duration
	for _, k := range keys {
		w := l.windows[k.key]
		if now.Sub(w.start) >= l.Window {
			w = window{start: now}
			l.windows[k.key] = w
		}
		if w.n >= k.limit {
			if d := w.start.Add(l.Window).Sub(now); d > wait {
				wait = d
			}
		}
	}
	if wait > 0 {
		return false, wait
	}
	for _, k := range keys {
		w := l.windows[k.key]
		w.n++
		l.windows[k.key] = w
	}
	return true, 0
}
