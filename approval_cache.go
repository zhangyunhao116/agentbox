package agentbox

import "sync"

// Compile-time interface check.
var _ ApprovalCache = (*MemoryApprovalCache)(nil)

// ApprovalCache caches user approval decisions for commands, avoiding
// repeated prompts for the same or similar commands. Implementations
// must be safe for concurrent use by multiple goroutines.
//
// Only Escalated command decisions (where the user was actually prompted)
// should be stored. Forbidden commands must never be cached to allow,
// and Allow/Sandboxed commands bypass the approval flow entirely.
type ApprovalCache interface {
	// Get returns the cached decision for a command, or (Sandboxed, false)
	// if no cached decision was found. The second return value indicates
	// whether a cached entry exists.
	Get(cmd string) (Decision, bool)

	// Set stores a user's approval decision for a command.
	Set(cmd string, decision Decision)
}

// MemoryApprovalCache is a thread-safe in-memory implementation of
// ApprovalCache. Decisions are stored for the lifetime of the cache
// (typically one session).
type MemoryApprovalCache struct {
	mu    sync.RWMutex
	cache map[string]Decision
}

// NewMemoryApprovalCache creates a new empty MemoryApprovalCache.
func NewMemoryApprovalCache() *MemoryApprovalCache {
	return &MemoryApprovalCache{
		cache: make(map[string]Decision),
	}
}

// Get returns the cached decision for cmd, or (Sandboxed, false) if
// no entry exists. It is safe to call on a zero-value MemoryApprovalCache.
func (c *MemoryApprovalCache) Get(cmd string) (Decision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cache == nil {
		return Sandboxed, false
	}
	d, ok := c.cache[cmd]
	return d, ok
}

// Set stores a decision for cmd in the cache.
// Forbidden decisions are never cached — they must always be re-evaluated.
// It is safe to call on a zero-value MemoryApprovalCache.
func (c *MemoryApprovalCache) Set(cmd string, decision Decision) {
	if decision == Forbidden {
		return // Forbidden decisions must never be cached
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = make(map[string]Decision)
	}
	c.cache[cmd] = decision
}
