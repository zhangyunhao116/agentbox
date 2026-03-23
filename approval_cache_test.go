package agentbox

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// TestMemoryApprovalCacheGetEmpty verifies that Get on an empty cache
// returns (Sandboxed, false).
func TestMemoryApprovalCacheGetEmpty(t *testing.T) {
	c := NewMemoryApprovalCache()
	d, ok := c.Get("anything")
	if ok {
		t.Fatal("Get on empty cache should return ok=false")
	}
	if d != Sandboxed {
		t.Errorf("Get on empty cache returned decision %v, want Sandboxed (zero value)", d)
	}
}

// TestMemoryApprovalCacheSetGet verifies basic Set then Get.
func TestMemoryApprovalCacheSetGet(t *testing.T) {
	c := NewMemoryApprovalCache()
	c.Set("sudo reboot", Allow)

	d, ok := c.Get("sudo reboot")
	if !ok {
		t.Fatal("Get after Set should return ok=true")
	}
	if d != Allow {
		t.Errorf("Get returned decision %v, want Allow", d)
	}
}

// TestMemoryApprovalCacheMultipleCommands verifies that different commands
// are cached independently.
func TestMemoryApprovalCacheMultipleCommands(t *testing.T) {
	c := NewMemoryApprovalCache()
	c.Set("sudo reboot", Allow)
	c.Set("echo remote", Escalated)

	d1, ok1 := c.Get("sudo reboot")
	d2, ok2 := c.Get("echo remote")

	if !ok1 || d1 != Allow {
		t.Errorf("sudo reboot: got (%v, %v), want (Allow, true)", d1, ok1)
	}
	if !ok2 || d2 != Escalated {
		t.Errorf("echo remote: got (%v, %v), want (Escalated, true)", d2, ok2)
	}
}

// TestMemoryApprovalCacheExactMatch verifies that the cache uses exact
// command string matching — different commands produce different entries.
func TestMemoryApprovalCacheExactMatch(t *testing.T) {
	c := NewMemoryApprovalCache()
	c.Set("sudo apt install vim", Allow)

	_, ok := c.Get("sudo apt install emacs")
	if ok {
		t.Error("cache should not match different command strings")
	}

	_, ok = c.Get("sudo apt install vim")
	if !ok {
		t.Error("cache should match the exact command string that was set")
	}
}

// TestMemoryApprovalCacheOverwrite verifies that Set overwrites a previous entry.
func TestMemoryApprovalCacheOverwrite(t *testing.T) {
	c := NewMemoryApprovalCache()
	c.Set("echo hello", Allow)
	c.Set("echo hello", Escalated)

	d, ok := c.Get("echo hello")
	if !ok || d != Escalated {
		t.Errorf("after overwrite: got (%v, %v), want (Escalated, true)", d, ok)
	}
}

// TestMemoryApprovalCacheForbiddenNotCached verifies that Forbidden decisions
// are silently dropped by Set — they must always be re-evaluated.
func TestMemoryApprovalCacheForbiddenNotCached(t *testing.T) {
	c := NewMemoryApprovalCache()
	c.Set("rm -rf /", Forbidden)

	_, ok := c.Get("rm -rf /")
	if ok {
		t.Error("Forbidden decision should not be cached, but Get returned ok=true")
	}
}

// TestMemoryApprovalCacheConcurrency verifies thread safety with concurrent
// Get and Set operations.
func TestMemoryApprovalCacheConcurrency(t *testing.T) {
	c := NewMemoryApprovalCache()
	var wg sync.WaitGroup

	// Spin up writers.
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := "cmd-" + string(rune('A'+i%26))
			c.Set(cmd, Allow)
		}(i)
	}

	// Spin up readers.
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Get("cmd-A")
		}()
	}

	wg.Wait()
	// If we reach here without a data race panic, the test passes.
}

// TestNopManagerApprovalCacheSkipsCallback verifies that the NopManager
// skips the ApprovalCallback on the second call for the same command when
// an ApprovalCache is configured.
func TestNopManagerApprovalCacheSkipsCallback(t *testing.T) {
	cache := NewMemoryApprovalCache()
	callCount := 0
	cb := func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return Approve, nil
	}
	mgr := newNopManagerWithConfig(&Config{
		ApprovalCallback: cb,
		ApprovalCache:    cache,
	})
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "test"}}

	// First call: callback invoked, result cached.
	_, err := mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("first Exec: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("callback count after first Exec = %d, want 1", callCount)
	}

	// Second call: callback should be skipped (cache hit).
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("second Exec: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callback count after second Exec = %d, want 1 (cached)", callCount)
	}
}

// TestNopManagerApprovalCacheDenied verifies that a denied decision is
// cached and auto-denies subsequent calls without invoking the callback.
func TestNopManagerApprovalCacheDenied(t *testing.T) {
	cache := NewMemoryApprovalCache()
	callCount := 0
	cb := func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return Deny, nil
	}
	mgr := newNopManagerWithConfig(&Config{
		ApprovalCallback: cb,
		ApprovalCache:    cache,
	})
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "test"}}

	// First call: callback invoked, denial cached.
	_, err := mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("first Exec should have been denied")
	}
	if callCount != 1 {
		t.Fatalf("callback count after first Exec = %d, want 1", callCount)
	}

	// Second call: callback should NOT be invoked (cached denial).
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("second Exec should have been denied (cached)")
	}
	if callCount != 1 {
		t.Errorf("callback count after second Exec = %d, want 1 (cached denial)", callCount)
	}
}

// TestNopManagerForbiddenNotCached verifies that Forbidden commands are
// never cached in the ApprovalCache.
func TestNopManagerForbiddenNotCached(t *testing.T) {
	cache := NewMemoryApprovalCache()
	mgr := newNopManagerWithConfig(&Config{
		ApprovalCache: cache,
	})
	defer mgr.Cleanup(context.Background())

	forbidAll := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "blocked"}}

	// Execute a Forbidden command.
	_, err := mgr.Exec(context.Background(), "rm -rf /", WithClassifier(forbidAll))
	if err == nil {
		t.Fatal("Forbidden command should fail")
	}

	// The cache should remain empty — Forbidden decisions are not cached.
	_, ok := cache.Get(normalizeCommand("rm -rf /"))
	if ok {
		t.Error("Forbidden command was cached, but should not be")
	}
}

// TestNopManagerNoCacheStillWorks verifies that the approval flow works
// without a cache (cache is nil).
func TestNopManagerNoCacheStillWorks(t *testing.T) {
	callCount := 0
	cb := func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return Approve, nil
	}
	mgr := newNopManagerWithConfig(&Config{
		ApprovalCallback: cb,
		// No ApprovalCache set.
	})
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "test"}}

	// Both calls should invoke the callback (no caching).
	_, err := mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("first Exec: %v", err)
	}
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("second Exec: %v", err)
	}
	if callCount != 2 {
		t.Errorf("callback count = %d, want 2 (no caching)", callCount)
	}
}

// TestManagerApprovalCacheSkipsCallback verifies that the main Manager
// skips the ApprovalCallback on the second call when an ApprovalCache
// is configured.
func TestManagerApprovalCacheSkipsCallback(t *testing.T) {
	cfg := newTestConfig(t)
	cache := NewMemoryApprovalCache()
	callCount := 0
	cfg.ApprovalCallback = func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return Approve, nil
	}
	cfg.ApprovalCache = cache
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "test"}}

	// First call: callback invoked.
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if isStubWrapError(err) {
		t.Skip("skipping: platform stub does not implement WrapCommand")
	}
	if err != nil {
		t.Fatalf("first Exec: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("callback count after first Exec = %d, want 1", callCount)
	}

	// Second call: cached approval, callback NOT invoked.
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("second Exec: %v", err)
	}
	if callCount != 1 {
		t.Errorf("callback count after second Exec = %d, want 1 (cached)", callCount)
	}
}

// TestManagerForbiddenNotCached verifies that Forbidden commands are never
// cached in the ApprovalCache via the main Manager.
func TestManagerForbiddenNotCached(t *testing.T) {
	cfg := newTestConfig(t)
	cache := NewMemoryApprovalCache()
	cfg.ApprovalCache = cache
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	forbidAll := &mockClassifier{result: ClassifyResult{Decision: Forbidden, Reason: "blocked"}}

	_, err = mgr.Exec(context.Background(), "rm -rf /", WithClassifier(forbidAll))
	if err == nil {
		t.Fatal("Forbidden command should fail")
	}

	_, ok := cache.Get(normalizeCommand("rm -rf /"))
	if ok {
		t.Error("Forbidden command was cached, but should not be")
	}
}

// TestWithApprovalCacheOption verifies the WithApprovalCache config helper.
func TestWithApprovalCacheOption(t *testing.T) {
	cfg := DefaultConfig()
	cache := NewMemoryApprovalCache()
	WithApprovalCache(cache)(cfg)

	if cfg.ApprovalCache != cache {
		t.Error("WithApprovalCache did not set the cache on Config")
	}
}

// TestApprovalCacheInterfaceCompliance verifies that MemoryApprovalCache
// satisfies the ApprovalCache interface at compile time.
func TestApprovalCacheInterfaceCompliance(t *testing.T) {
	var _ ApprovalCache = (*MemoryApprovalCache)(nil)
	var _ ApprovalCache = NewMemoryApprovalCache()
}

// TestNopManagerApprovalCacheDifferentCommands verifies that different
// escalated commands are cached independently.
func TestNopManagerApprovalCacheDifferentCommands(t *testing.T) {
	cache := NewMemoryApprovalCache()
	callCount := 0
	cb := func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return Approve, nil
	}
	mgr := newNopManagerWithConfig(&Config{
		ApprovalCallback: cb,
		ApprovalCache:    cache,
	})
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "test"}}

	// First command.
	_, err := mgr.Exec(context.Background(), "echo hello1", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("Exec echo hello1: %v", err)
	}

	// Different command — callback should be invoked again.
	_, err = mgr.Exec(context.Background(), "echo hello2", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("Exec echo hello2: %v", err)
	}

	if callCount != 2 {
		t.Errorf("callback count = %d, want 2 (different commands)", callCount)
	}

	// Same command as first — should be cached.
	_, err = mgr.Exec(context.Background(), "echo hello1", WithClassifier(escalateAll))
	if err != nil {
		t.Fatalf("Exec echo hello1 (repeat): %v", err)
	}
	if callCount != 2 {
		t.Errorf("callback count after repeat = %d, want 2 (cached)", callCount)
	}
}

// TestManagerApprovalCacheDeniedError verifies the error message for cached denials.
func TestManagerApprovalCacheDeniedError(t *testing.T) {
	cache := NewMemoryApprovalCache()
	callCount := 0
	cb := func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		callCount++
		return Deny, nil
	}
	mgr := newNopManagerWithConfig(&Config{
		ApprovalCallback: cb,
		ApprovalCache:    cache,
	})
	defer mgr.Cleanup(context.Background())

	escalateAll := &mockClassifier{result: ClassifyResult{Decision: Escalated, Reason: "test"}}

	// First call denied by user — triggers callback.
	_, err := mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("should be denied")
	}
	if !strings.Contains(err.Error(), "denied by user") {
		t.Errorf("first denial error = %v, want 'denied by user'", err)
	}

	// Second call — denied by cache, no callback.
	_, err = mgr.Exec(context.Background(), "echo hello", WithClassifier(escalateAll))
	if err == nil {
		t.Fatal("should be denied by cache")
	}
	if !strings.Contains(err.Error(), "denied by cached decision") {
		t.Errorf("cached denial error = %v, want 'denied by cached decision'", err)
	}
	if callCount != 1 {
		t.Errorf("callback count = %d, want 1", callCount)
	}
}

// TestMemoryApprovalCacheZeroValue verifies that a zero-value
// MemoryApprovalCache (created without NewMemoryApprovalCache) is safe
// to use: Get returns (Sandboxed, false), and Set+Get round-trips work.
func TestMemoryApprovalCacheZeroValue(t *testing.T) {
	var cache MemoryApprovalCache

	// Get on zero value must not panic and must report miss.
	d, ok := cache.Get("test-cmd")
	if ok {
		t.Error("expected ok=false for zero-value cache Get")
	}
	if d != Sandboxed {
		t.Errorf("expected Sandboxed, got %v", d)
	}

	// Set then Get should work.
	cache.Set("test-cmd", Escalated)
	d, ok = cache.Get("test-cmd")
	if !ok {
		t.Error("expected ok=true after Set")
	}
	if d != Escalated {
		t.Errorf("expected Escalated, got %v", d)
	}

	// Forbidden must not be cached (same behavior as constructed cache).
	cache.Set("forbidden-cmd", Forbidden)
	_, ok = cache.Get("forbidden-cmd")
	if ok {
		t.Error("expected ok=false for Forbidden decision")
	}
}
