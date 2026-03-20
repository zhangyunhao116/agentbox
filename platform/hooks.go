package platform

import (
	"os/exec"
	"sync"
)

// PostStartHook is called after cmd.Start() but before cmd.Wait().
// On Windows, the sandbox platform uses this to assign processes to Job Objects
// and resume suspended processes. The hook is removed after execution.
//
// This mechanism allows platform-specific WrapCommand implementations to inject
// custom process setup logic that must occur after process creation but before
// the process begins execution (e.g., Job Object assignment to a suspended process).
type PostStartHook func(cmd *exec.Cmd) error

var (
	postStartMu    sync.Mutex
	postStartHooks = map[*exec.Cmd]PostStartHook{}
)

// RegisterPostStartHook registers a hook to be called after cmd.Start().
// The platform's WrapCommand implementation can use this to set up Job Objects,
// assign security contexts, or perform other post-creation operations.
//
// The hook is automatically removed after execution by PopPostStartHook.
// If cmd is nil, this is a no-op.
func RegisterPostStartHook(cmd *exec.Cmd, hook PostStartHook) {
	if cmd == nil || hook == nil {
		return
	}
	postStartMu.Lock()
	defer postStartMu.Unlock()
	postStartHooks[cmd] = hook
}

// PopPostStartHook retrieves and removes the registered hook for cmd.
// Returns nil if no hook is registered.
// This is called by the executor after cmd.Start().
func PopPostStartHook(cmd *exec.Cmd) PostStartHook {
	if cmd == nil {
		return nil
	}
	postStartMu.Lock()
	defer postStartMu.Unlock()
	hook := postStartHooks[cmd]
	delete(postStartHooks, cmd)
	return hook
}
