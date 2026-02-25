package agentbox

import "runtime"

// osLinux is the GOOS value for Linux, extracted as a constant to satisfy goconst.
const osLinux = "linux"

// MaybeSandboxInit checks if the current process was re-executed as a sandbox helper.
// On Linux, this checks for the _AGENTBOX_CONFIG environment variable.
// On other platforms, this is a no-op that returns false.
//
// Call this at the very beginning of main() before any other initialization:
//
//	func main() {
//	    if agentbox.MaybeSandboxInit() {
//	        return
//	    }
//	    // ... rest of main
//	}
func MaybeSandboxInit() bool {
	if runtime.GOOS == osLinux {
		return maybeSandboxInitLinux()
	}
	return false
}
