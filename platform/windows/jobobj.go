//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"github.com/zhangyunhao116/agentbox/platform"
	"golang.org/x/sys/windows"
)

// Job Object limit flags
const (
	jobObjectLimitKillOnJobClose   = 0x00002000
	jobObjectLimitActiveProcess    = 0x00000008
	jobObjectLimitJobMemory        = 0x00000200
	jobObjectLimitJobTime          = 0x00000004
)

// createJobObject creates a Job Object with the specified resource limits.
// The Job Object is configured to automatically terminate all processes when closed
// (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
//
// Additional limits are applied based on the provided ResourceLimits:
// - MaxProcesses: Limits the number of active processes in the job
// - MaxMemoryBytes: Limits total committed memory for all processes
// - MaxCPUSeconds: Limits total CPU time for all processes
//
// The returned handle must be closed by the caller via closeJobObject() or windows.CloseHandle().
func createJobObject(limits *platform.ResourceLimits) (windows.Handle, error) {
	// Create anonymous job object (no name)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject failed: %w", err)
	}

	// Ensure cleanup on error
	var success bool
	defer func() {
		if !success {
			windows.CloseHandle(job)
		}
	}()

	// Build extended limit information structure
	var extLimits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION

	// Always enable kill-on-job-close to ensure cleanup
	extLimits.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose

	// Apply MaxProcesses limit if specified
	if limits != nil && limits.MaxProcesses > 0 {
		extLimits.BasicLimitInformation.LimitFlags |= jobObjectLimitActiveProcess
		extLimits.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxProcesses)
	}

	// Apply MaxMemoryBytes limit if specified
	if limits != nil && limits.MaxMemoryBytes > 0 {
		extLimits.BasicLimitInformation.LimitFlags |= jobObjectLimitJobMemory
		extLimits.JobMemoryLimit = uintptr(limits.MaxMemoryBytes)
	}

	// Apply MaxCPUSeconds limit if specified
	// Windows uses 100-nanosecond units for time limits
	if limits != nil && limits.MaxCPUSeconds > 0 {
		extLimits.BasicLimitInformation.LimitFlags |= jobObjectLimitJobTime
		// Convert seconds to 100-nanosecond units (1 second = 10,000,000 * 100ns)
		extLimits.BasicLimitInformation.PerJobUserTimeLimit = int64(limits.MaxCPUSeconds) * 10000000
	}

	// Set the job object information
	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&extLimits)),
		uint32(unsafe.Sizeof(extLimits)),
	)
	if err != nil {
		return 0, fmt.Errorf("SetInformationJobObject failed: %w", err)
	}

	success = true
	return job, nil
}

// closeJobObject closes a Job Object handle.
// This is a convenience wrapper around windows.CloseHandle for clarity.
// When a job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is closed,
// all processes in the job are automatically terminated.
func closeJobObject(handle windows.Handle) error {
	if err := windows.CloseHandle(handle); err != nil {
		return fmt.Errorf("CloseHandle(job) failed: %w", err)
	}
	return nil
}
