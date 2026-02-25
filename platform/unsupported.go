package platform

import (
	"context"
	"errors"
	"os/exec"
)

// unsupportedName is the name returned by the unsupported platform stub.
const unsupportedName = "unsupported"

// unsupportedPlatform is returned on operating systems where no sandbox is available.
type unsupportedPlatform struct{}

func (p *unsupportedPlatform) Name() string { return unsupportedName }

func (p *unsupportedPlatform) Available() bool { return false }

func (p *unsupportedPlatform) CheckDependencies() *DependencyCheck {
	return &DependencyCheck{
		Errors: []string{"unsupported operating system"},
	}
}

func (p *unsupportedPlatform) WrapCommand(_ context.Context, _ *exec.Cmd, _ *WrapConfig) error {
	return errors.New("sandbox not supported on this operating system")
}

func (p *unsupportedPlatform) Cleanup(_ context.Context) error {
	return nil
}

func (p *unsupportedPlatform) Capabilities() Capabilities {
	return Capabilities{}
}

// NewUnsupportedPlatform returns a Platform that always reports as unavailable.
// This is useful for testing and for platforms without sandbox support.
func NewUnsupportedPlatform() Platform {
	return &unsupportedPlatform{}
}
