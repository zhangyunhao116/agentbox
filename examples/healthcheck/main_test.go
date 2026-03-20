package main

import (
	"testing"

	"github.com/zhangyunhao116/agentbox"
	"github.com/zhangyunhao116/agentbox/testutil"
)

func TestHealthCheck(t *testing.T) {
	testutil.SkipIfWindows(t, "example requires sandbox platform not available on CI runners")
	if agentbox.MaybeSandboxInit() {
		return
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
