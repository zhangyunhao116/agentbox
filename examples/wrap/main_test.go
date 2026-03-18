package main

import (
	"testing"

	"github.com/zhangyunhao116/agentbox"
	"github.com/zhangyunhao116/agentbox/testutil"
)

func TestWrap(t *testing.T) {
	testutil.SkipIfWindows(t, "example uses DefaultConfig() which defaults to /bin/sh, unavailable on Windows")
	if agentbox.MaybeSandboxInit() {
		return
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
