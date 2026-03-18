package main

import (
	"testing"

	"github.com/zhangyunhao116/agentbox"
	"github.com/zhangyunhao116/agentbox/testutil"
)

func TestNetwork(t *testing.T) {
	testutil.SkipIfWindows(t, "example uses Exec() which requires Unix shell")
	if agentbox.MaybeSandboxInit() {
		return
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
