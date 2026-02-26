package main

import (
	"testing"

	"github.com/zhangyunhao116/agentbox"
)

func TestNetworkAccess(t *testing.T) {
	if agentbox.MaybeSandboxInit() {
		return
	}

	if err := run(); err != nil {
		t.Fatal(err)
	}
}
