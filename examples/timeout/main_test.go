package main

import (
	"testing"

	"github.com/zhangyunhao116/agentbox"
)

func TestTimeout(t *testing.T) {
	if agentbox.MaybeSandboxInit() {
		return
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
