package main

import "testing"

func TestClassifier(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
