package dataset

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestScanEntries(t *testing.T) {
	entries := []entry{
		{Command: "ls -la", Count: 100},
		{Command: "git status", Count: 50},
		{Command: "rm -rf /", Count: 3},
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got []entry
	err = ScanEntriesProgress(bytes.NewReader(data), func(command string, count int) error {
		got = append(got, entry{Command: command, Count: count})
		return nil
	}, io.Discard)
	if err != nil {
		t.Fatalf("ScanEntries: %v", err)
	}

	if len(got) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(got), len(entries))
	}
	for i, e := range entries {
		if got[i].Command != e.Command || got[i].Count != e.Count {
			t.Errorf("entry %d: got {%q, %d}, want {%q, %d}",
				i, got[i].Command, got[i].Count, e.Command, e.Count)
		}
	}
}

func TestScanEntriesEmpty(t *testing.T) {
	var count int
	err := ScanEntriesProgress(bytes.NewReader([]byte("[]")), func(string, int) error {
		count++
		return nil
	}, io.Discard)
	if err != nil {
		t.Fatalf("ScanEntries on empty array: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries, got %d", count)
	}
}

func TestScanEntriesCallbackError(t *testing.T) {
	data := []byte(`[{"command":"ls","count":1}]`)
	sentinel := errors.New("stop")

	err := ScanEntriesProgress(bytes.NewReader(data), func(string, int) error {
		return sentinel
	}, io.Discard)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestScanEntriesInvalidJSON(t *testing.T) {
	err := ScanEntries(bytes.NewReader([]byte("{}")), func(string, int) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for non-array JSON")
	}
}

func TestScanEntriesMalformedEntry(t *testing.T) {
	err := ScanEntries(bytes.NewReader([]byte(`[{"command":}]`)), func(string, int) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for malformed entry")
	}
}

func TestScanEntriesBrokenReader(t *testing.T) {
	err := ScanEntries(strings.NewReader(""), func(string, int) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for empty reader")
	}
}
