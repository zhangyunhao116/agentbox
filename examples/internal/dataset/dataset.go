// Package dataset provides shared helpers for streaming JSON command datasets
// used by multiple example programs. The dataset format is a JSON array of
// {"command": "...", "count": N} entries.
package dataset

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// entry mirrors a single object in the JSON dataset.
type entry struct {
	Command string `json:"command"`
	Count   int    `json:"count"`
}

// ScanEntries streams a JSON array of {"command","count"} objects from r,
// calling fn for each entry. It prints a progress indicator to stderr every
// 500k entries. The callback receives the command string and its occurrence
// count; returning a non-nil error aborts the scan.
func ScanEntries(r io.Reader, fn func(command string, count int) error) error {
	return ScanEntriesProgress(r, fn, os.Stderr)
}

// ScanEntriesProgress is like [ScanEntries] but writes progress output to
// the given writer instead of stderr. Pass nil or [io.Discard] to suppress
// progress output entirely.
func ScanEntriesProgress(r io.Reader, fn func(command string, count int) error, progress io.Writer) error {
	if progress == nil {
		progress = io.Discard
	}

	dec := json.NewDecoder(r)

	// Consume the opening '['.
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read opening token: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return fmt.Errorf("expected JSON array, got %v", tok)
	}

	var totalEntries int
	start := time.Now()

	for dec.More() {
		var e entry
		if err := dec.Decode(&e); err != nil {
			return fmt.Errorf("decode entry %d: %w", totalEntries+1, err)
		}
		totalEntries++

		if err := fn(e.Command, e.Count); err != nil {
			return err
		}

		// Progress indicator every 500k entries.
		if totalEntries%500_000 == 0 {
			elapsed := time.Since(start)
			fmt.Fprintf(progress, "\r  scanned %dk commands (%s)...", totalEntries/1000, elapsed.Round(time.Millisecond))
		}
	}

	// Consume the closing ']'.
	if _, err := dec.Token(); err != nil && err != io.EOF {
		return fmt.Errorf("read closing token: %w", err)
	}

	fmt.Fprintf(progress, "\r") // clear progress line
	fmt.Fprintf(progress, "  Done: scanned %d commands in %s\n", totalEntries, time.Since(start).Round(time.Millisecond))

	return nil
}
