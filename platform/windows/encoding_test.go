package windows

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// encodeUTF16LE converts a Go string to UTF-16LE bytes (no BOM).
func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// prependBOM prepends the UTF-16LE BOM (0xFF 0xFE) to b.
func prependBOM(b []byte) []byte {
	return append([]byte{0xff, 0xfe}, b...)
}

func TestCleanWSLOutput_UTF8Passthrough(t *testing.T) {
	input := "WSL version: 2.5.10.0\nKernel version: 5.15.153.1-2\n"
	got := cleanWSLOutput([]byte(input))
	if got != input {
		t.Errorf("expected pass-through, got %q", got)
	}
}

func TestCleanWSLOutput_Empty(t *testing.T) {
	got := cleanWSLOutput(nil)
	if got != "" {
		t.Errorf("expected empty string for nil, got %q", got)
	}
	got = cleanWSLOutput([]byte{})
	if got != "" {
		t.Errorf("expected empty string for empty slice, got %q", got)
	}
}

func TestCleanWSLOutput_UTF16LEWithBOM(t *testing.T) {
	original := "WSL version: 2.5.10.0\r\n"
	encoded := prependBOM(encodeUTF16LE(original))

	got := cleanWSLOutput(encoded)
	if got != original {
		t.Errorf("UTF-16LE with BOM: expected %q, got %q", original, got)
	}
}

func TestCleanWSLOutput_UTF16LEWithoutBOM(t *testing.T) {
	original := "Default Version: 2\r\n"
	encoded := encodeUTF16LE(original)

	got := cleanWSLOutput(encoded)
	if got != original {
		t.Errorf("UTF-16LE without BOM: expected %q, got %q", original, got)
	}
}

func TestCleanWSLOutput_UTF16LEMultiline(t *testing.T) {
	original := "WSL version: 2.5.10.0\r\nKernel version: 5.15.153.1-2\r\nWSLg version: 1.0.65\r\n"
	encoded := prependBOM(encodeUTF16LE(original))

	got := cleanWSLOutput(encoded)
	if got != original {
		t.Errorf("UTF-16LE multiline: expected %q, got %q", original, got)
	}
}

func TestCleanWSLOutput_UTF16LEDistroList(t *testing.T) {
	// Simulates "wsl.exe -l -q" output with UTF-16LE encoding.
	original := "Ubuntu\r\nAlpine\r\nagentbox-sb\r\n"
	encoded := prependBOM(encodeUTF16LE(original))

	got := cleanWSLOutput(encoded)
	if got != original {
		t.Errorf("UTF-16LE distro list: expected %q, got %q", original, got)
	}
}

func TestCleanWSLOutput_UTF16LEOddLength(t *testing.T) {
	// Simulate a truncated/corrupted trailing byte.
	original := "hello"
	encoded := encodeUTF16LE(original)
	encoded = append(encoded, 0x42) // extra trailing byte

	got := cleanWSLOutput(encoded)
	if got != original {
		t.Errorf("UTF-16LE with odd trailing byte: expected %q, got %q", original, got)
	}
}

func TestCleanWSLOutput_UTF16LEListVerbose(t *testing.T) {
	// Simulates "wsl.exe -l -v" output.
	original := "  NAME            STATE           VERSION\r\n" +
		"* Ubuntu          Running         2\r\n" +
		"  Alpine          Stopped         1\r\n"
	encoded := prependBOM(encodeUTF16LE(original))

	got := cleanWSLOutput(encoded)
	if got != original {
		t.Errorf("UTF-16LE list verbose: expected %q, got %q", original, got)
	}
}

func TestCleanWSLOutput_BOMOnlyUTF8(t *testing.T) {
	// A UTF-8 BOM (0xEF 0xBB 0xBF) should be treated as plain UTF-8
	// because it contains no null bytes.
	input := "\xef\xbb\xbfWSL version: 2.5.10.0\n"
	got := cleanWSLOutput([]byte(input))
	if got != input {
		t.Errorf("UTF-8 BOM: expected pass-through, got %q", got)
	}
}
