package windows

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// cleanWSLOutput decodes WSL command output that may be UTF-16LE encoded.
// WSL commands (wsl.exe --version, wsl.exe --status, wsl.exe -l -v, etc.)
// emit UTF-16LE on many Windows configurations, with each ASCII character
// followed by a \x00 null byte. This function detects such output and
// decodes it to a UTF-8 string. Plain UTF-8 input is returned unchanged.
func cleanWSLOutput(b []byte) string {
	// Fast path: if no null bytes, it is already UTF-8.
	if !bytes.Contains(b, []byte{0}) {
		return string(b)
	}

	// Strip UTF-16LE BOM (0xFF 0xFE) if present.
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
	}

	// Decode UTF-16LE to UTF-8.
	if len(b)%2 != 0 {
		b = b[:len(b)-1] // trim trailing byte for alignment
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}
