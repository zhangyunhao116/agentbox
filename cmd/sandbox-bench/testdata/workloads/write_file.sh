#!/bin/sh
# write_file.sh - Test file I/O sandbox overhead
# Creates a temp file, writes 1KB, reads it back, and cleans up.

f=$(mktemp)
dd if=/dev/zero of="$f" bs=1024 count=1 2>/dev/null
cat "$f" > /dev/null
rm -f "$f"
