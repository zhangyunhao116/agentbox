#!/bin/sh
# cpu_work.sh - Test CPU-bound workload
# Calculates md5 of random data (100KB).

dd if=/dev/urandom bs=1024 count=100 2>/dev/null | md5sum > /dev/null 2>&1 || md5 > /dev/null 2>&1
