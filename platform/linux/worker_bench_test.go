//go:build linux

package linux

import (
	"net"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

// BenchmarkWorkerProtocolEncode measures the performance of encoding a
// typical workerRequest.
func BenchmarkWorkerProtocolEncode(b *testing.B) {
	req := &workerRequest{
		ID:   "bench-request",
		Cmd:  "/usr/bin/python3",
		Args: []string{"-c", "print('hello world')"},
		Dir:  "/tmp",
		Env:  []string{"PATH=/usr/bin:/bin", "HOME=/home/user", "LANG=en_US.UTF-8"},
		WritableRoots: []string{"/tmp", "/var/tmp"},
		DenyWrite:     []string{"/etc", "/usr"},
		DenyRead:      []string{"/root"},
		NeedsNetworkRestriction: true,
		ResourceLimits: &platform.ResourceLimits{
			MaxProcesses:       100,
			MaxMemoryBytes:     1024 * 1024 * 1024,
			MaxFileDescriptors: 512,
			MaxCPUSeconds:      60,
		},
	}

	// Create a pipe that will be used for encoding.
	// We read from the server side in a goroutine to prevent blocking.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Read from server side in background to prevent write blocking.
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := encodeRequest(client, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWorkerProtocolDecode measures the performance of decoding a
// typical workerResponse.
func BenchmarkWorkerProtocolDecode(b *testing.B) {
	resp := &workerResponse{
		ID:       "bench-response",
		Stdout:   []byte("command output\nline 2\nline 3\n"),
		Stderr:   []byte(""),
		ExitCode: 0,
		Error:    "",
	}

	// Pre-encode the response once to measure only decode performance.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Set up a goroutine that will repeatedly encode responses.
	go func() {
		for {
			if err := encodeResponse(client, resp); err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decodeResponse(server)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWorkerProtocolRoundtrip measures the full encode+decode cycle
// performance for a typical request/response pair.
func BenchmarkWorkerProtocolRoundtrip(b *testing.B) {
	req := &workerRequest{
		ID:   "bench-roundtrip",
		Cmd:  "/usr/bin/python3",
		Args: []string{"-c", "print('hello')"},
		Dir:  "/tmp",
		Env:  []string{"PATH=/usr/bin:/bin"},
		WritableRoots: []string{"/tmp"},
		ResourceLimits: &platform.ResourceLimits{
			MaxProcesses: 100,
		},
	}

	resp := &workerResponse{
		ID:       "bench-roundtrip",
		Stdout:   []byte("hello\n"),
		Stderr:   []byte(""),
		ExitCode: 0,
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate a full roundtrip: encode request, decode it,
		// encode response, decode it.
		errCh := make(chan error, 2)

		// Server side: decode request, encode response.
		go func() {
			_, err := decodeRequest(server)
			if err != nil {
				errCh <- err
				return
			}
			err = encodeResponse(server, resp)
			errCh <- err
		}()

		// Client side: encode request, decode response.
		if err := encodeRequest(client, req); err != nil {
			b.Fatal(err)
		}
		if _, err := decodeResponse(client); err != nil {
			b.Fatal(err)
		}

		// Wait for server goroutine.
		if err := <-errCh; err != nil {
			b.Fatal(err)
		}
	}
}
