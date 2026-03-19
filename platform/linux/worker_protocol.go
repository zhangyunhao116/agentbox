//go:build linux

package linux

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/zhangyunhao116/agentbox/platform"
)

// workerRequest is sent from the Manager to the Worker via Unix socket.
// It contains all the information needed to execute a single command in the
// worker's sandbox environment.
type workerRequest struct {
	ID   string   `json:"id"`            // unique request ID
	Cmd  string   `json:"cmd"`           // command path (resolved)
	Args []string `json:"args"`          // command arguments
	Dir  string   `json:"dir,omitempty"` // working directory
	Env  []string `json:"env,omitempty"` // environment variables

	// Per-command sandbox config (subset of WrapConfig).
	WritableRoots           []string                 `json:"writable_roots,omitempty"`
	DenyWrite               []string                 `json:"deny_write,omitempty"`
	DenyRead                []string                 `json:"deny_read,omitempty"`
	NeedsNetworkRestriction bool                     `json:"needs_network_restriction,omitempty"`
	ResourceLimits          *platform.ResourceLimits `json:"resource_limits,omitempty"`
	MaxOutputBytes          int                      `json:"max_output_bytes,omitempty"` // max stdout/stderr size
}

// workerResponse is returned from the Worker to the Manager.
// It contains the execution result or any worker-level errors.
type workerResponse struct {
	ID       string `json:"id"`
	Stdout   []byte `json:"stdout"`          // raw stdout bytes
	Stderr   []byte `json:"stderr"`          // raw stderr bytes
	ExitCode int    `json:"exit_code"`       // command exit code
	Error    string `json:"error,omitempty"` // if worker-level error
}

// encodeRequest sends a workerRequest over the connection using length-prefix framing.
// Format: [4 bytes big-endian length][JSON payload]
func encodeRequest(conn net.Conn, req *workerRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	// Write 4-byte big-endian length prefix.
	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write JSON payload.
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	return nil
}

// decodeRequest reads a workerRequest from the connection using length-prefix framing.
// Format: [4 bytes big-endian length][JSON payload]
func decodeRequest(conn net.Conn) (*workerRequest, error) {
	// Read 4-byte big-endian length prefix.
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	// Sanity check: reject unreasonably large payloads (10MB limit).
	const maxPayloadSize = 10 * 1024 * 1024
	if length > maxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d bytes (max %d)", length, maxPayloadSize)
	}

	// Read JSON payload.
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	// Unmarshal the request.
	var req workerRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("unmarshal request: %w", err)
	}

	return &req, nil
}

// encodeResponse sends a workerResponse over the connection using length-prefix framing.
// Format: [4 bytes big-endian length][JSON payload]
func encodeResponse(conn net.Conn, resp *workerResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}

	// Write 4-byte big-endian length prefix.
	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write JSON payload.
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	return nil
}

// decodeResponse reads a workerResponse from the connection using length-prefix framing.
// Format: [4 bytes big-endian length][JSON payload]
func decodeResponse(conn net.Conn) (*workerResponse, error) {
	// Read 4-byte big-endian length prefix.
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	// Sanity check: reject unreasonably large payloads (10MB limit).
	const maxPayloadSize = 10 * 1024 * 1024
	if length > maxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d bytes (max %d)", length, maxPayloadSize)
	}

	// Read JSON payload.
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	// Unmarshal the response.
	var resp workerResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &resp, nil
}
