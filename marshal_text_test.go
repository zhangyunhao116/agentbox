package agentbox

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestDecisionMarshalText(t *testing.T) {
	tests := []struct {
		d    Decision
		want string
	}{
		{Sandboxed, "sandboxed"},
		{Allow, "allow"},
		{Escalated, "escalated"},
		{Forbidden, "forbidden"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got, err := tt.d.MarshalText()
			if err != nil {
				t.Fatalf("Decision(%d).MarshalText() error = %v", tt.d, err)
			}
			if string(got) != tt.want {
				t.Errorf("Decision(%d).MarshalText() = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestDecisionUnmarshalText(t *testing.T) {
	tests := []struct {
		text string
		want Decision
	}{
		{"sandboxed", Sandboxed},
		{"allow", Allow},
		{"escalated", Escalated},
		{"forbidden", Forbidden},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			var d Decision
			if err := d.UnmarshalText([]byte(tt.text)); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v", tt.text, err)
			}
			if d != tt.want {
				t.Errorf("UnmarshalText(%q) = %d, want %d", tt.text, d, tt.want)
			}
		})
	}

	// Round-trip: marshal then unmarshal should return original value.
	for _, orig := range []Decision{Sandboxed, Allow, Escalated, Forbidden} {
		t.Run("roundtrip_"+orig.String(), func(t *testing.T) {
			text, err := orig.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			var got Decision
			if err := got.UnmarshalText(text); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v", text, err)
			}
			if got != orig {
				t.Errorf("round-trip: got %d, want %d", got, orig)
			}
		})
	}

	// Unknown value should return error.
	t.Run("unknown", func(t *testing.T) {
		var d Decision
		err := d.UnmarshalText([]byte("bogus"))
		if err == nil {
			t.Error("UnmarshalText(\"bogus\") expected error, got nil")
		}
	})
}

func TestDecisionJSONRoundTrip(t *testing.T) {
	type sample struct {
		D Decision `json:"d"`
	}

	for _, dec := range []Decision{Sandboxed, Allow, Escalated, Forbidden} {
		t.Run(dec.String(), func(t *testing.T) {
			s := sample{D: dec}
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			// Verify JSON contains the string form, not the integer.
			want := `"d":"` + dec.String() + `"`
			if got := string(data); !strings.Contains(got, want) {
				t.Errorf("json.Marshal() = %s; want it to contain %s", got, want)
			}

			var s2 sample
			if err := json.Unmarshal(data, &s2); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if s2.D != dec {
				t.Errorf("json round-trip: got %d (%s), want %d (%s)", s2.D, s2.D, dec, dec)
			}
		})
	}
}

func TestApprovalDecisionMarshalText(t *testing.T) {
	tests := []struct {
		d    ApprovalDecision
		want string
	}{
		{Approve, "approve"},
		{Deny, "deny"},
		{ApproveSession, "approve_session"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got, err := tt.d.MarshalText()
			if err != nil {
				t.Fatalf("ApprovalDecision(%d).MarshalText() error = %v", tt.d, err)
			}
			if string(got) != tt.want {
				t.Errorf("ApprovalDecision(%d).MarshalText() = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestApprovalDecisionUnmarshalText(t *testing.T) {
	tests := []struct {
		text string
		want ApprovalDecision
	}{
		{"approve", Approve},
		{"deny", Deny},
		{"approve_session", ApproveSession},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			var d ApprovalDecision
			if err := d.UnmarshalText([]byte(tt.text)); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v", tt.text, err)
			}
			if d != tt.want {
				t.Errorf("UnmarshalText(%q) = %d, want %d", tt.text, d, tt.want)
			}
		})
	}

	// Round-trip
	for _, orig := range []ApprovalDecision{Approve, Deny, ApproveSession} {
		t.Run("roundtrip_"+orig.String(), func(t *testing.T) {
			text, err := orig.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			var got ApprovalDecision
			if err := got.UnmarshalText(text); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v", text, err)
			}
			if got != orig {
				t.Errorf("round-trip: got %d, want %d", got, orig)
			}
		})
	}

	// Unknown value should return error.
	t.Run("unknown", func(t *testing.T) {
		var d ApprovalDecision
		err := d.UnmarshalText([]byte("bogus"))
		if err == nil {
			t.Error("UnmarshalText(\"bogus\") expected error, got nil")
		}
	})
}

func TestApprovalDecisionJSONRoundTrip(t *testing.T) {
	type sample struct {
		D ApprovalDecision `json:"d"`
	}

	for _, dec := range []ApprovalDecision{Approve, Deny, ApproveSession} {
		t.Run(dec.String(), func(t *testing.T) {
			s := sample{D: dec}
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			// Verify JSON contains the string form, not the integer.
			want := `"d":"` + dec.String() + `"`
			if got := string(data); !strings.Contains(got, want) {
				t.Errorf("json.Marshal() = %s; want it to contain %s", got, want)
			}

			var s2 sample
			if err := json.Unmarshal(data, &s2); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if s2.D != dec {
				t.Errorf("json round-trip: got %d (%s), want %d (%s)", s2.D, s2.D, dec, dec)
			}
		})
	}
}

func TestFallbackPolicyMarshalText(t *testing.T) {
	tests := []struct {
		f    FallbackPolicy
		want string
	}{
		{FallbackStrict, "strict"},
		{FallbackWarn, "warn"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got, err := tt.f.MarshalText()
			if err != nil {
				t.Fatalf("FallbackPolicy(%d).MarshalText() error = %v", tt.f, err)
			}
			if string(got) != tt.want {
				t.Errorf("FallbackPolicy(%d).MarshalText() = %q, want %q", tt.f, got, tt.want)
			}
		})
	}
}

func TestFallbackPolicyUnmarshalText(t *testing.T) {
	tests := []struct {
		text string
		want FallbackPolicy
	}{
		{"strict", FallbackStrict},
		{"warn", FallbackWarn},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			var f FallbackPolicy
			if err := f.UnmarshalText([]byte(tt.text)); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v", tt.text, err)
			}
			if f != tt.want {
				t.Errorf("UnmarshalText(%q) = %d, want %d", tt.text, f, tt.want)
			}
		})
	}

	// Round-trip: marshal then unmarshal should return original value.
	for _, orig := range []FallbackPolicy{FallbackStrict, FallbackWarn} {
		t.Run("roundtrip_"+orig.String(), func(t *testing.T) {
			text, err := orig.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			var got FallbackPolicy
			if err := got.UnmarshalText(text); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v", text, err)
			}
			if got != orig {
				t.Errorf("round-trip: got %d, want %d", got, orig)
			}
		})
	}

	// Unknown value should return error.
	t.Run("unknown", func(t *testing.T) {
		var f FallbackPolicy
		err := f.UnmarshalText([]byte("bogus"))
		if err == nil {
			t.Error("UnmarshalText(\"bogus\") expected error, got nil")
		}
	})
}

func TestFallbackPolicyJSONRoundTrip(t *testing.T) {
	type sample struct {
		F FallbackPolicy `json:"f"`
	}

	for _, fp := range []FallbackPolicy{FallbackStrict, FallbackWarn} {
		t.Run(fp.String(), func(t *testing.T) {
			s := sample{F: fp}
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			// Verify JSON contains the string form, not the integer.
			want := `"f":"` + fp.String() + `"`
			if got := string(data); !strings.Contains(got, want) {
				t.Errorf("json.Marshal() = %s; want it to contain %s", got, want)
			}

			var s2 sample
			if err := json.Unmarshal(data, &s2); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if s2.F != fp {
				t.Errorf("json round-trip: got %d (%s), want %d (%s)", s2.F, s2.F, fp, fp)
			}
		})
	}
}

func TestNetworkModeMarshalText(t *testing.T) {
	tests := []struct {
		n    NetworkMode
		want string
	}{
		{NetworkFiltered, "filtered"},
		{NetworkBlocked, "blocked"},
		{NetworkAllowed, "allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got, err := tt.n.MarshalText()
			if err != nil {
				t.Fatalf("NetworkMode(%d).MarshalText() error = %v", tt.n, err)
			}
			if string(got) != tt.want {
				t.Errorf("NetworkMode(%d).MarshalText() = %q, want %q", tt.n, got, tt.want)
			}
		})
	}
}

func TestNetworkModeUnmarshalText(t *testing.T) {
	tests := []struct {
		text string
		want NetworkMode
	}{
		{"filtered", NetworkFiltered},
		{"blocked", NetworkBlocked},
		{"allowed", NetworkAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			var n NetworkMode
			if err := n.UnmarshalText([]byte(tt.text)); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v", tt.text, err)
			}
			if n != tt.want {
				t.Errorf("UnmarshalText(%q) = %d, want %d", tt.text, n, tt.want)
			}
		})
	}

	// Round-trip: marshal then unmarshal should return original value.
	for _, orig := range []NetworkMode{NetworkFiltered, NetworkBlocked, NetworkAllowed} {
		t.Run("roundtrip_"+orig.String(), func(t *testing.T) {
			text, err := orig.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			var got NetworkMode
			if err := got.UnmarshalText(text); err != nil {
				t.Fatalf("UnmarshalText(%q) error = %v", text, err)
			}
			if got != orig {
				t.Errorf("round-trip: got %d, want %d", got, orig)
			}
		})
	}

	// Unknown value should return error.
	t.Run("unknown", func(t *testing.T) {
		var n NetworkMode
		err := n.UnmarshalText([]byte("bogus"))
		if err == nil {
			t.Error("UnmarshalText(\"bogus\") expected error, got nil")
		}
	})
}

func TestNetworkModeJSONRoundTrip(t *testing.T) {
	type sample struct {
		N NetworkMode `json:"n"`
	}

	for _, nm := range []NetworkMode{NetworkFiltered, NetworkBlocked, NetworkAllowed} {
		t.Run(nm.String(), func(t *testing.T) {
			s := sample{N: nm}
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			// Verify JSON contains the string form, not the integer.
			want := `"n":"` + nm.String() + `"`
			if got := string(data); !strings.Contains(got, want) {
				t.Errorf("json.Marshal() = %s; want it to contain %s", got, want)
			}

			var s2 sample
			if err := json.Unmarshal(data, &s2); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if s2.N != nm {
				t.Errorf("json round-trip: got %d (%s), want %d (%s)", s2.N, s2.N, nm, nm)
			}
		})
	}
}

func TestExecArgsEmptyName(t *testing.T) {
	mgr := NewNopManager()
	_, err := mgr.ExecArgs(context.Background(), "", nil)
	if err == nil {
		t.Fatal("ExecArgs(\"\") should have returned an error")
	}
	if !errors.Is(err, ErrEmptyArgs) {
		t.Errorf("ExecArgs(\"\") error = %v, want ErrEmptyArgs", err)
	}
}

func TestWrapEmptyArgs(t *testing.T) {
	mgr := NewNopManager()
	cmd := &exec.Cmd{} // empty Args
	err := mgr.Wrap(context.Background(), cmd)
	if err == nil {
		t.Fatal("Wrap() with empty args should have returned an error")
	}
	if !errors.Is(err, ErrEmptyArgs) {
		t.Errorf("Wrap() with empty args: error = %v, want ErrEmptyArgs", err)
	}
	// Verify it is NOT ErrNilCommand.
	if errors.Is(err, ErrNilCommand) {
		t.Error("Wrap() with empty args should not return ErrNilCommand")
	}
}

func TestErrEmptyArgsDistinct(t *testing.T) {
	// ErrEmptyArgs and ErrNilCommand must be distinct sentinel errors.
	if errors.Is(ErrEmptyArgs, ErrNilCommand) {
		t.Error("ErrEmptyArgs should not match ErrNilCommand via errors.Is")
	}
	if errors.Is(ErrNilCommand, ErrEmptyArgs) {
		t.Error("ErrNilCommand should not match ErrEmptyArgs via errors.Is")
	}
	if ErrEmptyArgs.Error() == ErrNilCommand.Error() {
		t.Error("ErrEmptyArgs and ErrNilCommand should have different messages")
	}
}

