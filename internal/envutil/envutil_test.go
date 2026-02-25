package envutil

import (
	"testing"
)

func TestSetEnv(t *testing.T) {
	tests := []struct {
		name  string
		env   []string
		key   string
		value string
		want  []string
	}{
		{
			name:  "set new variable",
			env:   []string{"A=1"},
			key:   "B",
			value: "2",
			want:  []string{"A=1", "B=2"},
		},
		{
			name:  "replace existing variable",
			env:   []string{"A=1", "B=2"},
			key:   "A",
			value: "99",
			want:  []string{"A=99", "B=2"},
		},
		{
			name:  "set on nil slice",
			env:   nil,
			key:   "X",
			value: "y",
			want:  []string{"X=y"},
		},
		{
			name:  "set on empty slice",
			env:   []string{},
			key:   "X",
			value: "y",
			want:  []string{"X=y"},
		},
		{
			name:  "empty value",
			env:   []string{"A=1"},
			key:   "B",
			value: "",
			want:  []string{"A=1", "B="},
		},
		{
			name:  "value with equals sign",
			env:   []string{},
			key:   "URL",
			value: "http://host?a=1&b=2",
			want:  []string{"URL=http://host?a=1&b=2"},
		},
		{
			name:  "replace preserves position",
			env:   []string{"A=1", "B=2", "C=3"},
			key:   "B",
			value: "new",
			want:  []string{"A=1", "B=new", "C=3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SetEnv(tt.env, tt.key, tt.value)
			assertSliceEqual(t, got, tt.want)
		})
	}
}

func TestGetEnv(t *testing.T) {
	env := []string{"PATH=/usr/bin", "HOME=/home/user", "EMPTY=", "URL=http://x?a=1"}

	tests := []struct {
		name      string
		key       string
		wantValue string
		wantOK    bool
	}{
		{name: "existing key", key: "PATH", wantValue: "/usr/bin", wantOK: true},
		{name: "another key", key: "HOME", wantValue: "/home/user", wantOK: true},
		{name: "empty value", key: "EMPTY", wantValue: "", wantOK: true},
		{name: "value with equals", key: "URL", wantValue: "http://x?a=1", wantOK: true},
		{name: "missing key", key: "MISSING", wantValue: "", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := GetEnv(env, tt.key)
			if ok != tt.wantOK {
				t.Errorf("GetEnv(env, %q) ok = %v, want %v", tt.key, ok, tt.wantOK)
			}
			if val != tt.wantValue {
				t.Errorf("GetEnv(env, %q) = %q, want %q", tt.key, val, tt.wantValue)
			}
		})
	}

	t.Run("nil env", func(t *testing.T) {
		val, ok := GetEnv(nil, "KEY")
		if ok || val != "" {
			t.Errorf("GetEnv(nil, KEY) = (%q, %v), want (\"\", false)", val, ok)
		}
	})
}

func TestRemoveEnv(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		key  string
		want []string
	}{
		{
			name: "remove existing",
			env:  []string{"A=1", "B=2", "C=3"},
			key:  "B",
			want: []string{"A=1", "C=3"},
		},
		{
			name: "remove first",
			env:  []string{"A=1", "B=2"},
			key:  "A",
			want: []string{"B=2"},
		},
		{
			name: "remove last",
			env:  []string{"A=1", "B=2"},
			key:  "B",
			want: []string{"A=1"},
		},
		{
			name: "remove nonexistent",
			env:  []string{"A=1", "B=2"},
			key:  "C",
			want: []string{"A=1", "B=2"},
		},
		{
			name: "remove from nil",
			env:  nil,
			key:  "A",
			want: []string{},
		},
		{
			name: "remove from empty",
			env:  []string{},
			key:  "A",
			want: []string{},
		},
		{
			name: "no partial key match",
			env:  []string{"PATH=/usr/bin", "PATHEXT=.exe"},
			key:  "PATH",
			want: []string{"PATHEXT=.exe"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RemoveEnv(tt.env, tt.key)
			assertSliceEqual(t, got, tt.want)
		})
	}
}

func TestRemoveEnvPrefix(t *testing.T) {
	tests := []struct {
		name   string
		env    []string
		prefix string
		want   []string
	}{
		{
			name:   "remove DYLD_ prefix",
			env:    []string{"DYLD_LIBRARY_PATH=/lib", "DYLD_INSERT_LIBRARIES=foo", "PATH=/usr/bin"},
			prefix: "DYLD_",
			want:   []string{"PATH=/usr/bin"},
		},
		{
			name:   "no match",
			env:    []string{"A=1", "B=2"},
			prefix: "X_",
			want:   []string{"A=1", "B=2"},
		},
		{
			name:   "remove all",
			env:    []string{"X_A=1", "X_B=2"},
			prefix: "X_",
			want:   []string{},
		},
		{
			name:   "nil env",
			env:    nil,
			prefix: "X_",
			want:   []string{},
		},
		{
			name:   "empty prefix matches all",
			env:    []string{"A=1", "B=2"},
			prefix: "",
			want:   []string{},
		},
		{
			name:   "prefix matches key not value",
			env:    []string{"SAFE=DYLD_something"},
			prefix: "DYLD_",
			want:   []string{"SAFE=DYLD_something"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RemoveEnvPrefix(tt.env, tt.prefix)
			assertSliceEqual(t, got, tt.want)
		})
	}
}

func TestMergeEnv(t *testing.T) {
	tests := []struct {
		name       string
		base       []string
		additional []string
		want       []string
	}{
		{
			name:       "override existing",
			base:       []string{"A=1", "B=2"},
			additional: []string{"A=99"},
			want:       []string{"A=99", "B=2"},
		},
		{
			name:       "add new",
			base:       []string{"A=1"},
			additional: []string{"B=2"},
			want:       []string{"A=1", "B=2"},
		},
		{
			name:       "mixed override and add",
			base:       []string{"A=1", "B=2"},
			additional: []string{"B=99", "C=3"},
			want:       []string{"A=1", "B=99", "C=3"},
		},
		{
			name:       "empty base",
			base:       nil,
			additional: []string{"A=1"},
			want:       []string{"A=1"},
		},
		{
			name:       "empty additional",
			base:       []string{"A=1"},
			additional: nil,
			want:       []string{"A=1"},
		},
		{
			name:       "both empty",
			base:       nil,
			additional: nil,
			want:       []string{},
		},
		{
			name:       "preserves base order",
			base:       []string{"C=3", "A=1", "B=2"},
			additional: []string{"A=99"},
			want:       []string{"C=3", "A=99", "B=2"},
		},
		{
			name:       "duplicate in additional uses last",
			base:       []string{"A=1"},
			additional: []string{"B=first", "B=second"},
			want:       []string{"A=1", "B=second"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeEnv(tt.base, tt.additional)
			assertSliceEqual(t, got, tt.want)
		})
	}
}

// assertSliceEqual is a test helper that compares two string slices.
func assertSliceEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %v (len %d), want %v (len %d)", got, len(got), want, len(want))
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q\nfull got:  %v\nfull want: %v", i, got[i], want[i], got, want)
			return
		}
	}
}
