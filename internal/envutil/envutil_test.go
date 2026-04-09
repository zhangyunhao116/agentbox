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

func TestSanitizeEnv(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		want []string
	}{
		{
			name: "removes LD_PRELOAD",
			env:  []string{"PATH=/usr/bin", "LD_PRELOAD=/evil.so", "HOME=/home/user"},
			want: []string{"PATH=/usr/bin", "HOME=/home/user"},
		},
		{
			name: "removes LD_LIBRARY_PATH",
			env:  []string{"LD_LIBRARY_PATH=/lib", "HOME=/home"},
			want: []string{"HOME=/home"},
		},
		{
			name: "removes AWS_SECRET_ACCESS_KEY",
			env:  []string{"AWS_SECRET_ACCESS_KEY=secret", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes AWS_SESSION_TOKEN",
			env:  []string{"AWS_SESSION_TOKEN=tok", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes GITHUB_TOKEN",
			env:  []string{"GITHUB_TOKEN=ghp_abc", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes GH_TOKEN",
			env:  []string{"GH_TOKEN=ghp_abc", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes GITHUB_PAT",
			env:  []string{"GITHUB_PAT=ghp_abc", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes DOCKER_AUTH_CONFIG",
			env:  []string{"DOCKER_AUTH_CONFIG={}", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes NPM_TOKEN",
			env:  []string{"NPM_TOKEN=abc", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes _SECRET suffix",
			env:  []string{"MY_SECRET=foo", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes _PASSWORD suffix",
			env:  []string{"DB_PASSWORD=pass", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes _API_KEY suffix",
			env:  []string{"OPENAI_API_KEY=sk-abc", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes _PRIVATE_KEY suffix",
			env:  []string{"SSH_PRIVATE_KEY=-----BEGIN", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "removes _TOKEN suffix",
			env:  []string{"SLACK_TOKEN=xoxb-abc", "CUSTOM_TOKEN=xxx", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "suffix match is case-insensitive",
			env:  []string{"my_secret=foo", "db_password=bar", "PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		{
			name: "preserves _AGENTBOX_CONFIG",
			env:  []string{"_AGENTBOX_CONFIG=3", "LD_PRELOAD=/evil.so"},
			want: []string{"_AGENTBOX_CONFIG=3"},
		},
		{
			name: "preserves safe variables",
			env:  []string{"PATH=/bin", "HOME=/home", "TERM=xterm", "LANG=en_US.UTF-8"},
			want: []string{"PATH=/bin", "HOME=/home", "TERM=xterm", "LANG=en_US.UTF-8"},
		},
		{
			name: "removes multiple sensitive vars at once",
			env: []string{
				"PATH=/bin",
				"LD_PRELOAD=/evil.so",
				"GITHUB_TOKEN=tok",
				"MY_SECRET=s",
				"HOME=/home",
				"DB_PASSWORD=p",
			},
			want: []string{"PATH=/bin", "HOME=/home"},
		},
		{
			name: "nil input",
			env:  nil,
			want: []string{},
		},
		{
			name: "empty input",
			env:  []string{},
			want: []string{},
		},
		{
			name: "entry without equals sign",
			env:  []string{"NOEQUALS"},
			want: []string{"NOEQUALS"},
		},
		{
			name: "entry without equals sign but sensitive key",
			env:  []string{"LD_PRELOAD"},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeEnv(tt.env)
			assertSliceEqual(t, got, tt.want)
		})
	}
}

func TestSanitizeEnvWith(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		cfg  SanitizeConfig
		want []string
	}{
		{
			name: "custom exact keys only",
			env:  []string{"FOO=1", "BAR=2", "BAZ=3"},
			cfg: SanitizeConfig{
				ExactKeys: []string{"BAR"},
			},
			want: []string{"FOO=1", "BAZ=3"},
		},
		{
			name: "custom suffixes only",
			env:  []string{"PATH=/bin", "MY_CREDENTIAL=x", "HOME=/home"},
			cfg: SanitizeConfig{
				Suffixes: []string{"_CREDENTIAL"},
			},
			want: []string{"PATH=/bin", "HOME=/home"},
		},
		{
			name: "preserve overrides exact key",
			env:  []string{"LD_PRELOAD=/lib.so", "PATH=/bin"},
			cfg: SanitizeConfig{
				ExactKeys: []string{"LD_PRELOAD"},
				Preserve:  []string{"LD_PRELOAD"},
			},
			want: []string{"LD_PRELOAD=/lib.so", "PATH=/bin"},
		},
		{
			name: "preserve overrides suffix match",
			env:  []string{"MY_SECRET=s", "SAFE=ok"},
			cfg: SanitizeConfig{
				Suffixes: []string{"_SECRET"},
				Preserve: []string{"MY_SECRET"},
			},
			want: []string{"MY_SECRET=s", "SAFE=ok"},
		},
		{
			name: "agentbox config always preserved",
			env:  []string{"_AGENTBOX_CONFIG=cfg", "BAD=1"},
			cfg: SanitizeConfig{
				ExactKeys: []string{"_AGENTBOX_CONFIG", "BAD"},
			},
			want: []string{"_AGENTBOX_CONFIG=cfg"},
		},
		{
			name: "empty config removes nothing",
			env:  []string{"A=1", "B=2"},
			cfg:  SanitizeConfig{},
			want: []string{"A=1", "B=2"},
		},
		{
			name: "nil input",
			env:  nil,
			cfg:  SanitizeConfig{ExactKeys: []string{"X"}},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeEnvWith(tt.env, tt.cfg)
			assertSliceEqual(t, got, tt.want)
		})
	}
}

func TestDefaultSanitizeConfig(t *testing.T) {
	cfg := DefaultSanitizeConfig()

	// Must contain at least the well-known exact keys.
	exactSet := make(map[string]struct{}, len(cfg.ExactKeys))
	for _, k := range cfg.ExactKeys {
		exactSet[k] = struct{}{}
	}
	for _, want := range []string{"LD_PRELOAD", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"} {
		if _, ok := exactSet[want]; !ok {
			t.Errorf("DefaultSanitizeConfig().ExactKeys missing %q", want)
		}
	}

	// Must contain at least the known suffixes.
	if len(cfg.Suffixes) == 0 {
		t.Error("DefaultSanitizeConfig().Suffixes is empty")
	}

	// SanitizeEnv and SanitizeEnvWith with defaults should produce identical results.
	env := []string{"PATH=/bin", "LD_PRELOAD=/evil.so", "MY_SECRET=x", "HOME=/home"}
	got1 := SanitizeEnv(env)
	got2 := SanitizeEnvWith(env, cfg)
	assertSliceEqual(t, got1, got2)
}
