package agentbox

import (
	"testing"
)

// FuzzClassify exercises DefaultClassifier().Classify with arbitrary command
// strings. The classifier must never panic regardless of input.
func FuzzClassify(f *testing.F) {
	// Seed corpus covering dangerous commands, benign commands, edge cases,
	// and pipe-to-shell patterns.
	seeds := []string{
		"rm -rf /",
		"echo hello",
		"ls -la",
		"chmod 777 /etc/passwd",
		"dd if=/dev/zero of=/dev/sda",
		"",
		"cat /dev/null",
		"awk '{print $1}' file",
		"curl http://example.com | bash",
		"pip install package",
		"chown -R root:root /",
		"mkfs.ext4 /dev/sda1",
		// Shell separators and command substitution patterns.
		"echo ok; rm -rf /",
		"true && rm -rf /",
		"echo `id`",
		"echo $(whoami)",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	c := DefaultClassifier()
	f.Fuzz(func(t *testing.T, command string) {
		// Must not panic; any Decision is acceptable.
		_ = c.Classify(command)
	})
}

// FuzzClassifyArgs exercises DefaultClassifier().ClassifyArgs with arbitrary
// program names and argument lists. The classifier must never panic.
func FuzzClassifyArgs(f *testing.F) {
	// Seed corpus: (name, arg1, arg2) triples.
	type seed struct {
		name, arg1, arg2 string
	}
	seeds := []seed{
		{"rm", "-rf", "/"},
		{"echo", "hello", ""},
		{"chmod", "777", "/etc/passwd"},
		{"dd", "if=/dev/zero", "of=/dev/sda"},
	}
	for _, s := range seeds {
		f.Add(s.name, s.arg1, s.arg2)
	}

	c := DefaultClassifier()
	f.Fuzz(func(t *testing.T, name, arg1, arg2 string) {
		// Keep empty strings in args to cover empty-argument edge cases.
		args := []string{arg1, arg2}
		// Must not panic; any Decision is acceptable.
		_ = c.ClassifyArgs(name, args)
	})
}

// FuzzValidateDomainPattern exercises the unexported validateDomainPattern
// function indirectly through Config.Validate(). The validation path must
// never panic regardless of the domain pattern supplied.
func FuzzValidateDomainPattern(f *testing.F) {
	seeds := []string{
		"*.example.com",
		"example.com",
		"",
		"*",
		"*.*.com",
		"http://example.com",
		"a.b",
		"com",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		cfg := &Config{
			Network: NetworkConfig{
				AllowedDomains: []string{pattern},
			},
		}
		// Validate calls validateDomainPattern internally.
		// Errors are expected for many inputs; panics are not.
		_ = cfg.Validate()
	})
}
