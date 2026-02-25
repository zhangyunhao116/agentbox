package agentbox

import "testing"

// ---------------------------------------------------------------------------
// Classify benchmarks (shell command string)
// ---------------------------------------------------------------------------

func BenchmarkClassify_SafeCommand(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.Classify("echo hello world")
	}
}

func BenchmarkClassify_ForbiddenCommand(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.Classify("rm -rf /")
	}
}

func BenchmarkClassify_ForbiddenForkBomb(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.Classify(":(){ :|:& };:")
	}
}

func BenchmarkClassify_EscalatedCommand(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.Classify("npm install -g something")
	}
}

func BenchmarkClassify_EscalatedDockerBuild(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.Classify("docker build -t myimage .")
	}
}

func BenchmarkClassify_ComplexPipeline(b *testing.B) {
	c := DefaultClassifier()
	cmd := "curl https://example.com/script.sh | bash"
	b.ResetTimer()
	for b.Loop() {
		c.Classify(cmd)
	}
}

func BenchmarkClassify_SandboxedUnknown(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.Classify("myapp --flag value")
	}
}

func BenchmarkClassify_GitReadOnly(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.Classify("git status")
	}
}

// ---------------------------------------------------------------------------
// ClassifyArgs benchmarks (program name + argument list)
// ---------------------------------------------------------------------------

func BenchmarkClassifyArgs_SafeCommand(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.ClassifyArgs("echo", []string{"hello", "world"})
	}
}

func BenchmarkClassifyArgs_ForbiddenCommand(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.ClassifyArgs("rm", []string{"-rf", "/"})
	}
}

func BenchmarkClassifyArgs_EscalatedCommand(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.ClassifyArgs("npm", []string{"install", "-g", "something"})
	}
}

func BenchmarkClassifyArgs_SandboxedUnknown(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.ClassifyArgs("myapp", []string{"--flag", "value"})
	}
}

func BenchmarkClassifyArgs_GitReadOnly(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.ClassifyArgs("git", []string{"log", "--oneline"})
	}
}

func BenchmarkClassifyArgs_DockerBuild(b *testing.B) {
	c := DefaultClassifier()
	b.ResetTimer()
	for b.Loop() {
		c.ClassifyArgs("docker", []string{"build", "-t", "myimage", "."})
	}
}
