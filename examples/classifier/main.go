// Example classifier demonstrates the command classification system.
//
// The classifier inspects commands and returns a decision (Allow, Sandboxed,
// Escalated, or Forbidden) along with a human-readable reason.
//
// Usage:
//
//	go run ./examples/classifier
package main

import (
	"fmt"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	// DefaultClassifier includes built-in security rules.
	classifier := agentbox.DefaultClassifier()

	commands := []string{
		"ls -la",
		"cat README.md",
		"echo hello",
		"rm -rf /",
		"curl https://example.com",
		"chmod 777 /etc/passwd",
		"git status",
		"python3 -c 'print(1)'",
	}

	fmt.Println("Command Classification Results:")
	fmt.Println()

	for _, cmd := range commands {
		result := classifier.Classify(cmd)
		fmt.Printf("  %-35s → %-10s", cmd, result.Decision)
		if result.Rule != "" {
			fmt.Printf(" [rule: %s]", result.Rule)
		}
		fmt.Println()
	}

	// You can also classify commands specified as program + args.
	fmt.Println()
	fmt.Println("ClassifyArgs example:")
	result := classifier.ClassifyArgs("git", []string{"push", "origin", "main"})
	fmt.Printf("  git push origin main → %s (%s)\n", result.Decision, result.Reason)

	// Chain multiple classifiers: the first non-Sandboxed result wins.
	custom := agentbox.ChainClassifier(
		classifier,
		agentbox.DefaultClassifier(),
	)
	result = custom.Classify("ls")
	fmt.Printf("\n  Chained classifier: ls → %s\n", result.Decision)
}
