package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/pkg/logger"
)

func TestExecutorSparseConfigDoesNotDeadlock(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{}, logger.New("error"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := exec.Run(ctx, "sh", "-c", "printf ready")
	if err != nil {
		t.Fatalf("sparse-config executor failed: %v", err)
	}
	if result.Stdout != "ready" {
		t.Fatalf("stdout = %q, want ready", result.Stdout)
	}
}

func TestExecutorRejectsUntrustedExecutableNames(t *testing.T) {
	exec := NewExecutor(&config.Config{ToolsDir: t.TempDir()}, logger.New("error"))
	for _, name := range []string{"", ".", "..", "../sh", "/bin/sh", `..\sh`, "sh;touch", "sh name", "🔥"} {
		t.Run(name, func(t *testing.T) {
			if exec.IsToolAvailable(name) {
				t.Fatalf("unsafe tool %q reported available", name)
			}
			if _, err := exec.Run(context.Background(), name); err == nil {
				t.Fatalf("Run accepted unsafe tool %q", name)
			}
			if err := exec.RunWithCallback(context.Background(), "task", nil, name); err == nil {
				t.Fatalf("RunWithCallback accepted unsafe tool %q", name)
			}
			if _, err := exec.RunWithInput(context.Background(), strings.NewReader("input"), name); err == nil {
				t.Fatalf("RunWithInput accepted unsafe tool %q", name)
			}
			if err := exec.RunWithInputCallback(context.Background(), strings.NewReader("input"), "task", nil, name); err == nil {
				t.Fatalf("RunWithInputCallback accepted unsafe tool %q", name)
			}
		})
	}
}

func TestToolFreeExecutorDisablesInputVariants(t *testing.T) {
	exec := NewToolFreeExecutor(&config.Config{ToolsDir: t.TempDir()}, logger.New("error"))
	if _, err := exec.RunWithInput(context.Background(), strings.NewReader("payload"), "sh"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("RunWithInput error = %v, want disabled", err)
	}
	if err := exec.RunWithInputCallback(context.Background(), strings.NewReader("payload"), "task", nil, "sh"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("RunWithInputCallback error = %v, want disabled", err)
	}
}

func TestRunWithCallbackSurfacesStderrOnFailure(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{}, logger.New("error"))
	// Mimic a tool that rejects a flag and exits non-zero (httpx exit status 2):
	// the returned error must carry the tool's own stderr message, not just the code.
	err := exec.RunWithCallback(context.Background(), "task", nil, "sh",
		"-c", "echo 'flag provided but not defined: -bogus' 1>&2; exit 2")
	if err == nil {
		t.Fatal("expected a non-zero-exit error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("error must include the stderr reason, got: %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 2") {
		t.Fatalf("error must still include the exit code, got: %v", err)
	}
}

func TestRunWithCallbackNoErrorOnCleanExit(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{}, logger.New("error"))
	var lines []string
	err := exec.RunWithCallback(context.Background(), "task", func(l string) { lines = append(lines, l) },
		"sh", "-c", "echo one; echo two; echo noise 1>&2")
	if err != nil {
		t.Fatalf("clean exit must not error even with stderr output, got: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 stdout lines, got %v", lines)
	}
}

func TestStderrTailBounded(t *testing.T) {
	var tail stderrTail
	for i := 0; i < 20; i++ {
		tail.add(strings.Repeat("x", 100))
	}
	tail.add("") // blank lines ignored
	got := tail.string()
	if got == "" {
		t.Fatal("tail should retain recent lines")
	}
	if len(got) > 400+len("…") { // maxLen 400 + the 3-byte ellipsis rune
		t.Fatalf("tail must be length-bounded, got %d", len(got))
	}
}

func TestToolNameValidatorAllowsCuratedBareNames(t *testing.T) {
	for _, name := range []string{"httpx", "python3", "nuclei-templates", "tool_v2.1", "c++"} {
		if err := validateToolName(name); err != nil {
			t.Fatalf("validateToolName(%q): %v", name, err)
		}
	}
}
