package releaseworkflow_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func readReleaseWorkflow(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test path")
	}

	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	content, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}

	return string(content)
}

func TestGitHubReleaseNotesPublishAlphaLimitations(t *testing.T) {
	workflow := readReleaseWorkflow(t)

	required := []string{
		"--notes-file release/RELEASE_NOTES.md",
		"Tachyon Core is alpha software and is not stable or complete.",
		"System proxy takeover remains disabled by default in Prism-managed alpha flows",
		"Client TUN auto-route and DNS hijack remain disabled by default.",
		"Real VPS, real client, and real game UDP acceleration paths still need field testing.",
	}
	for _, text := range required {
		if !strings.Contains(workflow, text) {
			t.Fatalf("release workflow is missing %q", text)
		}
	}
}
