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
		"Client TUN auto-route and DNS hijack are unsupported and rejected by config validation.",
		"Real VPS, real client, and real game UDP acceleration paths still need field testing.",
	}
	for _, text := range required {
		if !strings.Contains(workflow, text) {
			t.Fatalf("release workflow is missing %q", text)
		}
	}
}

func TestGitHubCIDailyBuildCoversSupportedSixPlatformMatrix(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test path")
	}

	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	content, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read CI workflow: %v", err)
	}
	workflow := string(content)

	required := []string{
		"CGO_ENABLED: \"0\"",
		"bash scripts/verify-tgp-e2e.sh --self-test",
		"- goos: linux\n            goarch: amd64",
		"- goos: linux\n            goarch: arm64",
		"- goos: windows\n            goarch: amd64",
		"- goos: windows\n            goarch: arm64",
		"- goos: darwin\n            goarch: amd64",
		"- goos: darwin\n            goarch: arm64",
	}
	for _, text := range required {
		if !strings.Contains(workflow, text) {
			t.Fatalf("CI workflow is missing %q", text)
		}
	}
}

func TestReleaseBuildMatchesSupportedSixPlatformMatrix(t *testing.T) {
	workflow := readReleaseWorkflow(t)
	required := []string{
		"goos: linux\n            goarch: amd64",
		"goos: linux\n            goarch: arm64",
		"goos: windows\n            goarch: amd64",
		"goos: windows\n            goarch: arm64",
		"goos: darwin\n            goarch: amd64",
		"goos: darwin\n            goarch: arm64",
	}
	for _, text := range required {
		if !strings.Contains(workflow, text) {
			t.Fatalf("release workflow is missing %q", text)
		}
	}
	if strings.Contains(workflow, "goarch: \"386\"") {
		t.Fatal("release workflow must not publish legacy windows/386 assets")
	}

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	script, err := os.ReadFile(filepath.Join(root, "scripts", "build-release.ps1"))
	if err != nil {
		t.Fatalf("read local release script: %v", err)
	}
	if strings.Contains(string(script), `GOARCH = "386"`) {
		t.Fatal("local release script must not publish legacy windows/386 assets")
	}
}

func TestReleaseRequiresWindowsRouteSecurityIntegrations(t *testing.T) {
	workflow := readReleaseWorkflow(t)
	required := []string{
		"test-windows:",
		"Test full Windows suite",
		"-tags=routejournalintegration",
		"TestWindowsRouteJournalAbandonedPendingRealChildRecovery",
		"TACHYON_ALLOW_REAL_ROUTE_TEST: \"1\"",
		"needs: [test, test-windows]",
	}
	for _, text := range required {
		if !strings.Contains(workflow, text) {
			t.Fatalf("release workflow is missing Windows route security gate %q", text)
		}
	}
}
