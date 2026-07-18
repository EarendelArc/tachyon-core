package releaseworkflow_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, path ...string) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test path")
	}

	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	content, err := os.ReadFile(filepath.Join(append([]string{root}, path...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(path...), err)
	}

	return string(content)
}

func readReleaseWorkflow(t *testing.T) string {
	t.Helper()
	return readRepoFile(t, ".github", "workflows", "release.yml")
}

func TestGitHubReleaseNotesPublishAlphaLimitations(t *testing.T) {
	workflow := readReleaseWorkflow(t)

	required := []string{
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

	publication := readRepoFile(t, ".github", "scripts", "publish-release.sh")
	if !strings.Contains(publication, `--notes-file "${release_dir}/RELEASE_NOTES.md"`) {
		t.Fatal("release publication script does not use generated release notes")
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
		"needs: [verify_tag, test, test-windows]",
	}
	for _, text := range required {
		if !strings.Contains(workflow, text) {
			t.Fatalf("release workflow is missing Windows route security gate %q", text)
		}
	}
}

func TestReleasePinsTagBuildAndAssetsToVerifiedCommit(t *testing.T) {
	workflow := readReleaseWorkflow(t)
	required := []string{
		"verify_tag:",
		"concurrency:",
		"cancel-in-progress: false",
		"EXPECTED_COMMIT: ${{ needs.verify_tag.outputs.commit }}",
		"EXPECTED_TAG_OBJECT: ${{ needs.verify_tag.outputs.tag_object }}",
		`source_date_epoch=$(git show -s --format=%ct "${VERIFIED_COMMIT}")`,
		"bash .github/scripts/publish-release.sh",
	}
	for _, text := range required {
		if !strings.Contains(workflow, text) {
			t.Fatalf("release workflow is missing tag/commit gate %q", text)
		}
	}

	const pinnedCheckout = "ref: ${{ needs.verify_tag.outputs.commit }}"
	if count := strings.Count(workflow, pinnedCheckout); count < 4 {
		t.Fatalf("release workflow has %d commit-pinned checkouts, want at least 4", count)
	}

	const tagGate = `bash .github/scripts/verify-release-tag.sh`
	if count := strings.Count(workflow, tagGate); count < 2 {
		t.Fatalf("release workflow runs the tag gate %d times, want initial and pre-publish checks", count)
	}

	for _, forbidden := range []string{"date -u +%Y-%m-%dT%H:%M:%SZ"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("release workflow contains forbidden publication behavior %q", forbidden)
		}
	}

	publication := readRepoFile(t, ".github", "scripts", "publish-release.sh")
	for _, text := range []string{`--target "${commit}"`, "--verify-tag", "--draft", "gh release upload", "-F draft=false"} {
		if !strings.Contains(publication, text) {
			t.Fatalf("release publication script is missing %q", text)
		}
	}
	for _, forbidden := range []string{"gh release edit", "--clobber"} {
		if strings.Contains(publication, forbidden) {
			t.Fatalf("release publication script contains forbidden behavior %q", forbidden)
		}
	}
}
