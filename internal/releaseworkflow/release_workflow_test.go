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

func TestGitHubReleaseUsesDeterministicBilingualNotesContract(t *testing.T) {
	workflow := readReleaseWorkflow(t)
	preparation := readRepoFile(t, ".github", "scripts", "prepare-release.sh")
	publication := readRepoFile(t, ".github", "scripts", "publish-release.sh")
	templates := readRepoFile(t, ".github", "release-notes", "RELEASE_NOTES.md.tmpl") + "\n" +
		readRepoFile(t, ".github", "release-notes", "RELEASE_NOTES.zh-CN.md.tmpl")

	for _, text := range []string{
		`bash .github/scripts/prepare-release.sh "${version}" "${VERIFIED_COMMIT}" release`,
		"VERIFIED_COMMIT: ${{ needs.verify_tag.outputs.commit }}",
	} {
		if !strings.Contains(workflow, text) {
			t.Fatalf("release workflow is missing deterministic metadata contract %q", text)
		}
	}
	if strings.Contains(workflow, "generate-notes") {
		t.Fatal("release workflow must not depend on GitHub-generated release notes")
	}

	for _, text := range []string{
		"# Tachyon Core {{VERSION}}",
		"Version: `{{VERSION}}`",
		"Source commit: `{{COMMIT}}`",
		"## Compatibility",
		"## Installation",
		"## Verification",
		"## Alpha limitations",
		"Tachyon Core is alpha software and is not stable or complete.",
		"System proxy takeover remains disabled by default in Prism-managed alpha flows",
		"Client TUN auto-route and DNS hijack are unsupported and rejected by config validation.",
		"Real VPS, real client, and real game UDP acceleration paths still need field testing.",
		"RELEASE_NOTES.zh-CN.md",
		"版本：`{{VERSION}}`",
		"源代码提交：`{{COMMIT}}`",
		"## 兼容性",
		"## 安装",
		"## 校验",
		"## Alpha 限制",
	} {
		if !strings.Contains(templates, text) {
			t.Fatalf("shared release note templates are missing %q", text)
		}
	}
	for _, text := range []string{"RELEASE_NOTES.md.tmpl", "RELEASE_NOTES.zh-CN.md.tmpl", "{{VERSION}}", "{{COMMIT}}"} {
		if !strings.Contains(preparation, text) {
			t.Fatalf("release preparation script is missing shared-template behavior %q", text)
		}
	}

	for _, text := range []string{
		`"${release_dir}/RELEASE_NOTES.md"`,
		`"${release_dir}/RELEASE_NOTES.zh-CN.md"`,
		"sha256sum --check --strict SHA256SUMS.txt",
		`cat "${release_dir}/RELEASE_NOTES.md"`,
		`cat "${release_dir}/RELEASE_NOTES.zh-CN.md"`,
		`--notes-file "${body_file}"`,
	} {
		if !strings.Contains(publication, text) {
			t.Fatalf("release publication script is missing bilingual publication behavior %q", text)
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
	localBuild := string(script)
	if strings.Contains(localBuild, `GOARCH = "386"`) {
		t.Fatal("local release script must not publish legacy windows/386 assets")
	}
	for _, text := range []string{
		`show -s --format=%ct $sourceCommit`,
		`[DateTimeOffset]::FromUnixTimeSeconds($sourceDateEpoch)`,
		`$env:SOURCE_DATE_EPOCH = $sourceDateEpochText`,
		`[switch]$MetadataOnly`,
		`LastWriteTimeUtc = $commitTime`,
		`prepare-release.ps1`,
	} {
		if !strings.Contains(localBuild, text) {
			t.Fatalf("local release script is missing deterministic behavior %q", text)
		}
	}
	if strings.Contains(localBuild, "Get-Date") {
		t.Fatal("local release script must not use wall-clock build metadata")
	}

	windowsPreparation := readRepoFile(t, "scripts", "prepare-release.ps1")
	for _, text := range []string{
		"RELEASE_NOTES.md.tmpl",
		"RELEASE_NOTES.zh-CN.md.tmpl",
		`@("RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md") + $zipNames`,
		"[System.Text.ASCIIEncoding]::new()",
		"$checksumLines -join",
	} {
		if !strings.Contains(windowsPreparation, text) {
			t.Fatalf("Windows release preparation is missing contract %q", text)
		}
	}

	ci := readRepoFile(t, ".github", "workflows", "ci.yml")
	if !strings.Contains(ci, ".github/scripts/test-build-release-policy.ps1") {
		t.Fatal("CI does not run the Windows release golden policy test")
	}
}

func TestReleaseRequiresWindowsRouteSecurityIntegrations(t *testing.T) {
	workflows := []struct {
		name    string
		content string
	}{
		{name: "CI", content: readRepoFile(t, ".github", "workflows", "ci.yml")},
		{name: "Release", content: readReleaseWorkflow(t)},
	}

	const protectedJournalGate = `-run '^TestWindowsRouteJournal(RegistryIntegration|InitializesSecretFromProtectedEmptyHKLMKey|MachineMutexMultiProcess|MachineMutexTimeoutAndAbandonment)$'`
	const realRouteGate = `-run '^TestWindowsRouteJournal(AbandonedPendingRealChildRecovery|RecordFailureRealRouteRollback)$'`
	for _, workflow := range workflows {
		for _, gate := range []string{protectedJournalGate, realRouteGate} {
			if count := strings.Count(workflow.content, gate); count != 1 {
				t.Fatalf("%s workflow contains Windows route gate %q %d times, want exactly 1", workflow.name, gate, count)
			}
		}
		if count := strings.Count(workflow.content, "RecordFailureRealRouteRollback"); count != 1 {
			t.Fatalf("%s workflow selects rollback integration %d times, want exactly 1", workflow.name, count)
		}
		if !strings.Contains(workflow.content, "TACHYON_ALLOW_REAL_ROUTE_TEST: \"1\"") {
			t.Fatalf("%s workflow is missing the real-route opt-in gate", workflow.name)
		}
	}

	release := workflows[1].content
	for _, required := range []string{"test-windows:", "Test full Windows suite", "needs: [verify_tag, test, test-windows]"} {
		if !strings.Contains(release, required) {
			t.Fatalf("Release workflow is missing Windows route security requirement %q", required)
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
