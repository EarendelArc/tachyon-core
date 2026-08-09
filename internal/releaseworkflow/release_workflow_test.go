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
		"generate-build-metadata.py",
		"generate-evidence-manifest.py",
		"generate-wintun-contract.py",
		"verify-published-release.sh",
		"Upload sanitized Helper evidence",
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
		"## Verification and release assets",
		"## Limitations",
		"WFP Helper / Captured UDP Named Pipe v2 Preview",
		"no real WFP callout",
		"no signed WFP driver",
		"no process capture",
		"no real game end-to-end (E2E) validation",
		"Prism-managed system-proxy takeover remains disabled by default",
		"RELEASE_NOTES.zh-CN.md",
		"版本：`{{VERSION}}`",
		"源代码提交：`{{COMMIT}}`",
		"## 兼容性",
		"## 校验与发布资产",
		"## 限制",
		"不包含真实 WFP callout",
	} {
		if !strings.Contains(templates, text) {
			t.Fatalf("shared release note templates are missing %q", text)
		}
	}
	for _, text := range []string{"prepare-release-metadata.py", `--template-directory "${template_dir}"`} {
		if !strings.Contains(preparation, text) {
			t.Fatalf("release preparation script is missing shared metadata generator behavior %q", text)
		}
	}
	metadataGenerator := readRepoFile(t, ".github", "scripts", "prepare-release-metadata.py")
	for _, text := range []string{"RELEASE_NOTES.md.tmpl", "RELEASE_NOTES.zh-CN.md.tmpl", "{{VERSION}}", "{{COMMIT}}", "SHA256SUMS.txt"} {
		if !strings.Contains(metadataGenerator, text) {
			t.Fatalf("shared metadata generator is missing %q", text)
		}
	}

	for _, text := range []string{
		`"${release_dir}/RELEASE_NOTES.md"`,
		`"${release_dir}/RELEASE_NOTES.zh-CN.md"`,
		"sha256sum --check --strict SHA256SUMS.txt",
		`cat "${release_dir}/RELEASE_NOTES.md"`,
		`cat "${release_dir}/RELEASE_NOTES.zh-CN.md"`,
		`--notes-file "${body_file}"`,
		"BUILD_METADATA.json",
		"WINTUN_SIDECAR_CONTRACT.json",
		"EVIDENCE_MANIFEST.json",
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
		"release-policy:",
		"linux-lifecycle:",
		"go-test:",
		"go-race:",
		"needs: [release-policy, linux-lifecycle, go-test, go-race, test-windows, build]",
		"python3 .github/scripts/test-reproducible-release.py",
		"python .github/scripts/test-reproducible-release.py",
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
		`must be an annotated tag`,
		`generate-wintun-contract.py`,
		`deterministic_archive.py`,
		`--verify-official`,
		`validate-release-assets.py`,
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
		"prepare-release-metadata.py",
		"--template-directory $TemplateDirectory",
		"generate-wintun-contract.py",
		"--verify-official",
		"validate-release-assets.py",
		"unexpected asset",
	} {
		if !strings.Contains(windowsPreparation, text) {
			t.Fatalf("Windows release preparation is missing contract %q", text)
		}
	}

	ci := readRepoFile(t, ".github", "workflows", "ci.yml")
	if !strings.Contains(ci, ".github/scripts/test-build-release-policy.ps1") {
		t.Fatal("CI does not run the Windows release golden policy test")
	}
	if strings.Index(ci, "release-policy:") > strings.Index(ci, "linux-lifecycle:") ||
		strings.Index(ci, "linux-lifecycle:") > strings.Index(ci, "go-test:") {
		t.Fatal("CI independent gate declarations are missing or unexpectedly ordered")
	}

	wintunContract := readRepoFile(t, ".github", "wintun", "WINTUN_SIDECAR_CONTRACT.json")
	for _, text := range []string{`"size": 427552`, `"size": 222488`} {
		if !strings.Contains(wintunContract, text) {
			t.Fatalf("Wintun sidecar contract is missing verified DLL size %q", text)
		}
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
	for _, text := range []string{`--target "${commit}"`, "--verify-tag", "--draft", "gh release upload", "-F draft=false", `"repos/${repository}/immutable-releases"`, "X-GitHub-Api-Version: 2026-03-10"} {
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

func TestReleaseRejectsLightweightTagsAndValidatesPublishedAssets(t *testing.T) {
	tagVerification := readRepoFile(t, ".github", "scripts", "verify-release-tag.sh")
	for _, text := range []string{
		`[[ "${tag_type}" == "tag" ]]`,
		"must be an annotated tag object",
		`verification="annotated-tag"`,
	} {
		if !strings.Contains(tagVerification, text) {
			t.Fatalf("release tag verification is missing %q", text)
		}
	}
	legacyMode := "ref-" + "commit"
	if strings.Contains(tagVerification, legacyMode) {
		t.Fatal("release tag verification still contains legacy lightweight-tag compatibility")
	}

	bashPolicy := readRepoFile(t, ".github", "scripts", "test-release-policy.sh")
	for _, text := range []string{
		"lightweight tag at expected commit",
		"refs/tags/v1.2.5",
		"test-published-release-policy.py",
	} {
		if !strings.Contains(bashPolicy, text) {
			t.Fatalf("Bash release policy is missing %q", text)
		}
	}

	publishedVerification := readRepoFile(t, ".github", "scripts", "verify-published-release.sh")
	for _, text := range []string{
		`gh api "repos/${repository}/releases/tags/${version}"`,
		"validate-published-release.py",
	} {
		if !strings.Contains(publishedVerification, text) {
			t.Fatalf("published release verification is missing %q", text)
		}
	}
	for _, forbidden := range []string{"TACHYON_RELEASE_JSON", "fixture", "FIXTURE"} {
		if strings.Contains(publishedVerification, forbidden) {
			t.Fatalf("production published release verification contains fixture bypass %q", forbidden)
		}
	}

	fixtures := readRepoFile(t, ".github", "scripts", "test-published-release-policy.py")
	for _, text := range []string{
		"test_positive_fixture_passes",
		"test_is_immutable_false_fails",
		"test_target_commit_mismatch_fails",
		"test_digest_mismatch_fails",
		"test_size_mismatch_fails",
		"test_missing_asset_fails",
		"test_extra_asset_fails",
	} {
		if !strings.Contains(fixtures, text) {
			t.Fatalf("published release fixture policy is missing %q", text)
		}
	}
}

func TestCurrentReleasePipelineIsPrereleaseOnly(t *testing.T) {
	workflow := readReleaseWorkflow(t)
	if strings.Contains(workflow, "inputs.prerelease") {
		t.Fatal("workflow_dispatch exposes a formal-release path")
	}
	if count := strings.Count(workflow, `echo "prerelease=true"`); count != 1 {
		t.Fatalf("release workflow forces prerelease metadata %d times, want exactly 1", count)
	}
	if !strings.Contains(workflow, `RELEASE_SETTINGS_TOKEN: ${{ secrets.RELEASE_SETTINGS_TOKEN }}`) {
		t.Fatal("release workflow does not provide the immutable-release settings credential")
	}

	publication := readRepoFile(t, ".github", "scripts", "publish-release.sh")
	for _, required := range []string{
		`[[ "${prerelease}" == "true" ]]`,
		"only prerelease publication is supported",
		"--prerelease",
		`[[ ${#assets[@]} -eq 13 ]]`,
		`[[ ${#expected_checksum_entries[@]} -eq 12 ]]`,
		`[[ -n "${settings_token}" ]]`,
		"repository immutable releases are not provably enabled",
	} {
		if !strings.Contains(publication, required) {
			t.Fatalf("prerelease publication policy is missing %q", required)
		}
	}
	gate := strings.Index(publication, `[[ "${prerelease}" == "true" ]]`)
	firstGitHubRead := strings.Index(publication, `gh release view "${version}"`)
	if gate < 0 || firstGitHubRead < 0 || gate > firstGitHubRead {
		t.Fatal("prerelease-only gate must run before the first GitHub API operation")
	}
	immutableGate := strings.Index(publication, `"repos/${repository}/immutable-releases"`)
	firstReleaseCreate := strings.Index(publication, `gh release create "${version}"`)
	if immutableGate < 0 || firstReleaseCreate < 0 || immutableGate > firstReleaseCreate {
		t.Fatal("repository immutable-release setting must be verified before draft creation")
	}

	bashPolicy := readRepoFile(t, ".github", "scripts", "test-release-policy.sh")
	for _, required := range []string{
		"non-prerelease publication",
		"run_publish happy false v1.2.4-alpha.24",
		"prerelease=false reached the GitHub API",
		"mutable repository setting",
		"missing immutable settings credential",
	} {
		if !strings.Contains(bashPolicy, required) {
			t.Fatalf("persistent prerelease-negative policy is missing %q", required)
		}
	}
}

func TestDockerInstallerLifecycleFixturesAreMandatory(t *testing.T) {
	fixture := readRepoFile(t, "scripts", "test-docker-installer-lifecycle.sh")
	for _, required := range []string{
		`[[ "$(uname -s)" == "Linux" ]] || fail`,
		"setsid env",
		"kill -s",
		"kill -KILL",
		"another Docker installer owns the lifecycle lock",
		"SIGKILL did not leave a recovery journal",
	} {
		if !strings.Contains(fixture, required) {
			t.Fatalf("Docker lifecycle fixture is missing %q", required)
		}
	}

	for name, workflow := range map[string]string{
		"CI":      readRepoFile(t, ".github", "workflows", "ci.yml"),
		"Release": readReleaseWorkflow(t),
	} {
		for _, required := range []string{
			"Verify Docker installer process lifecycle",
			"timeout-minutes: 3",
			"timeout --signal=TERM --kill-after=10s 150s bash scripts/test-docker-installer-lifecycle.sh",
		} {
			if !strings.Contains(workflow, required) {
				t.Fatalf("%s workflow is missing mandatory Docker lifecycle gate %q", name, required)
			}
		}
	}
}
