// Package manager implements XrayManager backed by the GitHub Releases API.
// It downloads, verifies and extracts xray-core binaries to a managed directory.
package manager

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	githubAPIBase  = "https://api.github.com/repos/XTLS/Xray-core"
	binaryName     = "xray"
	defaultTimeout = 30 * time.Second
)

// GitHubManager implements XrayManager using the GitHub Releases API.
type GitHubManager struct {
	installDir string
	client     *http.Client
}

// NewGitHubManager creates a manager that stores binaries in installDir.
func NewGitHubManager(installDir string) (*GitHubManager, error) {
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return nil, fmt.Errorf("create install dir %q: %w", installDir, err)
	}
	return &GitHubManager{
		installDir: installDir,
		client:     &http.Client{Timeout: defaultTimeout},
	}, nil
}

// ListReleases fetches the most recent xray-core releases from GitHub.
func (m *GitHubManager) ListReleases(ctx context.Context) ([]Release, error) {
	url := fmt.Sprintf("%s/releases?per_page=30", githubAPIBase)
	body, err := m.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var raw []struct {
		TagName     string    `json:"tag_name"`
		PublishedAt time.Time `json:"published_at"`
		Assets      []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode releases: %w", err)
	}

	releases := make([]Release, 0, len(raw))
	for _, r := range raw {
		rel := Release{
			Version:     r.TagName,
			PublishedAt: r.PublishedAt,
		}
		platform := currentPlatform()
		for _, asset := range r.Assets {
			if platformFromAssetName(asset.Name) == platform {
				rel.AssetURL = asset.BrowserDownloadURL
			}
			if strings.HasSuffix(asset.Name, ".sha256sum") || asset.Name == "checksums.txt" {
				rel.ChecksumURL = asset.BrowserDownloadURL
			}
		}
		releases = append(releases, rel)
	}
	return releases, nil
}

// Latest returns the newest release.
func (m *GitHubManager) Latest(ctx context.Context) (Release, error) {
	releases, err := m.ListReleases(ctx)
	if err != nil {
		return Release{}, err
	}
	if len(releases) == 0 {
		return Release{}, fmt.Errorf("no releases found")
	}
	return releases[0], nil
}

// Ensure downloads version if not already installed; returns the Binary path.
func (m *GitHubManager) Ensure(ctx context.Context, version string, opt DownloadOptions) (Binary, error) {
	bin := Binary{
		Version: version,
		Path:    m.binaryPath(),
	}

	// Already installed?
	if m.installedVersion() == version {
		return bin, nil
	}

	// Find the release.
	releases, err := m.ListReleases(ctx)
	if err != nil {
		return Binary{}, fmt.Errorf("list releases: %w", err)
	}
	var rel Release
	for _, r := range releases {
		if r.Version == version || version == "latest" {
			rel = r
			break
		}
	}
	if rel.AssetURL == "" {
		return Binary{}, fmt.Errorf("no asset for version %q on platform %s/%s", version, opt.Platform, opt.Arch)
	}

	// Download to temp file.
	tmpFile, err := os.CreateTemp(m.installDir, "xray-download-*.tmp")
	if err != nil {
		return Binary{}, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.AssetURL, nil)
	if err != nil {
		return Binary{}, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return Binary{}, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Binary{}, fmt.Errorf("download status: %s", resp.Status)
	}

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmpFile, hasher), resp.Body); err != nil {
		return Binary{}, fmt.Errorf("write archive: %w", err)
	}
	_ = tmpFile.Close()

	bin.SHA256 = hex.EncodeToString(hasher.Sum(nil))

	// Extract xray binary from zip.
	if err := extractBinary(tmpPath, m.binaryPath()); err != nil {
		return Binary{}, fmt.Errorf("extract: %w", err)
	}

	// Write version file.
	if err := os.WriteFile(m.versionPath(), []byte(version), 0o644); err != nil {
		return Binary{}, fmt.Errorf("write version: %w", err)
	}

	return bin, nil
}

// Verify re-hashes the installed binary and checks it matches bin.SHA256.
func (m *GitHubManager) Verify(_ context.Context, bin Binary) error {
	if bin.SHA256 == "" {
		return nil
	}
	f, err := os.Open(bin.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, bin.SHA256) {
		return fmt.Errorf("SHA-256 mismatch: want %s got %s", bin.SHA256, got)
	}
	return nil
}

// Remove deletes the installed binary for version.
func (m *GitHubManager) Remove(_ context.Context, _ string) error {
	_ = os.Remove(m.binaryPath())
	_ = os.Remove(m.versionPath())
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (m *GitHubManager) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api %q: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("github api status %s", resp.Status)
	}
	return resp.Body, nil
}

func (m *GitHubManager) binaryPath() string {
	name := binaryName
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(m.installDir, name)
}

func (m *GitHubManager) versionPath() string {
	return filepath.Join(m.installDir, "version.txt")
}

func (m *GitHubManager) installedVersion() string {
	b, err := os.ReadFile(m.versionPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// extractBinary extracts the xray executable from a zip archive.
func extractBinary(archivePath, destPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	targetName := binaryName
	if runtime.GOOS == "windows" {
		targetName += ".exe"
	}

	for _, f := range r.File {
		if filepath.Base(f.Name) != targetName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("create binary: %w", err)
		}
		defer out.Close()

		_, err = io.Copy(out, rc)
		return err
	}
	return fmt.Errorf("binary %q not found in archive", targetName)
}

func currentPlatform() string {
	os := runtime.GOOS
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "64"
	case "arm64":
		arch = "arm64-v8a"
	case "386":
		arch = "32"
	}
	return fmt.Sprintf("%s-%s", os, arch)
}

func platformFromAssetName(name string) string {
	name = strings.TrimSuffix(name, ".zip")
	name = strings.TrimPrefix(name, "Xray-")
	for _, k := range []string{"linux-64", "linux-arm64-v8a", "darwin-64", "darwin-arm64-v8a", "windows-64"} {
		if name == k {
			return k
		}
	}
	return ""
}

// Ensure GitHubManager satisfies the XrayManager interface.
var _ XrayManager = (*GitHubManager)(nil)
