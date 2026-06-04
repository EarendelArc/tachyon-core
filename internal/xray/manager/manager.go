package manager

import (
	"context"
	"time"
)

type Release struct {
	Version     string
	AssetURL    string
	ChecksumURL string
	PublishedAt time.Time
}

type Binary struct {
	Version string
	Path    string
	SHA256  string
}

type DownloadOptions struct {
	Platform string
	Arch     string
	Resume   bool
}

type XrayManager interface {
	ListReleases(ctx context.Context) ([]Release, error)
	Latest(ctx context.Context) (Release, error)
	Ensure(ctx context.Context, version string, opt DownloadOptions) (Binary, error)
	Verify(ctx context.Context, bin Binary) error
	Remove(ctx context.Context, version string) error
}
