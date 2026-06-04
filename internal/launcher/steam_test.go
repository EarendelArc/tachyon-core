package launcher

import (
	"strings"
	"testing"
)

func TestParseSteamLibraryFolders(t *testing.T) {
	input := `"libraryfolders"
{
	"0"
	{
		"path"		"C:\\Program Files (x86)\\Steam"
		"label"		""
		"contentid"		"123"
		"apps"
		{
			"730"		"123456"
			"1245620"		"654321"
		}
	}
	"1"
	{
		"path"		"D:\\SteamLibrary"
		"apps"
		{
			"570"		"42"
		}
	}
}`

	folders, err := ParseSteamLibraryFolders(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse library folders: %v", err)
	}
	if len(folders) != 2 {
		t.Fatalf("expected two folders, got %d", len(folders))
	}
	if folders[0].Path != `C:\\Program Files (x86)\\Steam` {
		t.Fatalf("unexpected first path: %q", folders[0].Path)
	}
	if len(folders[0].AppIDs) != 2 || folders[0].AppIDs[0] != 730 || folders[0].AppIDs[1] != 1245620 {
		t.Fatalf("unexpected first apps: %#v", folders[0].AppIDs)
	}
	if len(folders[1].AppIDs) != 1 || folders[1].AppIDs[0] != 570 {
		t.Fatalf("unexpected second apps: %#v", folders[1].AppIDs)
	}
}

func TestParseSteamAppManifest(t *testing.T) {
	input := `"AppState"
{
	"appid"		"730"
	"Universe"		"1"
	"name"		"Counter-Strike 2"
	"StateFlags"		"4"
	"installdir"		"Counter-Strike Global Offensive"
}`

	manifest, err := ParseSteamAppManifest(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse app manifest: %v", err)
	}
	if manifest.AppID != 730 {
		t.Fatalf("unexpected app id: %d", manifest.AppID)
	}
	if manifest.Name != "Counter-Strike 2" {
		t.Fatalf("unexpected name: %q", manifest.Name)
	}
	if manifest.InstallDir != "Counter-Strike Global Offensive" {
		t.Fatalf("unexpected install dir: %q", manifest.InstallDir)
	}
}
