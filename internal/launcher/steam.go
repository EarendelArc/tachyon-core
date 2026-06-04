package launcher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type SteamLibraryFolder struct {
	Path   string   `json:"path"`
	AppIDs []uint32 `json:"appIds"`
}

type SteamAppManifest struct {
	AppID       uint32 `json:"appId"`
	Name        string `json:"name"`
	InstallDir  string `json:"installDir"`
	Universe    string `json:"universe"`
	StateFlags  uint32 `json:"stateFlags"`
	LibraryPath string `json:"libraryPath"`
}

type SteamScanner struct{}

func NewSteamScanner() *SteamScanner {
	return &SteamScanner{}
}

func (s *SteamScanner) Scan(ctx context.Context, steamRoot string) ([]SteamAppManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	libraryFile := filepath.Join(steamRoot, "steamapps", "libraryfolders.vdf")
	file, err := os.Open(libraryFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	folders, err := ParseSteamLibraryFolders(file)
	if err != nil {
		return nil, err
	}
	if !containsLibraryPath(folders, steamRoot) {
		folders = append([]SteamLibraryFolder{{Path: steamRoot}}, folders...)
	}

	var manifests []SteamAppManifest
	for _, folder := range folders {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		apps, err := scanSteamAppManifests(folder.Path)
		if err != nil {
			continue
		}
		manifests = append(manifests, apps...)
	}

	return manifests, nil
}

func scanSteamAppManifests(libraryPath string) ([]SteamAppManifest, error) {
	pattern := filepath.Join(libraryPath, "steamapps", "appmanifest_*.acf")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	var manifests []SteamAppManifest
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		manifest, err := ParseSteamAppManifest(file)
		_ = file.Close()
		if err != nil {
			continue
		}
		manifest.LibraryPath = libraryPath
		manifests = append(manifests, manifest)
	}
	return manifests, nil
}

func ParseSteamLibraryFolders(r io.Reader) ([]SteamLibraryFolder, error) {
	tokens, err := tokenizeVDF(r)
	if err != nil {
		return nil, err
	}

	var folders []SteamLibraryFolder
	for idx := 0; idx+2 < len(tokens); idx++ {
		if !isUint(tokens[idx]) || tokens[idx+1] != "{" {
			continue
		}

		end := matchingClose(tokens, idx+1)
		if end <= idx+1 {
			continue
		}

		folder := SteamLibraryFolder{}
		for scan := idx + 2; scan < end; scan++ {
			switch tokens[scan] {
			case "path":
				if scan+1 < end {
					folder.Path = tokens[scan+1]
				}
			case "apps":
				if scan+1 < end && tokens[scan+1] == "{" {
					appsEnd := matchingClose(tokens, scan+1)
					if appsEnd > scan+1 && appsEnd <= end {
						folder.AppIDs = parseSteamApps(tokens[scan+2 : appsEnd])
						scan = appsEnd
					}
				}
			}
		}
		if folder.Path != "" {
			folders = append(folders, folder)
		}
		idx = end
	}

	return folders, nil
}

func containsLibraryPath(folders []SteamLibraryFolder, path string) bool {
	normalized := normalizePath(path)
	for _, folder := range folders {
		if normalizePath(folder.Path) == normalized {
			return true
		}
	}
	return false
}

func normalizePath(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

func ParseSteamAppManifest(r io.Reader) (SteamAppManifest, error) {
	tokens, err := tokenizeVDF(r)
	if err != nil {
		return SteamAppManifest{}, err
	}

	var manifest SteamAppManifest
	for idx := 0; idx+1 < len(tokens); idx++ {
		key := strings.ToLower(tokens[idx])
		value := tokens[idx+1]
		switch key {
		case "appid":
			manifest.AppID = parseUint32(value)
		case "name":
			manifest.Name = value
		case "installdir":
			manifest.InstallDir = value
		case "universe":
			manifest.Universe = value
		case "stateflags":
			manifest.StateFlags = parseUint32(value)
		}
	}

	if manifest.AppID == 0 {
		return SteamAppManifest{}, fmt.Errorf("steam app manifest missing appid")
	}
	return manifest, nil
}

func parseSteamApps(tokens []string) []uint32 {
	var appIDs []uint32
	for idx := 0; idx+1 < len(tokens); idx += 2 {
		appID := parseUint32(tokens[idx])
		if appID != 0 {
			appIDs = append(appIDs, appID)
		}
	}
	return appIDs
}

func tokenizeVDF(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	var tokens []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		tokens = append(tokens, quotedTokens(line)...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

func quotedTokens(line string) []string {
	var tokens []string
	for {
		if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "}") {
			tokens = append(tokens, line[:1])
			line = strings.TrimSpace(line[1:])
			continue
		}

		start := strings.IndexByte(line, '"')
		if start < 0 {
			return tokens
		}
		line = line[start+1:]
		end := strings.IndexByte(line, '"')
		if end < 0 {
			return tokens
		}
		tokens = append(tokens, unescapeVDFString(line[:end]))
		line = line[end+1:]
	}
}

func unescapeVDFString(value string) string {
	value = strings.ReplaceAll(value, `\\`, `\`)
	value = strings.ReplaceAll(value, `\"`, `"`)
	return value
}

func matchingClose(tokens []string, openIdx int) int {
	depth := 0
	for idx := openIdx; idx < len(tokens); idx++ {
		switch tokens[idx] {
		case "{":
			depth++
		case "}":
			depth--
			if depth == 0 {
				return idx
			}
		}
	}
	return -1
}

func isUint(value string) bool {
	_, err := strconv.ParseUint(value, 10, 32)
	return err == nil
}

func parseUint32(value string) uint32 {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(parsed)
}
