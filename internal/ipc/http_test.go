package ipc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/routing"
)

func TestHTTPGameProfileLifecycle(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(routingService)

	body := bytes.NewBufferString(`{
		"id": "manual",
		"displayName": "Manual Game",
		"enabled": true,
		"manual": true,
		"priority": 100,
		"match": {
			"processNames": ["manual.exe"],
			"paths": [],
			"pathPrefixes": [],
			"sha256": [],
			"steamAppIds": []
		},
		"udpPolicy": "tgp",
		"tcpPolicy": "auto"
	}`)

	req := httptest.NewRequest(http.MethodPost, "/v1/routing/game-profiles", body)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/routing/game-profiles", nil)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var response struct {
		Profiles []routing.GameProfile `json:"profiles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Profiles) != 1 || response.Profiles[0].ID != "manual" {
		t.Fatalf("unexpected profiles: %#v", response.Profiles)
	}

	req = httptest.NewRequest(http.MethodDelete, "/v1/routing/game-profiles/manual", nil)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPOptionsCORS(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(routingService)

	req := httptest.NewRequest(http.MethodOptions, "/v1/routing/game-profiles", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("expected wildcard cors origin, got %q", got)
	}
}

func TestHTTPScanSteam(t *testing.T) {
	root := t.TempDir()
	secondary := filepath.Join(root, "library2")
	writeFile(t, filepath.Join(root, "steamapps", "libraryfolders.vdf"), `"libraryfolders"
{
	"0"
	{
		"path"		"`+escapeVDFPath(root)+`"
	}
	"1"
	{
		"path"		"`+escapeVDFPath(secondary)+`"
	}
}`)
	writeFile(t, filepath.Join(secondary, "steamapps", "appmanifest_730.acf"), `"AppState"
{
	"appid"		"730"
	"name"		"Counter-Strike 2"
	"installdir"		"Counter-Strike Global Offensive"
}`)

	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(routingService)
	req := httptest.NewRequest(http.MethodGet, "/v1/launchers/steam/scan?root="+url.QueryEscape(root), nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Profiles []routing.GameProfile `json:"profiles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Profiles) != 1 {
		t.Fatalf("expected one profile suggestion, got %#v", response.Profiles)
	}
	if response.Profiles[0].Match.SteamAppIDs[0] != 730 {
		t.Fatalf("unexpected steam app id: %#v", response.Profiles[0].Match.SteamAppIDs)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func escapeVDFPath(path string) string {
	return strings.ReplaceAll(path, `\`, `\\`)
}
