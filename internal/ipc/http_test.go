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
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

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
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

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
	server := NewHTTPServer(HTTPOptions{Routing: routingService})
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


func TestHTTPHealth(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if response["status"] != "ok" {
		t.Fatalf("expected status ok, got %q", response["status"])
	}
}

func TestHTTPUpdateGameProfile(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

	addBody := bytes.NewBufferString(`{
		"id": "update-me",
		"displayName": "Original",
		"enabled": true,
		"manual": true,
		"priority": 50,
		"match": {"processNames": ["orig.exe"]},
		"udpPolicy": "tgp",
		"tcpPolicy": "auto"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/routing/game-profiles", addBody)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add profile: %d %s", rec.Code, rec.Body.String())
	}

	updateBody := bytes.NewBufferString(`{
		"id": "update-me",
		"displayName": "Updated Name",
		"enabled": false,
		"manual": true,
		"priority": 99,
		"match": {"processNames": ["updated.exe"]},
		"udpPolicy": "direct",
		"tcpPolicy": "direct"
	}`)
	req = httptest.NewRequest(http.MethodPut, "/v1/routing/game-profiles/update-me", updateBody)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var profile routing.GameProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &profile); err != nil {
		t.Fatalf("decode updated profile: %v", err)
	}
	if profile.DisplayName != "Updated Name" {
		t.Fatalf("expected display name Updated Name, got %q", profile.DisplayName)
	}
	if profile.Priority != 99 {
		t.Fatalf("expected priority 99, got %d", profile.Priority)
	}
	if profile.Enabled {
		t.Fatal("expected enabled false")
	}
	if profile.UDPPolicy != routing.UDPPolicyDirect {
		t.Fatalf("expected udpPolicy direct, got %q", profile.UDPPolicy)
	}
}

func TestHTTPPostDuplicateID(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

	body := bytes.NewBufferString(`{
		"id": "dup",
		"displayName": "Dup",
		"enabled": true,
		"manual": true,
		"match": {"processNames": ["dup.exe"]},
		"udpPolicy": "tgp",
		"tcpPolicy": "auto"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/routing/game-profiles", body)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first add: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/routing/game-profiles", body)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 duplicate, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPDeleteNotFound(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

	req := httptest.NewRequest(http.MethodDelete, "/v1/routing/game-profiles/nonexistent", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPPutNotFound(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

	body := bytes.NewBufferString(`{
		"id": "nonexistent",
		"displayName": "Ghost",
		"enabled": true,
		"manual": true,
		"match": {"processNames": ["ghost.exe"]},
		"udpPolicy": "tgp",
		"tcpPolicy": "auto"
	}`)
	req := httptest.NewRequest(http.MethodPut, "/v1/routing/game-profiles/nonexistent", body)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPPostInvalidJSON(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

	body := bytes.NewBufferString(`not json`)
	req := httptest.NewRequest(http.MethodPost, "/v1/routing/game-profiles", body)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code < 400 {
		t.Fatalf("expected error status, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPPostMissingRequiredFields(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

	body := bytes.NewBufferString(`{
		"id": "",
		"displayName": "",
		"match": {}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/routing/game-profiles", body)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPGetEmptyProfiles(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

	req := httptest.NewRequest(http.MethodGet, "/v1/routing/game-profiles", nil)
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
	if len(response.Profiles) != 0 {
		t.Fatalf("expected empty profiles, got %d", len(response.Profiles))
	}
}

func TestHTTPPutEmptyID(t *testing.T) {
	routingService := routing.NewService(routing.NewMemoryStore(routing.DefaultConfig()))
	server := NewHTTPServer(HTTPOptions{Routing: routingService})

	body := bytes.NewBufferString(`{
		"id": "",
		"displayName": "Test",
		"enabled": true,
		"manual": true,
		"match": {"processNames": ["test.exe"]},
		"udpPolicy": "tgp",
		"tcpPolicy": "auto"
	}`)
	req := httptest.NewRequest(http.MethodPut, "/v1/routing/game-profiles/", body)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for empty profile id in URL, got %d: %s", rec.Code, rec.Body.String())
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

