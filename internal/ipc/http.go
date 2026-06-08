package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tachyon-space/tachyon-core/internal/launcher"
	"github.com/tachyon-space/tachyon-core/internal/observability"
	"github.com/tachyon-space/tachyon-core/internal/routing"
)

type HTTPServer struct {
	routing      *routing.Service
	broadcaster  *observability.Broadcaster
	mux          *http.ServeMux
}

// HTTPOptions configures the IPC HTTP server.
type HTTPOptions struct {
	Routing     *routing.Service
	Broadcaster *observability.Broadcaster
}

func NewHTTPServer(opts HTTPOptions) *HTTPServer {
	server := &HTTPServer{
		routing:     opts.Routing,
		broadcaster: opts.Broadcaster,
		mux:         http.NewServeMux(),
	}
	server.routes()
	return server
}

func (s *HTTPServer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}

func (s *HTTPServer) routes() {
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /v1/routing/game-profiles", s.handleListGameProfiles)
	s.mux.HandleFunc("POST /v1/routing/game-profiles", s.handleAddGameProfile)
	s.mux.HandleFunc("PUT /v1/routing/game-profiles/", s.handleUpdateGameProfile)
	s.mux.HandleFunc("DELETE /v1/routing/game-profiles/", s.handleRemoveGameProfile)
	s.mux.HandleFunc("GET /v1/launchers/steam/scan", s.handleScanSteam)
	if s.broadcaster != nil {
		s.mux.Handle("GET /v1/telemetry/sse", s.broadcaster)
	}
}

func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *HTTPServer) handleListGameProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.routing.ListGameProfiles(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
}

func (s *HTTPServer) handleAddGameProfile(w http.ResponseWriter, r *http.Request) {
	var profile routing.GameProfile
	if err := decodeJSON(r, &profile); err != nil {
		writeError(w, err)
		return
	}
	created, err := s.routing.AddGameProfile(r.Context(), profile)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *HTTPServer) handleUpdateGameProfile(w http.ResponseWriter, r *http.Request) {
	id := profileIDFromPath(r.URL.Path)
	var profile routing.GameProfile
	if err := decodeJSON(r, &profile); err != nil {
		writeError(w, err)
		return
	}
	updated, err := s.routing.UpdateGameProfile(r.Context(), id, profile)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *HTTPServer) handleRemoveGameProfile(w http.ResponseWriter, r *http.Request) {
	id := profileIDFromPath(r.URL.Path)
	if err := s.routing.RemoveGameProfile(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *HTTPServer) handleScanSteam(w http.ResponseWriter, r *http.Request) {
	root := strings.TrimSpace(r.URL.Query().Get("root"))
	scanner := launcher.NewSteamScanner()

	var apps []launcher.SteamAppManifest
	var err error
	if root == "" {
		apps, err = scanner.ScanDefaultRoots(r.Context())
	} else {
		apps, err = scanner.Scan(r.Context(), root)
	}
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"apps":     apps,
		"profiles": steamProfileSuggestions(apps),
	})
}

func profileIDFromPath(path string) string {
	const prefix = "/v1/routing/game-profiles/"
	return strings.TrimSpace(strings.TrimPrefix(path, prefix))
}

func steamProfileSuggestions(apps []launcher.SteamAppManifest) []routing.GameProfile {
	profiles := make([]routing.GameProfile, 0, len(apps))
	for _, app := range apps {
		displayName := app.Name
		if displayName == "" {
			displayName = app.InstallDir
		}
		if displayName == "" || app.AppID == 0 {
			continue
		}

		prefix := ""
		if app.LibraryPath != "" && app.InstallDir != "" {
			prefix = filepath.Join(app.LibraryPath, "steamapps", "common", app.InstallDir)
		}

		profiles = append(profiles, routing.GameProfile{
			ID:          "steam-" + uint32String(app.AppID),
			DisplayName: displayName,
			Enabled:     true,
			Manual:      false,
			Priority:    10,
			Match: routing.MatchRule{
				PathPrefixes: compactStrings([]string{prefix}),
				SteamAppIDs:  []uint32{app.AppID},
			},
			UDPPolicy: routing.UDPPolicyTGP,
			TCPPolicy: routing.TCPPolicyAuto,
		})
	}
	return profiles
}

func uint32String(value uint32) string {
	return strconv.FormatUint(uint64(value), 10)
}

func compactStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, routing.ErrProfileNotFound):
		status = http.StatusNotFound
	case errors.Is(err, routing.ErrDuplicateID):
		status = http.StatusConflict
	case errors.Is(err, routing.ErrInvalidProfile):
		status = http.StatusBadRequest
	case errors.Is(err, context.Canceled):
		status = http.StatusRequestTimeout
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
