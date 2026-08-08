package ipc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
	listen       netip.AddrPort
	sessionToken []byte
	origins      map[string]struct{}
}

const MaxRequestBodyBytes int64 = 64 << 10

var errInvalidRequestBody = errors.New("invalid request body")

// HTTPOptions configures the IPC HTTP server.
type HTTPOptions struct {
	Routing        *routing.Service
	Broadcaster    *observability.Broadcaster
	ListenAddress  string
	SessionToken   string
	AllowedOrigins []string
}

func NewHTTPServer(opts HTTPOptions) (*HTTPServer, error) {
	listen, err := ParseListenAddress(opts.ListenAddress)
	if err != nil {
		return nil, err
	}
	if err := ValidateSessionToken(opts.SessionToken); err != nil {
		return nil, err
	}
	origins, err := validateAllowedOrigins(opts.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	server := &HTTPServer{
		routing:      opts.Routing,
		broadcaster:  opts.Broadcaster,
		mux:          http.NewServeMux(),
		listen:       listen,
		sessionToken: []byte(opts.SessionToken),
		origins:      origins,
	}
	server.routes()
	return server, nil
}

func (s *HTTPServer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if !s.validRemote(r.RemoteAddr) || !s.validHost(r.Host) {
			writeJSON(w, http.StatusMisdirectedRequest, map[string]string{"error": "request authority is not the configured loopback endpoint"})
			return
		}
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if _, ok := s.origins[origin]; !ok {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin is not allowed"})
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			if origin == "" || !validPreflightMethod(r.Header.Get("Access-Control-Request-Method")) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CORS preflight"})
				return
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "300")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !s.authorized(r.Header.Get("Authorization")) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tachyon-core-ipc"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		if !validRouteMethod(r.Method, r.URL.Path) {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "application/json" {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
		}
		s.mux.ServeHTTP(w, r)
	})
}

// ParseListenAddress accepts only the two numeric loopback addresses. Hostnames
// are deliberately rejected so DNS cannot change the security boundary.
func ParseListenAddress(raw string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("IPC listen address must be numeric loopback with a port: %w", err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" || (addr != netip.MustParseAddr("127.0.0.1") && addr != netip.IPv6Loopback()) {
		return netip.AddrPort{}, errors.New("IPC listen host must be exactly 127.0.0.1 or ::1")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("IPC listen port must be between 1 and 65535")
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func validateAllowedOrigins(values []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, raw := range values {
		origin := strings.TrimSpace(raw)
		if origin == "" {
			continue
		}
		if origin == "*" || strings.EqualFold(origin, "null") {
			return nil, fmt.Errorf("IPC allowed origin %q is forbidden", origin)
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return nil, fmt.Errorf("IPC allowed origin %q must be an exact origin", origin)
		}
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https", "tauri":
		default:
			return nil, fmt.Errorf("IPC allowed origin %q uses an unsupported scheme", origin)
		}
		result[origin] = struct{}{}
	}
	return result, nil
}

func (s *HTTPServer) validHost(raw string) bool {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr != s.listen.Addr() {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && uint16(port) == s.listen.Port()
}

func (s *HTTPServer) validRemote(raw string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && (addr == netip.MustParseAddr("127.0.0.1") || addr == netip.IPv6Loopback())
}

func (s *HTTPServer) authorized(raw string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(raw, prefix) || strings.ContainsAny(raw[len(prefix):], " \t\r\n") {
		return false
	}
	presented := []byte(raw[len(prefix):])
	return len(presented) == len(s.sessionToken) && subtle.ConstantTimeCompare(presented, s.sessionToken) == 1
}

func validPreflightMethod(method string) bool {
	switch strings.TrimSpace(method) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func validRouteMethod(method, path string) bool {
	switch path {
	case "/v1/health", "/v1/routing/game-profiles", "/v1/launchers/steam/scan", "/v1/telemetry/sse":
		return method == http.MethodGet || (path == "/v1/routing/game-profiles" && method == http.MethodPost)
	default:
		if strings.HasPrefix(path, "/v1/routing/game-profiles/") {
			return method == http.MethodPut || method == http.MethodDelete
		}
		return method == http.MethodGet
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
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
	s.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "endpoint not found"})
	})
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
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return err
		}
		return fmt.Errorf("%w: malformed JSON", errInvalidRequestBody)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: request body must contain exactly one JSON value", errInvalidRequestBody)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		status = http.StatusRequestEntityTooLarge
	case errors.Is(err, errInvalidRequestBody):
		status = http.StatusBadRequest
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
