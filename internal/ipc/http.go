package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/tachyon-space/tachyon-core/internal/routing"
)

type HTTPServer struct {
	routing *routing.Service
	mux     *http.ServeMux
}

func NewHTTPServer(routingService *routing.Service) *HTTPServer {
	server := &HTTPServer{
		routing: routingService,
		mux:     http.NewServeMux(),
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

func profileIDFromPath(path string) string {
	const prefix = "/v1/routing/game-profiles/"
	return strings.TrimSpace(strings.TrimPrefix(path, prefix))
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
