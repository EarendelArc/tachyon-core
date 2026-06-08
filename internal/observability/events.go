// Package observability implements the real-time telemetry stream from
// Tachyon Core to Prism.
//
// The telemetry stream is served as Server-Sent Events (SSE) over the existing
// HTTP bridge at /v1/telemetry/sse. No external dependencies are required.
//
// Event types match the IPC API spec:
//   - hello       Core version, platform, config path
//   - telemetry   Packet counters, TGP session metrics, resource usage
//   - route_event Game routing decision for a flow
//   - tgp_session TGP session opened, closed, or migrated
//   - error       Non-fatal Core error
package observability

import (
	"fmt"
	"runtime"
	"time"
)

// EventType identifies the kind of telemetry event.
type EventType string

const (
	EventHello      EventType = "hello"
	EventTelemetry  EventType = "telemetry"
	EventRouteEvent EventType = "route_event"
	EventTGPSession EventType = "tgp_session"
	EventError      EventType = "error"
)

// Event is the envelope for all telemetry events.
type Event struct {
	Type EventType   `json:"type"`
	Seq  uint64      `json:"seq"`
	TS   string      `json:"ts"`
	Data interface{} `json:"data"`
}

// HelloData is sent once when a client connects.
type HelloData struct {
	Version    string `json:"version"`
	Platform   string `json:"platform"`
	ConfigPath string `json:"config_path,omitempty"`
}

// TelemetryData contains periodic pipeline and session metrics.
type TelemetryData struct {
	PacketsRead   uint64  `json:"packets_read"`
	Unsupported   uint64  `json:"unsupported"`
	LookupErrors  uint64  `json:"lookup_errors"`
	DecidedTGP    uint64  `json:"decided_tgp"`
	DecidedDirect uint64  `json:"decided_direct"`
	DecidedDrop   uint64  `json:"decided_drop"`
	HandlerErrors uint64  `json:"handler_errors"`
	TGPSessions   int     `json:"tgp_sessions"`
	Goroutines    int     `json:"goroutines"`
}

// RouteEventData describes a single routing decision.
type RouteEventData struct {
	ProcessName string `json:"process_name"`
	PID         uint32 `json:"pid,omitempty"`
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	Proto       string `json:"proto"`
	Decision    string `json:"decision"`
	RuleMatched string `json:"rule_matched"`
}

// TGPSessionEvent describes a TGP session lifecycle change.
type TGPSessionEvent struct {
	State   string `json:"state"` // "opened", "closed", "migrated"
	Remote  string `json:"remote"`
	Session string `json:"session,omitempty"`
}

// ErrorData describes a non-fatal Core error.
type ErrorData struct {
	Message string `json:"message"`
	Source  string `json:"source,omitempty"`
}

// NewHello creates a hello event.
func NewHello(version, configPath string) Event {
	return Event{
		Type: EventHello,
		TS:   nowISO(),
		Data: HelloData{
			Version:    version,
			Platform:   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			ConfigPath: configPath,
		},
	}
}

// NewTelemetry creates a telemetry snapshot event.
func NewTelemetry(data TelemetryData) Event {
	return Event{
		Type: EventTelemetry,
		TS:   nowISO(),
		Data: data,
	}
}

// NewRouteEvent creates a route decision event.
func NewRouteEvent(data RouteEventData) Event {
	return Event{
		Type: EventRouteEvent,
		TS:   nowISO(),
		Data: data,
	}
}

// NewTGPSessionEvent creates a TGP session lifecycle event.
func NewTGPSessionEvent(state, remote string) Event {
	return Event{
		Type: EventTGPSession,
		TS:   nowISO(),
		Data: TGPSessionEvent{
			State:  state,
			Remote: remote,
		},
	}
}

// NewErrorEvent creates a non-fatal error event.
func NewErrorEvent(message, source string) Event {
	return Event{
		Type: EventError,
		TS:   nowISO(),
		Data: ErrorData{
			Message: message,
			Source:  source,
		},
	}
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
