package observability

import (
	"encoding/json"
	"testing"
)

func TestNewHelloEvent(t *testing.T) {
	event := NewHello("0.1.0", "/path/to/config.json")
	if event.Type != EventHello {
		t.Fatalf("expected type hello, got %q", event.Type)
	}
	if event.TS == "" {
		t.Fatal("expected non-empty timestamp")
	}
	data, ok := event.Data.(HelloData)
	if !ok {
		t.Fatalf("expected HelloData, got %T", event.Data)
	}
	if data.Version != "0.1.0" {
		t.Fatalf("expected version 0.1.0, got %q", data.Version)
	}
	if data.ConfigPath != "/path/to/config.json" {
		t.Fatalf("expected config path, got %q", data.ConfigPath)
	}
	if data.Platform == "" {
		t.Fatal("expected non-empty platform")
	}
}

func TestNewTelemetryEvent(t *testing.T) {
	data := TelemetryData{
		PacketsRead:   100,
		DecidedTGP:    60,
		DecidedDirect: 30,
		DecidedDrop:   10,
		Goroutines:    42,
	}
	event := NewTelemetry(data)
	if event.Type != EventTelemetry {
		t.Fatalf("expected type telemetry, got %q", event.Type)
	}
	td, ok := event.Data.(TelemetryData)
	if !ok {
		t.Fatalf("expected TelemetryData, got %T", event.Data)
	}
	if td.PacketsRead != 100 {
		t.Fatalf("expected 100 packets, got %d", td.PacketsRead)
	}
	if td.Goroutines != 42 {
		t.Fatalf("expected 42 goroutines, got %d", td.Goroutines)
	}
}

func TestNewRouteEvent(t *testing.T) {
	event := NewRouteEvent(RouteEventData{
		ProcessName: "cs2.exe",
		PID:         1234,
		Src:         "198.18.0.2:57392",
		Dst:         "162.254.195.4:27015",
		Proto:       "udp",
		Decision:    "tgp",
		RuleMatched: "process:cs2.exe",
	})
	if event.Type != EventRouteEvent {
		t.Fatalf("expected type route_event, got %q", event.Type)
	}
	re, ok := event.Data.(RouteEventData)
	if !ok {
		t.Fatalf("expected RouteEventData, got %T", event.Data)
	}
	if re.ProcessName != "cs2.exe" {
		t.Fatalf("expected cs2.exe, got %q", re.ProcessName)
	}
	if re.Decision != "tgp" {
		t.Fatalf("expected tgp decision, got %q", re.Decision)
	}
}

func TestNewTGPSessionEvent(t *testing.T) {
	event := NewTGPSessionEvent("opened", "1.2.3.4:443")
	if event.Type != EventTGPSession {
		t.Fatalf("expected type tgp_session, got %q", event.Type)
	}
	se, ok := event.Data.(TGPSessionEvent)
	if !ok {
		t.Fatalf("expected TGPSessionEvent, got %T", event.Data)
	}
	if se.State != "opened" {
		t.Fatalf("expected state opened, got %q", se.State)
	}
	if se.Remote != "1.2.3.4:443" {
		t.Fatalf("expected remote 1.2.3.4:443, got %q", se.Remote)
	}
}

func TestNewErrorEvent(t *testing.T) {
	event := NewErrorEvent("something failed", "pipeline")
	if event.Type != EventError {
		t.Fatalf("expected type error, got %q", event.Type)
	}
	ed, ok := event.Data.(ErrorData)
	if !ok {
		t.Fatalf("expected ErrorData, got %T", event.Data)
	}
	if ed.Message != "something failed" {
		t.Fatalf("expected message, got %q", ed.Message)
	}
	if ed.Source != "pipeline" {
		t.Fatalf("expected source pipeline, got %q", ed.Source)
	}
}

func TestEventJSONRoundTrip(t *testing.T) {
	event := NewHello("0.1.0", "")
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Type != EventHello {
		t.Fatalf("expected type hello after round-trip, got %q", decoded.Type)
	}
}

func TestEventTypeConstants(t *testing.T) {
	if EventHello != "hello" {
		t.Fatalf("EventHello = %q", EventHello)
	}
	if EventTelemetry != "telemetry" {
		t.Fatalf("EventTelemetry = %q", EventTelemetry)
	}
	if EventRouteEvent != "route_event" {
		t.Fatalf("EventRouteEvent = %q", EventRouteEvent)
	}
	if EventTGPSession != "tgp_session" {
		t.Fatalf("EventTGPSession = %q", EventTGPSession)
	}
	if EventError != "error" {
		t.Fatalf("EventError = %q", EventError)
	}
}
