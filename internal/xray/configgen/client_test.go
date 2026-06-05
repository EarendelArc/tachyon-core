package configgen

import (
	"encoding/json"
	"testing"
)

func TestBuildClientConfig(t *testing.T) {
	data, err := BuildClientConfig(ClientOptions{
		ServerAddr: "vpn.example.com:443",
		VLESSUID:   "00000000-0000-0000-0000-000000000000",
		SNI:        "front.example.com",
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode generated json: %v", err)
	}
	inbounds := cfg["inbounds"].([]any)
	socks := inbounds[0].(map[string]any)
	if socks["protocol"] != "socks" || socks["listen"] != "127.0.0.1" || socks["port"].(float64) != 10808 {
		t.Fatalf("unexpected socks inbound: %#v", socks)
	}
	outbounds := cfg["outbounds"].([]any)
	proxy := outbounds[0].(map[string]any)
	if proxy["protocol"] != "vless" {
		t.Fatalf("unexpected outbound: %#v", proxy)
	}
	settings := proxy["settings"].(map[string]any)
	if settings["address"] != "vpn.example.com" ||
		settings["port"].(float64) != 443 ||
		settings["id"] != "00000000-0000-0000-0000-000000000000" ||
		settings["encryption"] != "none" {
		t.Fatalf("unexpected vless settings: %#v", settings)
	}
	if _, ok := settings["vnext"]; ok {
		t.Fatalf("unexpected legacy vnext settings: %#v", settings)
	}
	stream := proxy["streamSettings"].(map[string]any)
	if stream["network"] != "raw" || stream["security"] != "tls" {
		t.Fatalf("unexpected stream settings: %#v", stream)
	}
	tls := stream["tlsSettings"].(map[string]any)
	if tls["serverName"] != "front.example.com" {
		t.Fatalf("unexpected tls settings: %#v", tls)
	}
}

func TestBuildClientConfigRequiresUUID(t *testing.T) {
	_, err := BuildClientConfig(ClientOptions{ServerAddr: "vpn.example.com:443"})
	if err == nil {
		t.Fatal("expected missing uuid error")
	}
}
