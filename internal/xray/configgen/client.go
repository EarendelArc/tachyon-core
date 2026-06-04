package configgen

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

const DefaultClientSOCKSAddr = "127.0.0.1:10808"

type ClientOptions struct {
	SOCKSAddr  string
	ServerAddr string
	VLESSUID   string
	SNI        string
}

func BuildClientConfig(opts ClientOptions) ([]byte, error) {
	socksHost, socksPort, err := splitHostPort(opts.SOCKSAddr, DefaultClientSOCKSAddr)
	if err != nil {
		return nil, fmt.Errorf("parse socks addr: %w", err)
	}
	serverHost, serverPort, err := splitHostPort(opts.ServerAddr, "")
	if err != nil {
		return nil, fmt.Errorf("parse server addr: %w", err)
	}
	if opts.VLESSUID == "" {
		return nil, fmt.Errorf("vless uuid is required")
	}
	sni := opts.SNI
	if sni == "" {
		sni = serverHost
	}

	cfg := map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
		},
		"inbounds": []any{
			map[string]any{
				"tag":      "tachyon-socks",
				"listen":   socksHost,
				"port":     socksPort,
				"protocol": "socks",
				"settings": map[string]any{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": []any{
			map[string]any{
				"tag":      "tachyon-proxy",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": serverHost,
							"port":    serverPort,
							"users": []any{
								map[string]any{
									"id":         opts.VLESSUID,
									"encryption": "none",
									"flow":       "xtls-rprx-vision",
								},
							},
						},
					},
				},
				"streamSettings": map[string]any{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": map[string]any{
						"serverName":  sni,
						"fingerprint": "chrome",
					},
				},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func splitHostPort(raw string, fallback string) (string, int, error) {
	if raw == "" {
		raw = fallback
	}
	if raw == "" {
		return "", 0, fmt.Errorf("address is required")
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, err
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range: %d", port)
	}
	return host, port, nil
}
