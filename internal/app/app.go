// Package app is the dependency-injection root of tachyon-core.
//
// It wires together all internal subsystems and hands them off to either the
// client runner or the server runner depending on the configured mode.
//
// Startup order (client mode):
//  1. Observability (metrics endpoint, logger)
//  2. TUN device creation
//  3. PID tracker
//  4. Routing engine (loads rules)
//  5. IPC server for Prism control
//  6. TGP client session
//  7. TUN pipeline starts forwarding game UDP packets
//
// Startup order (server mode):
//  1. Observability
//  2. TGP relay
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/ipc"
	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/pipeline"
	"github.com/tachyon-space/tachyon-core/internal/routing"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
	"github.com/tachyon-space/tachyon-core/internal/tun"
)

// App is the fully wired application. Callers obtain one via New and then
// call Run to block until the context is cancelled.
type App struct {
	cfg    *config.Config
	logger *slog.Logger
	mode   config.Mode
}

// New constructs and validates the application without starting any I/O.
// Any error here is a programming or configuration mistake.
func New(cfg *config.Config, logger *slog.Logger) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must not be nil")
	}
	return &App{
		cfg:    cfg,
		logger: logger,
		mode:   cfg.Mode,
	}, nil
}

// Run starts the application and blocks until ctx is cancelled.
// It is the responsibility of the caller to cancel ctx on shutdown signals.
func (a *App) Run(ctx context.Context) error {
	switch a.mode {
	case config.ModeClient:
		return a.runClient(ctx)
	case config.ModeServer:
		return a.runServer(ctx)
	default:
		return fmt.Errorf("unknown mode: %q", a.mode)
	}
}

// ---------------------------------------------------------------------------
// Client mode
// ---------------------------------------------------------------------------

func (a *App) runClient(ctx context.Context) error {
	a.logger.Info("starting in client mode")

	tunPrefixes, err := parseTUNPrefixes(a.cfg.Client.TUN.Address)
	if err != nil {
		return err
	}

	tunDevice, err := tun.New(tun.Options{
		Name:      a.cfg.Client.TUN.Name,
		Addresses: tunPrefixes,
		MTU:       a.cfg.Client.TUN.MTU,
		AutoRoute: a.cfg.Client.TUN.AutoRoute,
		DNSHijack: a.cfg.Client.TUN.DNSHijack,
	})
	if err != nil {
		return fmt.Errorf("create TUN device: %w", err)
	}
	defer func() {
		if err := tunDevice.Close(); err != nil {
			a.logger.Warn("close TUN device", "error", err)
		}
	}()
	a.logger.Info("TUN device ready",
		"name", tunDevice.Name(),
		"addresses", tunDevice.Addresses(),
		"mtu", tunDevice.MTU(),
	)

	tracker, err := pidtrack.New()
	if err != nil {
		return fmt.Errorf("create PID tracker: %w", err)
	}
	a.logger.Info("PID tracker ready")

	routingService := routing.NewService(routing.NewMemoryStore(routingRuntimeConfig(a.cfg.Client.Routing)))
	gameEngine, err := routingService.Engine(ctx)
	if err != nil {
		return fmt.Errorf("load routing profiles: %w", err)
	}
	packetRouter := pipeline.NewRouter(a.cfg.Client.Routing, gameEngine)
	a.logger.Info("routing engine ready", "profiles", len(gameEngine.Profiles), "config_rules", len(a.cfg.Client.Routing.Rules))

	ipcHTTP := ipc.NewHTTPServer(routingService)
	httpServer := &http.Server{
		Addr:              clientHTTPAddr(a.cfg.IPC),
		Handler:           ipcHTTP.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 3)
	go func() {
		a.logger.Info("IPC HTTP bridge listening", "addr", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("IPC HTTP bridge: %w", err)
		}
	}()

	go refreshRoutingEngine(ctx, routingService, packetRouter, a.logger)

	tgpManager, err := tgp.NewClientManager(tgp.ClientManagerOptions{
		RemoteAddr:       clientTGPRemoteAddr(a.cfg.Client.Proxy),
		PacerPPS:         a.cfg.TGP.Pacing.InitialRatePPS,
		HandshakeTimeout: a.cfg.TGP.HandshakeTimeout,
		OnDatagram: func(_ context.Context, datagram tgp.TunnelDatagram) error {
			packet, err := buildIPv4UDPPacket(datagram.RemoteAddrPort(), datagram.LocalAddrPort(), datagram.Payload)
			if err != nil {
				return err
			}
			return tunDevice.WritePacket(packet)
		},
	})
	if err != nil {
		return fmt.Errorf("create TGP client manager: %w", err)
	}
	defer func() {
		if err := tgpManager.Close(); err != nil {
			a.logger.Warn("close TGP client manager", "error", err)
		}
	}()

	packetPipeline := pipeline.New(pipeline.Options{
		Device:  tunDevice,
		Tracker: tracker,
		Router:  packetRouter,
		Handler: clientPacketHandler{
			logger: a.logger,
			tgp:    tgpManager,
		},
		Logger: a.logger,
	})
	go func() {
		a.logger.Info("TUN packet pipeline running")
		if err := packetPipeline.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("packet pipeline: %w", err)
		}
	}()

	a.logger.Info("client subsystems initialised, waiting for shutdown signal")
	var runErr error
	select {
	case <-ctx.Done():
		a.logger.Info("client shutdown initiated", "reason", ctx.Err())
	case runErr = <-errCh:
		a.logger.Error("client subsystem failed", "error", runErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		a.logger.Warn("shutdown IPC HTTP bridge", "error", err)
	}
	if err := a.shutdownClient(shutdownCtx); err != nil {
		return err
	}
	if stats := packetPipeline.Snapshot(); stats.PacketsRead > 0 {
		a.logger.Info("packet pipeline stopped",
			"packets", stats.PacketsRead,
			"unsupported", stats.Unsupported,
			"lookup_errors", stats.LookupErrors,
			"tgp", stats.DecidedTGP,
			"direct", stats.DecidedDirect,
			"drop", stats.DecidedDrop,
		)
	}
	return runErr
}

func (a *App) shutdownClient(ctx context.Context) error {
	a.logger.Info("shutting down client subsystems")
	// Subsystem-owned resources are closed by the defers registered in runClient.
	_ = ctx
	a.logger.Info("client shutdown complete")
	return nil
}

func parseTUNPrefixes(raw string) ([]netip.Prefix, error) {
	parts := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("parse client.tun.address %q: %w", value, err)
		}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("client.tun.address must contain at least one CIDR prefix")
	}
	return prefixes, nil
}

func clientHTTPAddr(cfg config.IPCConfig) string {
	if value := strings.TrimSpace(os.Getenv("TACHYON_HTTP_ADDR")); value != "" {
		return value
	}
	if value := strings.TrimSpace(cfg.WebSocketAddr); value != "" {
		return value
	}
	return "127.0.0.1:55123"
}

func clientTGPRemoteAddr(cfg config.ProxyConfig) string {
	if value := strings.TrimSpace(cfg.TGPServerAddr); value != "" {
		return value
	}
	return strings.TrimSpace(cfg.ServerAddr)
}

func defaultRoutingStorePath() string {
	if value := strings.TrimSpace(os.Getenv("TACHYON_ROUTING_STORE")); value != "" {
		return value
	}
	if dir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "tachyon", "routing.json")
	}
	return filepath.Join(".", "tachyon-routing.json")
}

func routingRuntimeConfig(cfg config.RoutingConfig) routing.Config {
	runtimeCfg := routing.DefaultConfig()
	if cfg.GameProfiles != nil {
		runtimeCfg.GameProfiles = append([]routing.GameProfile(nil), cfg.GameProfiles...)
	}
	if cfg.Launchers != nil {
		runtimeCfg.Launchers = *cfg.Launchers
	}
	return runtimeCfg
}

func refreshRoutingEngine(ctx context.Context, service *routing.Service, router *pipeline.Router, logger *slog.Logger) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			engine, err := service.Engine(ctx)
			if err != nil {
				logger.Warn("refresh routing engine", "error", err)
				continue
			}
			router.SetGameEngine(engine)
		}
	}
}

// ---------------------------------------------------------------------------
// Server mode
// ---------------------------------------------------------------------------

func (a *App) runServer(ctx context.Context) error {
	a.logger.Info("starting in server mode", "listen", a.cfg.Server.Listen)

	tgpRelay, err := tgp.NewRelay(tgp.RelayOptions{
		ListenAddr: a.cfg.Server.Listen,
		PacerPPS:   a.cfg.TGP.Pacing.InitialRatePPS,
		Handler: serverRelayHandler{
			logger: a.logger,
			forwarder: netUDPForwarder{
				timeout: a.cfg.Server.Relay.DialTimeout,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create TGP relay: %w", err)
	}
	defer func() {
		if err := tgpRelay.Close(); err != nil {
			a.logger.Warn("close TGP relay", "error", err)
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		a.logger.Info("TGP relay listening", "addr", a.cfg.Server.Listen)
		if err := tgpRelay.ListenAndServe(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("TGP relay: %w", err)
		}
	}()

	a.logger.Info("server subsystems initialised, waiting for shutdown signal")
	var runErr error
	select {
	case <-ctx.Done():
		a.logger.Info("server shutdown initiated", "reason", ctx.Err())
	case runErr = <-errCh:
		a.logger.Error("server subsystem failed", "error", runErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := tgpRelay.Close(); err != nil {
		a.logger.Warn("shutdown TGP relay", "error", err)
	}
	if err := a.shutdownServer(shutdownCtx); err != nil {
		return err
	}
	return runErr
}

func (a *App) shutdownServer(ctx context.Context) error {
	a.logger.Info("shutting down server subsystems")
	_ = ctx
	a.logger.Info("server shutdown complete")
	return nil
}
