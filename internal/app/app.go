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
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/ipc"
	"github.com/tachyon-space/tachyon-core/internal/observability"
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
	client clientRuntime
}

type clientRuntime struct {
	selectiveRoutesSupported func() bool
	newTUN                   func(tun.Options) (tun.Device, error)
	stableInterfaceLUID      func(tun.Device) uint64
	installSelectiveRoutes   func(context.Context, tun.SelectiveRouteOptions) (tun.RouteTransaction, error)
	newPIDTracker            func() (*pidtrack.Tracker, error)
}

// New constructs and validates the application without starting any I/O.
// Any error here is a programming or configuration mistake.
func New(cfg *config.Config, logger *slog.Logger) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &App{
		cfg:    cfg,
		logger: logger,
		mode:   cfg.Mode,
		client: clientRuntime{
			selectiveRoutesSupported: tun.SelectiveRoutesSupported,
			newTUN:                   tun.New,
			stableInterfaceLUID:      tun.StableInterfaceLUID,
			installSelectiveRoutes:   tun.InstallSelectiveRoutes,
			newPIDTracker:            pidtrack.New,
		},
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
	gameRoutes, err := parseGameRoutePrefixes(a.cfg.Client.TUN.GameRoutes)
	if err != nil {
		return err
	}
	if len(gameRoutes) > 0 && !a.client.selectiveRoutesSupported() {
		return fmt.Errorf("install client.tun.game_routes: %w", tun.ErrSelectiveRoutesUnsupported)
	}
	remoteAddr := clientTGPRemoteAddr(a.cfg.Client.Proxy)
	relayAddrs, err := resolveTGPRelayAddresses(ctx, remoteAddr)
	if err != nil {
		return err
	}
	relayPolicy, err := newTGPRelayPolicy(remoteAddr, relayAddrs, gameRoutes)
	if err != nil {
		return err
	}
	plannedRoutes, err := tun.PlanSelectiveRoutes(gameRoutes, relayAddrs)
	if err != nil {
		return fmt.Errorf("validate client.tun.game_routes: %w", err)
	}

	tunDevice, err := a.client.newTUN(tun.Options{
		Name:      a.cfg.Client.TUN.Name,
		Addresses: tunPrefixes,
		MTU:       a.cfg.Client.TUN.MTU,
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
	routeTxn, err := a.client.installSelectiveRoutes(ctx, tun.SelectiveRouteOptions{
		InterfaceName: tunDevice.Name(),
		InterfaceLUID: a.client.stableInterfaceLUID(tunDevice),
		Destinations:  plannedRoutes,
		Excluded:      relayAddrs,
	})
	if err != nil {
		return fmt.Errorf("install selective game routes: %w", err)
	}
	defer func() {
		if err := routeTxn.Close(); err != nil {
			a.logger.Error("rollback selective game routes", "error", err)
		}
	}()
	a.logger.Info("selective game routes ready",
		"destinations", gameRoutes,
		"relay_exclusions", relayAddrs,
	)

	tracker, err := a.client.newPIDTracker()
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

	tgpManager, err := tgp.NewClientManager(tgp.ClientManagerOptions{
		RemoteAddr:       remoteAddr,
		PinnedRemotes:    relayPolicy.Endpoints(),
		LocalAddrs:       clientTGPLocalAddrs(a.cfg.Client.Proxy, a.cfg.TGP.Multipath),
		PacerPPS:         tgpPacerPPS(a.cfg.TGP.Pacing),
		FEC:              tgpFECOptions(a.cfg.TGP.FEC),
		MaxDatagramSize:  a.cfg.TGP.MaxDatagramSize,
		DisableMigration: !a.cfg.TGP.ConnectionMigration,
		AuthKey:          tgpAuthKey(a.cfg.TGP.Auth),
		HandshakeTimeout: a.cfg.TGP.HandshakeTimeout,
		ValidateRemote:   relayPolicy.Validate,
		OnDatagram: func(_ context.Context, datagram tgp.TunnelDatagram) error {
			packet, err := buildUDPPacket(datagram.RemoteAddrPort(), datagram.LocalAddrPort(), datagram.Payload)
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

	var telemetryCollector *observability.Collector
	var telemetryBroadcaster *observability.Broadcaster
	packetPipeline := pipeline.New(pipeline.Options{
		Device:  tunDevice,
		Tracker: tracker,
		Router:  packetRouter,
		Handler: clientPacketHandler{
			logger: a.logger,
			tgp:    tgpManager,
		},
		Logger: a.logger,
		OnDecision: func(d pipeline.Decision) {
			routeEvent := observability.NewRouteEvent(observability.RouteEventData{
				ProcessName: d.Process.Name,
				PID:         uint32(d.Process.PID),
				Src:         fmt.Sprintf("%s:%d", d.Flow.LocalIP, d.Flow.LocalPort),
				Dst:         fmt.Sprintf("%s:%d", d.Flow.RemoteIP, d.Flow.RemotePort),
				Proto:       string(d.Flow.Transport),
				Decision:    string(d.Action),
				RuleMatched: d.Reason,
			})
			if telemetryCollector != nil && telemetryBroadcaster != nil {
				routeEvent.Seq = telemetryCollector.NextSeq()
				telemetryBroadcaster.Broadcast(routeEvent)
			}
		},
	})

	telemetryCollector = observability.NewCollector(packetPipeline, tgpManager)
	telemetryBroadcaster = observability.NewBroadcaster(observability.BroadcasterOptions{
		Collector:         telemetryCollector,
		Logger:            a.logger,
		Version:           "dev",
		ConfigPath:        "",
		TelemetryInterval: time.Duration(a.cfg.IPC.TelemetryIntervalMS) * time.Millisecond,
	})
	go telemetryBroadcaster.Start(ctx)

	ipcHTTP := ipc.NewHTTPServer(ipc.HTTPOptions{
		Routing:     routingService,
		Broadcaster: telemetryBroadcaster,
	})
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
	telemetryBroadcaster.Close()
	shutdownErr := a.shutdownClient(shutdownCtx)
	routeErr := routeTxn.Close()
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
	return errors.Join(runErr, shutdownErr, routeErr)
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

func parseGameRoutePrefixes(raw []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for idx, item := range raw {
		value := strings.TrimSpace(item)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("parse client.tun.game_routes[%d] %q: %w", idx, value, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func resolveTGPRelayAddresses(ctx context.Context, raw string) ([]netip.Addr, error) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse TGP relay address %q: %w", raw, err)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve TGP relay host %q before installing routes: %w", host, err)
	}
	seen := make(map[netip.Addr]struct{}, len(addrs))
	result := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !addr.IsValid() {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		result = append(result, addr)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("TGP relay host %q resolved to no IP addresses", host)
	}
	return result, nil
}

func validateTGPRemoteRoute(remote net.Addr, gameRoutes []netip.Prefix) error {
	udpAddr, ok := remote.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return fmt.Errorf("unsupported TGP relay address type %T", remote)
	}
	addr, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return fmt.Errorf("invalid TGP relay IP %q", udpAddr.IP)
	}
	_, err := tun.PlanSelectiveRoutes(gameRoutes, []netip.Addr{addr.Unmap()})
	return err
}

type tgpRelayPolicy struct {
	approved   map[netip.AddrPort]struct{}
	endpoints  []net.Addr
	gameRoutes []netip.Prefix
}

func newTGPRelayPolicy(raw string, addrs []netip.Addr, gameRoutes []netip.Prefix) (*tgpRelayPolicy, error) {
	_, portRaw, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse TGP relay address %q: %w", raw, err)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("parse TGP relay port %q", portRaw)
	}
	policy := &tgpRelayPolicy{
		approved:   make(map[netip.AddrPort]struct{}, len(addrs)),
		endpoints:  make([]net.Addr, 0, len(addrs)),
		gameRoutes: append([]netip.Prefix(nil), gameRoutes...),
	}
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !addr.IsValid() {
			continue
		}
		endpoint := netip.AddrPortFrom(addr, uint16(port))
		if _, exists := policy.approved[endpoint]; exists {
			continue
		}
		udpAddr := net.UDPAddrFromAddrPort(endpoint)
		if err := validateTGPRemoteRoute(udpAddr, gameRoutes); err != nil {
			return nil, fmt.Errorf("approve TGP relay endpoint %s: %w", endpoint, err)
		}
		policy.approved[endpoint] = struct{}{}
		policy.endpoints = append(policy.endpoints, udpAddr)
	}
	if len(policy.endpoints) == 0 {
		return nil, fmt.Errorf("TGP relay %q has no approved endpoints", raw)
	}
	return policy, nil
}

func (p *tgpRelayPolicy) Endpoints() []net.Addr {
	return append([]net.Addr(nil), p.endpoints...)
}

func (p *tgpRelayPolicy) Validate(remote net.Addr) error {
	if err := validateTGPRemoteRoute(remote, p.gameRoutes); err != nil {
		return err
	}
	udpAddr, ok := remote.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return fmt.Errorf("unsupported TGP relay address type %T", remote)
	}
	addr, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok || udpAddr.Port < 1 || udpAddr.Port > 65535 {
		return fmt.Errorf("invalid TGP relay endpoint %v", remote)
	}
	endpoint := netip.AddrPortFrom(addr.Unmap(), uint16(udpAddr.Port))
	if _, ok := p.approved[endpoint]; !ok {
		return fmt.Errorf("TGP relay endpoint %s is outside the startup-pinned approved set", endpoint)
	}
	return nil
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

func clientTGPLocalAddrs(cfg config.ProxyConfig, multipath bool) []string {
	addrs := make([]string, 0, len(cfg.LocalAddrs))
	for _, addr := range cfg.LocalAddrs {
		if value := strings.TrimSpace(addr); value != "" {
			addrs = append(addrs, value)
		}
	}
	if !multipath && len(addrs) > 1 {
		return addrs[:1]
	}
	return addrs
}

func tgpFECOptions(cfg config.FECConfig) tgp.FECOptions {
	return tgp.FECOptions{
		DataShards:   cfg.DataShards,
		ParityShards: cfg.ParityShards,
		GroupTimeout: cfg.GroupTimeout,
		Dynamic:      cfg.Dynamic,
		AdaptWindow:  cfg.AdaptWindow,
	}
}

func tgpPacerPPS(cfg config.PacingConfig) float64 {
	rate := cfg.InitialRatePPS
	if cfg.MaxRatePPS > 0 && rate > cfg.MaxRatePPS {
		return cfg.MaxRatePPS
	}
	return rate
}

func tgpAuthKey(cfg config.TGPAuthConfig) []byte {
	if value := strings.TrimSpace(cfg.PSK); value != "" {
		return []byte(value)
	}
	return nil
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

	udpRelay := newUDPRelayPoolWithOptions(a.logger, udpRelayPoolOptions{
		DialTimeout:        a.cfg.Server.Relay.DialTimeout,
		IdleTimeout:        a.cfg.Server.Relay.IdleTimeout,
		MaxFlows:           a.cfg.Server.Relay.MaxFlows,
		MaxFlowsPerSession: a.cfg.Server.Relay.MaxFlowsPerSession,
	})
	defer func() {
		if err := udpRelay.Close(); err != nil {
			a.logger.Warn("close UDP relay pool", "error", err)
		}
	}()
	targetACL, err := newTargetACL(a.cfg.Server.Relay.AllowedTargets)
	if err != nil {
		return fmt.Errorf("create relay target ACL: %w", err)
	}

	tgpRelay, err := tgp.NewRelay(tgp.RelayOptions{
		ListenAddr:         a.cfg.Server.Listen,
		PacerPPS:           tgpPacerPPS(a.cfg.TGP.Pacing),
		FEC:                tgpFECOptions(a.cfg.TGP.FEC),
		MaxDatagramSize:    a.cfg.TGP.MaxDatagramSize,
		DisableMigration:   !a.cfg.TGP.ConnectionMigration,
		AuthKey:            tgpAuthKey(a.cfg.TGP.Auth),
		SessionIdleTimeout: a.cfg.TGP.SessionIdleTimeout,
		MaxSessions:        a.cfg.Server.Relay.MaxSessions,
		SessionQueueSize:   a.cfg.Server.Relay.SessionQueueSize,
		HandlerConcurrency: a.cfg.Server.Relay.HandlerConcurrency,
		Handler: serverRelayHandler{
			logger: a.logger,
			relay:  udpRelay,
			acl:    targetACL,
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
