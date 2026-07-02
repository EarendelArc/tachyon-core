package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

var ErrRelayTargetDenied = errors.New("udp relay target denied by ACL")
var ErrUDPRelayFlowLimit = errors.New("udp relay flow limit reached")

type gameUDPRelay interface {
	ForwardUDP(ctx context.Context, packet tgp.RelayPacket, datagram tgp.TunnelDatagram) error
}

type serverRelayHandler struct {
	logger *slog.Logger
	relay  gameUDPRelay
	acl    *targetACL
}

func (h serverRelayHandler) HandleRelayPacket(ctx context.Context, packet tgp.RelayPacket) error {
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}

	datagram, err := tgp.ParseTunnelDatagram(packet.Payload)
	if err != nil {
		return err
	}
	target := datagram.RemoteAddrPort()
	if h.acl == nil || !h.acl.Allows(target) {
		return fmt.Errorf("%w: %s", ErrRelayTargetDenied, target)
	}
	if h.relay != nil {
		if err := h.relay.ForwardUDP(ctx, packet, datagram); err != nil {
			return err
		}
	}
	logger.Debug("TGP relay forwarded UDP payload",
		"session", packet.SessionID,
		"target", target,
		"bytes", len(datagram.Payload),
	)
	return nil
}

type targetACL struct {
	rules []targetACLRule
}

type targetACLRule struct {
	prefixes []netip.Prefix
	ports    []portRange
}

type portRange struct {
	start uint16
	end   uint16
}

func newTargetACL(rules []config.RelayTargetRule) (*targetACL, error) {
	acl := &targetACL{}
	for idx, rule := range rules {
		compiled := targetACLRule{
			ports: []portRange{{start: 1, end: 65535}},
		}
		if value := strings.TrimSpace(rule.CIDR); value != "" {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("server.relay.allowed_targets[%d].cidr: %w", idx, err)
			}
			if prefix.Bits() == 0 {
				return nil, fmt.Errorf("server.relay.allowed_targets[%d].cidr must not allow the whole internet", idx)
			}
			compiled.prefixes = append(compiled.prefixes, prefix.Masked())
		}
		if value := strings.TrimSpace(rule.Domain); value != "" {
			prefixes, err := resolveACLDomain(value)
			if err != nil {
				return nil, fmt.Errorf("server.relay.allowed_targets[%d].domain: %w", idx, err)
			}
			compiled.prefixes = append(compiled.prefixes, prefixes...)
		}
		if strings.TrimSpace(rule.Ports) == "" {
			return nil, fmt.Errorf("server.relay.allowed_targets[%d].ports is required", idx)
		}
		ports, err := parseACLPortRanges(rule.Ports)
		if err != nil {
			return nil, fmt.Errorf("server.relay.allowed_targets[%d].ports: %w", idx, err)
		}
		compiled.ports = ports
		if len(compiled.prefixes) == 0 {
			return nil, fmt.Errorf("server.relay.allowed_targets[%d] requires cidr or resolvable domain", idx)
		}
		acl.rules = append(acl.rules, compiled)
	}
	return acl, nil
}

func (a *targetACL) Allows(target netip.AddrPort) bool {
	if a == nil || !target.IsValid() || len(a.rules) == 0 {
		return false
	}
	for _, rule := range a.rules {
		if !rule.portAllowed(target.Port()) {
			continue
		}
		for _, prefix := range rule.prefixes {
			if prefix.Contains(target.Addr()) {
				return true
			}
		}
	}
	return false
}

func (r targetACLRule) portAllowed(port uint16) bool {
	for _, item := range r.ports {
		if port >= item.start && port <= item.end {
			return true
		}
	}
	return false
}

func resolveACLDomain(domain string) ([]netip.Prefix, error) {
	if addr, err := netip.ParseAddr(domain); err == nil {
		return []netip.Prefix{addrPrefix(addr)}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		prefixes = append(prefixes, addrPrefix(addr))
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no A/AAAA records for %q", domain)
	}
	return prefixes, nil
}

func addrPrefix(addr netip.Addr) netip.Prefix {
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32)
	}
	return netip.PrefixFrom(addr, 128)
}

func parseACLPortRanges(raw string) ([]portRange, error) {
	var ranges []portRange
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			return nil, fmt.Errorf("empty port range")
		}
		bounds := strings.Split(item, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid range %q", item)
		}
		start, err := parseACLPort(bounds[0])
		if err != nil {
			return nil, err
		}
		end := start
		if len(bounds) == 2 {
			end, err = parseACLPort(bounds[1])
			if err != nil {
				return nil, err
			}
		}
		if start > end {
			return nil, fmt.Errorf("range %q has start greater than end", item)
		}
		ranges = append(ranges, portRange{start: start, end: end})
	}
	return ranges, nil
}

func parseACLPort(raw string) (uint16, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid UDP port %q", raw)
	}
	return uint16(port), nil
}

type udpRelayPool struct {
	logger             *slog.Logger
	dialTimeout        time.Duration
	idleTimeout        time.Duration
	sendTimeout        time.Duration
	maxFlows           int
	maxFlowsPerSession int

	mu                sync.Mutex
	flows             map[udpRelayKey]*udpRelayFlow
	flowCounts        map[tgp.SessionID]int
	pendingFlows      int
	pendingFlowCounts map[tgp.SessionID]int
	closed            bool
}

type udpRelayPoolOptions struct {
	DialTimeout        time.Duration
	IdleTimeout        time.Duration
	MaxFlows           int
	MaxFlowsPerSession int
}

type udpRelayKey struct {
	sessionID tgp.SessionID
	local     netip.AddrPort
	remote    netip.AddrPort
}

type udpRelayFlow struct {
	pool        *udpRelayPool
	key         udpRelayKey
	conn        net.Conn
	session     tgp.Session
	idleTimeout time.Duration
	sendTimeout time.Duration
	closeOnce   sync.Once
}

func newUDPRelayPool(logger *slog.Logger, dialTimeout time.Duration, idleTimeout time.Duration) *udpRelayPool {
	return newUDPRelayPoolWithOptions(logger, udpRelayPoolOptions{
		DialTimeout: dialTimeout,
		IdleTimeout: idleTimeout,
	})
}

func newUDPRelayPoolWithOptions(logger *slog.Logger, opts udpRelayPoolOptions) *udpRelayPool {
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	maxFlows := opts.MaxFlows
	if maxFlows <= 0 {
		maxFlows = 4096
	}
	maxFlowsPerSession := opts.MaxFlowsPerSession
	if maxFlowsPerSession <= 0 {
		maxFlowsPerSession = 256
	}
	return &udpRelayPool{
		logger:             logger,
		dialTimeout:        dialTimeout,
		idleTimeout:        idleTimeout,
		sendTimeout:        dialTimeout,
		maxFlows:           maxFlows,
		maxFlowsPerSession: maxFlowsPerSession,
		flows:              make(map[udpRelayKey]*udpRelayFlow),
		flowCounts:         make(map[tgp.SessionID]int),
		pendingFlowCounts:  make(map[tgp.SessionID]int),
	}
}

func (p *udpRelayPool) ForwardUDP(ctx context.Context, packet tgp.RelayPacket, datagram tgp.TunnelDatagram) error {
	if packet.Session == nil {
		return errors.New("tgp relay packet has no session")
	}
	key := udpRelayKey{
		sessionID: packet.SessionID,
		local:     datagram.LocalAddrPort(),
		remote:    datagram.RemoteAddrPort(),
	}
	flow, err := p.flow(ctx, key, packet.Session)
	if err != nil {
		return err
	}
	return flow.write(ctx, datagram.Payload)
}

func (p *udpRelayPool) flow(ctx context.Context, key udpRelayKey, session tgp.Session) (*udpRelayFlow, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("udp relay pool is closed")
	}
	if flow := p.flows[key]; flow != nil {
		p.mu.Unlock()
		return flow, nil
	}
	if !p.reserveFlowLocked(key.sessionID) {
		p.mu.Unlock()
		return nil, fmt.Errorf("%w: session=%x remote=%s", ErrUDPRelayFlowLimit, key.sessionID, key.remote)
	}
	p.mu.Unlock()
	reserved := true
	defer func() {
		if reserved {
			p.releaseReservedFlow(key.sessionID)
		}
	}()

	dialCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		dialCtx, cancel = context.WithTimeout(ctx, p.dialTimeout)
	}
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", key.remote.String())
	if err != nil {
		return nil, fmt.Errorf("dial game udp %s: %w", key.remote, err)
	}
	created := &udpRelayFlow{
		pool:        p,
		key:         key,
		conn:        conn,
		session:     session,
		idleTimeout: p.idleTimeout,
		sendTimeout: p.sendTimeout,
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseReservedFlowLocked(key.sessionID)
	reserved = false
	if p.closed {
		_ = created.close()
		return nil, errors.New("udp relay pool is closed")
	}
	if existing := p.flows[key]; existing != nil {
		_ = created.close()
		return existing, nil
	}
	if !p.flowLimitAllowsLocked(key.sessionID) {
		_ = created.close()
		return nil, fmt.Errorf("%w: session=%x remote=%s", ErrUDPRelayFlowLimit, key.sessionID, key.remote)
	}
	p.flows[key] = created
	p.flowCounts[key.sessionID]++
	go created.readLoop()
	return created, nil
}

func (p *udpRelayPool) reserveFlowLocked(sessionID tgp.SessionID) bool {
	if !p.flowLimitAllowsWithPendingLocked(sessionID) {
		return false
	}
	p.pendingFlows++
	p.pendingFlowCounts[sessionID]++
	return true
}

func (p *udpRelayPool) releaseReservedFlow(sessionID tgp.SessionID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseReservedFlowLocked(sessionID)
}

func (p *udpRelayPool) releaseReservedFlowLocked(sessionID tgp.SessionID) {
	if p.pendingFlows > 0 {
		p.pendingFlows--
	}
	if count := p.pendingFlowCounts[sessionID]; count <= 1 {
		delete(p.pendingFlowCounts, sessionID)
	} else {
		p.pendingFlowCounts[sessionID] = count - 1
	}
}

func (p *udpRelayPool) flowLimitAllowsWithPendingLocked(sessionID tgp.SessionID) bool {
	if p.maxFlows > 0 && len(p.flows)+p.pendingFlows >= p.maxFlows {
		return false
	}
	if p.maxFlowsPerSession > 0 && p.flowCounts[sessionID]+p.pendingFlowCounts[sessionID] >= p.maxFlowsPerSession {
		return false
	}
	return true
}

func (p *udpRelayPool) flowLimitAllowsLocked(sessionID tgp.SessionID) bool {
	if p.maxFlows > 0 && len(p.flows) >= p.maxFlows {
		return false
	}
	if p.maxFlowsPerSession > 0 && p.flowCounts[sessionID] >= p.maxFlowsPerSession {
		return false
	}
	return true
}

func (p *udpRelayPool) remove(key udpRelayKey, flow *udpRelayFlow) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.flows[key] == flow {
		delete(p.flows, key)
		if count := p.flowCounts[key.sessionID]; count <= 1 {
			delete(p.flowCounts, key.sessionID)
		} else {
			p.flowCounts[key.sessionID] = count - 1
		}
	}
}

func (p *udpRelayPool) Close() error {
	p.mu.Lock()
	flows := make([]*udpRelayFlow, 0, len(p.flows))
	for _, flow := range p.flows {
		flows = append(flows, flow)
	}
	p.flows = make(map[udpRelayKey]*udpRelayFlow)
	p.flowCounts = make(map[tgp.SessionID]int)
	p.pendingFlows = 0
	p.pendingFlowCounts = make(map[tgp.SessionID]int)
	p.closed = true
	p.mu.Unlock()

	for _, flow := range flows {
		_ = flow.close()
	}
	return nil
}

func (f *udpRelayFlow) write(ctx context.Context, payload []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = f.conn.SetWriteDeadline(deadline)
	} else if f.sendTimeout > 0 {
		_ = f.conn.SetWriteDeadline(time.Now().Add(f.sendTimeout))
	}
	if _, err := f.conn.Write(payload); err != nil {
		return fmt.Errorf("write game udp %s: %w", f.key.remote, err)
	}
	return nil
}

func (f *udpRelayFlow) readLoop() {
	defer func() {
		f.pool.remove(f.key, f)
		_ = f.close()
	}()

	buf := make([]byte, 65535)
	for {
		if f.idleTimeout > 0 {
			_ = f.conn.SetReadDeadline(time.Now().Add(f.idleTimeout))
		}
		n, err := f.conn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return
			}
			if f.pool.logger != nil {
				f.pool.logger.Debug("UDP relay read loop ended", "target", f.key.remote, "error", err)
			}
			return
		}
		if n == 0 {
			continue
		}
		if err := f.sendResponse(buf[:n]); err != nil {
			if f.pool.logger != nil {
				f.pool.logger.Debug("UDP relay response send failed", "target", f.key.remote, "error", err)
			}
			return
		}
	}
}

func (f *udpRelayFlow) sendResponse(payload []byte) error {
	responsePayload, err := tgp.MarshalTunnelDatagram(tgp.TunnelDatagram{
		LocalIP:    f.key.local.Addr(),
		LocalPort:  f.key.local.Port(),
		RemoteIP:   f.key.remote.Addr(),
		RemotePort: f.key.remote.Port(),
		Payload:    append([]byte(nil), payload...),
	})
	if err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(context.Background(), f.sendTimeout)
	defer cancel()
	return f.session.SendPacket(sendCtx, capturedPacketStream, responsePayload)
}

func (f *udpRelayFlow) close() error {
	var err error
	f.closeOnce.Do(func() {
		err = f.conn.Close()
	})
	return err
}
