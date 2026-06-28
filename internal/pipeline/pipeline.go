package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/tachyon-space/tachyon-core/internal/pidtrack"
	"github.com/tachyon-space/tachyon-core/internal/tun"
)

type Tracker interface {
	LookupFlow(ctx context.Context, flow pidtrack.FlowKey) (pidtrack.ProcessInfo, error)
}

type Handler interface {
	HandlePacket(ctx context.Context, decision Decision, packet []byte) error
}

type HandlerFunc func(ctx context.Context, decision Decision, packet []byte) error

func (f HandlerFunc) HandlePacket(ctx context.Context, decision Decision, packet []byte) error {
	return f(ctx, decision, packet)
}

type Stats struct {
	PacketsRead   uint64
	BytesRead     uint64
	BytesTGP      uint64
	BytesDirect   uint64
	BytesDrop     uint64
	Unsupported   uint64
	LookupErrors  uint64
	DecidedTGP    uint64
	DecidedDirect uint64
	DecidedDrop   uint64
	HandlerErrors uint64
}

type Pipeline struct {
	device     tun.Device
	tracker    Tracker
	router     *Router
	handler    Handler
	logger     *slog.Logger
	onDecision DecisionCallback
	stats      Stats
}

// DecisionCallback is called after each routing decision with the flow,
// process info, and chosen action. Implementations must be fast and
// non-blocking since it runs on the hot packet path.
type DecisionCallback func(decision Decision)

type Options struct {
	Device  tun.Device
	Tracker Tracker
	Router  *Router
	Handler Handler
	Logger  *slog.Logger

	// OnDecision, if set, is called for every routing decision.
	OnDecision DecisionCallback
}

func New(opts Options) *Pipeline {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	handler := opts.Handler
	if handler == nil {
		handler = HandlerFunc(func(context.Context, Decision, []byte) error { return nil })
	}
	return &Pipeline{
		device:     opts.Device,
		tracker:    opts.Tracker,
		router:     opts.Router,
		handler:    handler,
		logger:     logger,
		onDecision: opts.OnDecision,
	}
}

func (p *Pipeline) Run(ctx context.Context) error {
	buf := make([]byte, p.device.MTU())
	if len(buf) == 0 {
		buf = make([]byte, 9000)
	}

	for {
		n, err := p.device.ReadPacket(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n == 0 {
			continue
		}

		packet := append([]byte(nil), buf[:n]...)
		atomic.AddUint64(&p.stats.PacketsRead, 1)
		atomic.AddUint64(&p.stats.BytesRead, uint64(len(packet)))
		if err := p.handlePacket(ctx, packet); err != nil && ctx.Err() == nil {
			p.logger.Warn("packet pipeline handler error", "error", err)
		}
	}
}

func (p *Pipeline) Snapshot() Stats {
	return Stats{
		PacketsRead:   atomic.LoadUint64(&p.stats.PacketsRead),
		BytesRead:     atomic.LoadUint64(&p.stats.BytesRead),
		BytesTGP:      atomic.LoadUint64(&p.stats.BytesTGP),
		BytesDirect:   atomic.LoadUint64(&p.stats.BytesDirect),
		BytesDrop:     atomic.LoadUint64(&p.stats.BytesDrop),
		Unsupported:   atomic.LoadUint64(&p.stats.Unsupported),
		LookupErrors:  atomic.LoadUint64(&p.stats.LookupErrors),
		DecidedTGP:    atomic.LoadUint64(&p.stats.DecidedTGP),
		DecidedDirect: atomic.LoadUint64(&p.stats.DecidedDirect),
		DecidedDrop:   atomic.LoadUint64(&p.stats.DecidedDrop),
		HandlerErrors: atomic.LoadUint64(&p.stats.HandlerErrors),
	}
}

func (p *Pipeline) handlePacket(ctx context.Context, packet []byte) error {
	flow, err := ParseFlow(packet)
	if err != nil {
		atomic.AddUint64(&p.stats.Unsupported, 1)
		return nil
	}

	proc, err := p.tracker.LookupFlow(ctx, flow)
	if err != nil {
		atomic.AddUint64(&p.stats.LookupErrors, 1)
		return err
	}

	decision := p.router.Decide(flow, proc)
	p.countDecision(decision.Action, len(packet))
	if p.onDecision != nil {
		p.onDecision(decision)
	}

	if err := p.handler.HandlePacket(ctx, decision, packet); err != nil {
		atomic.AddUint64(&p.stats.HandlerErrors, 1)
		return err
	}
	return nil
}

func (p *Pipeline) countDecision(action Action, packetBytes int) {
	bytes := uint64(packetBytes)
	switch action {
	case ActionTGP:
		atomic.AddUint64(&p.stats.DecidedTGP, 1)
		atomic.AddUint64(&p.stats.BytesTGP, bytes)
	case ActionDirect:
		atomic.AddUint64(&p.stats.DecidedDirect, 1)
		atomic.AddUint64(&p.stats.BytesDirect, bytes)
	case ActionDrop:
		atomic.AddUint64(&p.stats.DecidedDrop, 1)
		atomic.AddUint64(&p.stats.BytesDrop, bytes)
	}
}

type LoggingHandler struct {
	Logger *slog.Logger
}

func (h LoggingHandler) HandlePacket(ctx context.Context, decision Decision, packet []byte) error {
	_ = ctx
	logger := h.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Debug("packet route decision",
		"action", decision.Action,
		"reason", decision.Reason,
		"transport", decision.Flow.Transport,
		"local", decision.Flow.LocalIP,
		"local_port", decision.Flow.LocalPort,
		"remote", decision.Flow.RemoteIP,
		"remote_port", decision.Flow.RemotePort,
		"process", decision.Process.Name,
		"bytes", len(packet),
	)
	return nil
}
