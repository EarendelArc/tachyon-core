package pipeline

import "sync/atomic"

// Accessor methods on Pipeline satisfy the observability.PipelineStats interface.

func (p *Pipeline) PacketsRead() uint64 {
	return atomic.LoadUint64(&p.stats.PacketsRead)
}

func (p *Pipeline) Unsupported() uint64 {
	return atomic.LoadUint64(&p.stats.Unsupported)
}

func (p *Pipeline) LookupErrors() uint64 {
	return atomic.LoadUint64(&p.stats.LookupErrors)
}

func (p *Pipeline) DecidedTGP() uint64 {
	return atomic.LoadUint64(&p.stats.DecidedTGP)
}

func (p *Pipeline) DecidedDirect() uint64 {
	return atomic.LoadUint64(&p.stats.DecidedDirect)
}

func (p *Pipeline) DecidedDrop() uint64 {
	return atomic.LoadUint64(&p.stats.DecidedDrop)
}

func (p *Pipeline) HandlerErrors() uint64 {
	return atomic.LoadUint64(&p.stats.HandlerErrors)
}
