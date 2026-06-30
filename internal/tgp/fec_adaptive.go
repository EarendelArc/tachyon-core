package tgp

import "math"

const defaultFECAdaptWindow = 32

type FECAdaptiveController struct {
	dataShards int
	maxParity  int
	window     int

	delivered int
	recovered int
	lossRate  float64
}

func NewFECAdaptiveController(dataShards, maxParity, window int) *FECAdaptiveController {
	if dataShards < 1 {
		dataShards = 1
	}
	if maxParity < 1 {
		maxParity = dataShards
	}
	if maxParity > dataShards {
		maxParity = dataShards
	}
	if window <= 0 {
		window = defaultFECAdaptWindow
	}
	return &FECAdaptiveController{
		dataShards: dataShards,
		maxParity:  maxParity,
		window:     window,
	}
}

func (c *FECAdaptiveController) Observe(delivered, recovered int) (int, float64, bool) {
	if c == nil || delivered <= 0 {
		return 0, 0, false
	}
	if recovered < 0 {
		recovered = 0
	}
	c.delivered += delivered
	c.recovered += recovered
	if c.delivered < c.window {
		return 0, c.lossRate, false
	}
	c.lossRate = float64(c.recovered) / float64(c.delivered)
	parity := c.parityForLoss(c.lossRate)
	c.delivered = 0
	c.recovered = 0
	return parity, c.lossRate, true
}

func (c *FECAdaptiveController) LossRate() float64 {
	if c == nil {
		return 0
	}
	return c.lossRate
}

func (c *FECAdaptiveController) parityForLoss(loss float64) int {
	switch {
	case loss >= 0.10:
		return c.maxParity
	case loss >= 0.03:
		return clampInt(int(math.Ceil(float64(c.dataShards)*0.50)), 1, c.maxParity)
	default:
		return clampInt(int(math.Ceil(float64(c.dataShards)*0.25)), 1, c.maxParity)
	}
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
