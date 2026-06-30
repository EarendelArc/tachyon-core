package tgp

import "testing"

func TestFECAdaptiveControllerKeepsProbeParityAtLowLoss(t *testing.T) {
	controller := NewFECAdaptiveController(4, 4, 4)
	parity, loss, updated := controller.Observe(4, 0)
	if !updated {
		t.Fatal("expected update after one window")
	}
	if parity != 1 {
		t.Fatalf("expected one probe parity shard, got %d", parity)
	}
	if loss != 0 {
		t.Fatalf("expected zero loss, got %f", loss)
	}
}

func TestFECAdaptiveControllerIncreasesParityAtHigherLoss(t *testing.T) {
	controller := NewFECAdaptiveController(4, 4, 4)
	parity, loss, updated := controller.Observe(4, 1)
	if !updated {
		t.Fatal("expected update after one window")
	}
	if parity != 4 {
		t.Fatalf("expected max parity at 25%% loss, got %d", parity)
	}
	if loss != 0.25 {
		t.Fatalf("expected 25%% loss, got %f", loss)
	}
}

func TestFECAdaptiveControllerUsesMidTierParity(t *testing.T) {
	controller := NewFECAdaptiveController(4, 4, 20)
	parity, loss, updated := controller.Observe(20, 1)
	if !updated {
		t.Fatal("expected update after one window")
	}
	if parity != 2 {
		t.Fatalf("expected half parity at 5%% loss, got %d", parity)
	}
	if loss != 0.05 {
		t.Fatalf("expected 5%% loss, got %f", loss)
	}
}

func TestDatagramSessionAdjustsFECParityFromRecoverySamples(t *testing.T) {
	session := &DatagramSession{
		fec: FECOptions{
			DataShards:   4,
			ParityShards: 1,
			Dynamic:      true,
			AdaptWindow:  1,
		},
		fecAdapt: NewFECAdaptiveController(4, 4, 1),
	}
	session.observeFECDelivery(1, 1)
	if session.fec.ParityShards != 4 {
		t.Fatalf("expected parity to increase to max, got %d", session.fec.ParityShards)
	}
	if session.Stats().PacketLoss != 1 {
		t.Fatalf("expected packet loss stat to be 1.0, got %f", session.Stats().PacketLoss)
	}
}
