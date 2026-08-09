package helper

import (
	"context"
	"errors"
	"testing"
)

func TestRequiredWFPDriverContractUsesGeneratedCaptureOnlyABI(t *testing.T) {
	contract := RequiredWFPDriverContract()
	if err := contract.Validate(); err != nil {
		t.Fatal(err)
	}
	if contract.NegotiateIOCTL != ioctlWFPNegotiate || contract.SetPolicyIOCTL != ioctlWFPSetPolicy ||
		contract.DisablePolicyIOCTL != ioctlWFPDisablePolicy || contract.DequeueIOCTL != ioctlWFPDequeue ||
		contract.VerdictIOCTL != ioctlWFPVerdict || contract.StatisticsIOCTL != ioctlWFPStatistics {
		t.Fatal("contract IOCTLs did not come from generated ABI")
	}
	if wfpRequiredCapabilities&(1<<12) != 0 {
		t.Fatal("capture-only ABI unexpectedly contains a receive-injection capability")
	}
}

func TestUnavailableProviderAndInjectorNeverBecomeReady(t *testing.T) {
	provider := NewUnavailableCaptureProvider()
	if health := provider.Health(); health.Status != "not_ready" || health.Verified {
		t.Fatalf("unavailable provider health = %+v", health)
	}
	if err := provider.Start(context.Background(), CaptureCallbacks{}); !errors.Is(err, ErrCaptureUnavailable) {
		t.Fatalf("provider start error = %v", err)
	}
	if err := NewUnavailableInjector().Inject(context.Background(), Delivery{}); !errors.Is(err, ErrCaptureUnavailable) {
		t.Fatalf("inject error = %v", err)
	}
}

func TestWFPContractRejectsDuplicateGeneratedIOCTL(t *testing.T) {
	contract := RequiredWFPDriverContract()
	contract.VerdictIOCTL = contract.DequeueIOCTL
	if err := contract.Validate(); err == nil {
		t.Fatal("duplicate IOCTL contract accepted")
	}
}
