package helper

import "context"

type CaptureDevice interface {
	CaptureProvider
	Injector
}

type failedCaptureDevice struct{ reason string }

func (device failedCaptureDevice) Contract() WFPDriverContract { return RequiredWFPDriverContract() }
func (device failedCaptureDevice) Start(context.Context, CaptureCallbacks) error {
	return ErrCaptureUnavailable
}
func (device failedCaptureDevice) Stop(context.Context) error { return nil }
func (device failedCaptureDevice) Inject(context.Context, Delivery) error {
	return ErrCaptureUnavailable
}
func (device failedCaptureDevice) CloseFlow(context.Context, FlowIdentity) error { return nil }
func (device failedCaptureDevice) Close(context.Context) error                   { return nil }
func (device failedCaptureDevice) Health() ProviderHealth {
	return ProviderHealth{Status: "not_ready", Reason: device.reason, Verified: false}
}
