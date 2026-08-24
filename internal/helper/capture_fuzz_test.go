package helper

import "testing"

func FuzzParseWFPCaptureNeverPanics(f *testing.F) {
	policy := fixturePolicy()
	f.Add(fixtureCapture(policy.Generation, 1, 1, policy.LeaseNonce))
	f.Fuzz(func(t *testing.T, wire []byte) {
		frame, _ := parseWFPCapture(wire)
		clear(frame.Payload)
	})
}
