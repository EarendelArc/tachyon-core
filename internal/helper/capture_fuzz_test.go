package helper

import "testing"

func FuzzUnmarshalWFPWire(f *testing.F) {
	handshake, _ := MarshalWFPDriverHandshake(WFPDriverHandshake{
		Header:     WFPABIHeader{Version: WFPDriverABIVersion, Kind: WFPKindHandshake, RequestID: 1},
		ContractID: WFPDriverContractID, Capabilities: WFPRequiredCapabilityMask, MaxMTU: 1500,
	}, WFPMaxMessageSize)
	datagram, _ := MarshalWFPDatagram(WFPDatagramMessage{RequestID: 2, Payload: []byte("seed")}, WFPMaxMessageSize)
	flow, _ := MarshalWFPFlowIdentity(WFPFlowIdentityABI{
		Header: WFPABIHeader{Version: WFPDriverABIVersion, Kind: WFPKindFlow, RequestID: 3},
	}, WFPMaxMessageSize)
	for _, seed := range [][]byte{nil, handshake, datagram, flow} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = UnmarshalWFPDriverHandshake(wire, WFPMaxMessageSize)
		_, _ = UnmarshalWFPDatagram(wire, WFPMaxMessageSize)
		_, _ = UnmarshalWFPFlowIdentity(wire, WFPMaxMessageSize)
	})
}
