package app

import (
	"context"
	"testing"

	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

func TestServerRelayHandlerAcceptsPacket(t *testing.T) {
	handler := serverRelayHandler{}
	err := handler.HandleRelayPacket(context.Background(), tgp.RelayPacket{
		Payload: []byte("packet"),
	})
	if err != nil {
		t.Fatalf("handle relay packet: %v", err)
	}
}
