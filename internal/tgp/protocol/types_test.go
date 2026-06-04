package protocol

import "testing"

func TestHeaderValidate(t *testing.T) {
	header := Header{
		Magic:   Magic,
		Version: Version,
		Type:    PacketData,
	}

	if err := header.Validate(); err != nil {
		t.Fatalf("valid header rejected: %v", err)
	}
}

func TestHeaderValidateRejectsBadMagic(t *testing.T) {
	header := Header{
		Magic:   0,
		Version: Version,
		Type:    PacketData,
	}

	if err := header.Validate(); err == nil {
		t.Fatal("expected bad magic error")
	}
}
