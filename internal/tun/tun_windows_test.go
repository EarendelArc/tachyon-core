//go:build windows

package tun

import (
	"math"
	"testing"
)

func TestValidateWintunPacketSizeBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		size      uint32
		bufferLen int
		wantSize  int
		wantError bool
	}{
		{name: "empty", size: 0, bufferLen: 0, wantSize: 0},
		{name: "exact", size: 128, bufferLen: 128, wantSize: 128},
		{name: "one byte too large", size: 129, bufferLen: 128, wantError: true},
		{name: "maximum uint32 into small buffer", size: math.MaxUint32, bufferLen: 128, wantError: true},
		{name: "negative buffer length", size: 0, bufferLen: -1, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotSize, err := validateWintunPacketSize(test.size, test.bufferLen)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError=%v", err, test.wantError)
			}
			if err == nil && gotSize != test.wantSize {
				t.Fatalf("size = %d, want %d", gotSize, test.wantSize)
			}
		})
	}
}
