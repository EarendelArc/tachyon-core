package tgp

import "testing"

func TestPathControlAuthenticatesChallengeResponse(t *testing.T) {
	var sessionID SessionID
	copy(sessionID[:], []byte("path-control-cid"))
	var trafficKey [trafficKeySize]byte
	for i := range trafficKey {
		trafficKey[i] = byte(i + 1)
	}
	key := derivePathAuthKey(trafficKey, sessionID)
	clientNonce := [pathControlNonceSize]byte{1, 2, 3, 4}
	serverNonce := [pathControlNonceSize]byte{5, 6, 7, 8}

	for _, msgType := range []pathControlType{pathControlRequest, pathControlChallenge, pathControlResponse} {
		wire, err := marshalPathControl(msgType, sessionID, clientNonce, serverNonce, key)
		if err != nil {
			t.Fatalf("marshal type %d: %v", msgType, err)
		}
		msg, err := parsePathControl(wire)
		if err != nil {
			t.Fatalf("parse type %d: %v", msgType, err)
		}
		if !verifyPathControl(msg, key) {
			t.Fatalf("type %d did not authenticate", msgType)
		}
		wire[len(wire)-1] ^= 0x80
		tampered, err := parsePathControl(wire)
		if err != nil {
			t.Fatalf("parse tampered type %d: %v", msgType, err)
		}
		if verifyPathControl(tampered, key) {
			t.Fatalf("type %d accepted a tampered tag", msgType)
		}
	}
}

func TestPathControlKeyIsSessionBound(t *testing.T) {
	var firstID SessionID
	copy(firstID[:], []byte("first-path-cid!!"))
	var secondID SessionID
	copy(secondID[:], []byte("second-path-cid!"))
	var trafficKey [trafficKeySize]byte
	trafficKey[0] = 42
	firstKey := derivePathAuthKey(trafficKey, firstID)
	secondKey := derivePathAuthKey(trafficKey, secondID)
	nonce := [pathControlNonceSize]byte{9, 8, 7, 6}
	wire, err := marshalPathControl(pathControlRequest, firstID, nonce, [pathControlNonceSize]byte{}, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := parsePathControl(wire)
	if err != nil {
		t.Fatal(err)
	}
	if verifyPathControl(msg, secondKey) {
		t.Fatal("path control authenticated with a different session key")
	}
}
