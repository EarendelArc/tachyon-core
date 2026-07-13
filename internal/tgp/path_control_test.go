package tgp

import (
	"testing"
	"time"
)

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

func TestPathRequestNonceTimeWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	nonce, err := newPathRequestNonce(now)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPathRequestTime(nonce, now, pathRequestLifetime) {
		t.Fatal("fresh path request nonce was rejected")
	}
	if verifyPathRequestTime(nonce, now.Add(pathRequestLifetime+2*time.Second), pathRequestLifetime) {
		t.Fatal("expired path request nonce was accepted")
	}
	future, err := newPathRequestNonce(now.Add(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if verifyPathRequestTime(future, now, pathRequestLifetime) {
		t.Fatal("path request nonce beyond clock-skew allowance was accepted")
	}

	var key [trafficKeySize]byte
	key[0] = 99
	wire, err := marshalPathControl(pathControlRequest, SessionID{}, nonce, [pathControlNonceSize]byte{}, key)
	if err != nil {
		t.Fatal(err)
	}
	wire[21] ^= 0x01
	tampered, err := parsePathControl(wire)
	if err != nil {
		t.Fatal(err)
	}
	if verifyPathControl(tampered, key) {
		t.Fatal("tampered path request timestamp remained authenticated")
	}
}

func TestPathCookieIsSourceBoundAndExpires(t *testing.T) {
	var sessionID SessionID
	copy(sessionID[:], []byte("cookie-source-id"))
	var key [trafficKeySize]byte
	key[0] = 73
	clientNonce := [pathControlNonceSize]byte{1, 9, 8, 4}
	first, ok := newSourceAddrKey(mustUDPAddr(t, "127.0.0.1:41001"))
	if !ok {
		t.Fatal("first source key is invalid")
	}
	second, ok := newSourceAddrKey(mustUDPAddr(t, "127.0.0.1:41002"))
	if !ok {
		t.Fatal("second source key is invalid")
	}
	now := time.Now()
	cookie := newPathCookie(key, sessionID, first, clientNonce, now)
	if !verifyPathCookie(cookie, key, sessionID, first, clientNonce, now, pathChallengeLifetime) {
		t.Fatal("fresh source-bound cookie was rejected")
	}
	if verifyPathCookie(cookie, key, sessionID, second, clientNonce, now, pathChallengeLifetime) {
		t.Fatal("path cookie authenticated from a different source")
	}
	if verifyPathCookie(cookie, key, sessionID, first, clientNonce, now.Add(pathChallengeLifetime+time.Second), pathChallengeLifetime) {
		t.Fatal("expired path cookie was accepted")
	}
}
