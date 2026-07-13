package tgp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	pathControlNonceSize = 16
	pathControlTagSize   = sha256.Size
	pathRequestSize      = 4 + 1 + 16 + pathControlNonceSize + pathControlTagSize
	pathChallengeSize    = pathRequestSize + pathControlNonceSize
	pathRequestLifetime  = 10 * time.Second
)

var (
	pathControlMagic      = [4]byte{0x54, 0x47, 0x50, 0x02}
	ErrInvalidPathControl = errors.New("invalid tgp path control")
)

type pathControlType uint8

const (
	pathControlRequest pathControlType = iota + 1
	pathControlChallenge
	pathControlResponse
)

type pathControlMessage struct {
	msgType     pathControlType
	sessionID   SessionID
	clientNonce [pathControlNonceSize]byte
	serverNonce [pathControlNonceSize]byte
	tag         [pathControlTagSize]byte
}

func derivePathAuthKey(clientToServer [trafficKeySize]byte, sessionID SessionID) [trafficKeySize]byte {
	mac := hmac.New(sha256.New, clientToServer[:])
	_, _ = mac.Write([]byte("tachyon-tgp-v1 path authentication"))
	_, _ = mac.Write(sessionID[:])
	var key [trafficKeySize]byte
	copy(key[:], mac.Sum(nil))
	return key
}

func newPathRequestNonce(now time.Time) ([pathControlNonceSize]byte, error) {
	var nonce [pathControlNonceSize]byte
	binary.BigEndian.PutUint64(nonce[:8], uint64(now.Unix()))
	if _, err := rand.Read(nonce[8:]); err != nil {
		return nonce, fmt.Errorf("generate path request nonce: %w", err)
	}
	return nonce, nil
}

func verifyPathRequestTime(nonce [pathControlNonceSize]byte, now time.Time, maxAge time.Duration) bool {
	issuedUnix := binary.BigEndian.Uint64(nonce[:8])
	if issuedUnix > uint64(^uint64(0)>>1) {
		return false
	}
	issuedAt := time.Unix(int64(issuedUnix), 0)
	return !issuedAt.After(now.Add(time.Second)) && now.Sub(issuedAt) <= maxAge
}

func newPathCookie(key [trafficKeySize]byte, sessionID SessionID, source sourceAddrKey, clientNonce [pathControlNonceSize]byte, issuedAt time.Time) [pathControlNonceSize]byte {
	var cookie [pathControlNonceSize]byte
	binary.BigEndian.PutUint64(cookie[:8], uint64(issuedAt.Unix()))
	tag := pathCookieTag(key, sessionID, source, clientNonce, cookie[:8])
	copy(cookie[8:], tag[:8])
	return cookie
}

func verifyPathCookie(cookie [pathControlNonceSize]byte, key [trafficKeySize]byte, sessionID SessionID, source sourceAddrKey, clientNonce [pathControlNonceSize]byte, now time.Time, maxAge time.Duration) bool {
	issuedUnix := binary.BigEndian.Uint64(cookie[:8])
	if issuedUnix > uint64(^uint64(0)>>1) {
		return false
	}
	issuedAt := time.Unix(int64(issuedUnix), 0)
	if issuedAt.After(now.Add(time.Second)) || now.Sub(issuedAt) > maxAge {
		return false
	}
	want := pathCookieTag(key, sessionID, source, clientNonce, cookie[:8])
	return subtle.ConstantTimeCompare(cookie[8:], want[:8]) == 1
}

func pathCookieTag(key [trafficKeySize]byte, sessionID SessionID, source sourceAddrKey, clientNonce [pathControlNonceSize]byte, issued []byte) [pathControlTagSize]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("tachyon-tgp-v1 path cookie"))
	_, _ = mac.Write(sessionID[:])
	_, _ = mac.Write(clientNonce[:])
	_, _ = mac.Write(issued)
	_, _ = mac.Write([]byte(source.network))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(source.address))
	var tag [pathControlTagSize]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func marshalPathControl(msgType pathControlType, sessionID SessionID, clientNonce, serverNonce [pathControlNonceSize]byte, key [trafficKeySize]byte) ([]byte, error) {
	if msgType != pathControlRequest && msgType != pathControlChallenge && msgType != pathControlResponse {
		return nil, ErrInvalidPathControl
	}
	size := pathRequestSize
	if msgType != pathControlRequest {
		size = pathChallengeSize
	}
	wire := make([]byte, size)
	copy(wire[:4], pathControlMagic[:])
	wire[4] = byte(msgType)
	copy(wire[5:21], sessionID[:])
	copy(wire[21:37], clientNonce[:])
	tagAt := 37
	if msgType != pathControlRequest {
		copy(wire[37:53], serverNonce[:])
		tagAt = 53
	}
	tag := pathControlTag(key, wire[:tagAt])
	copy(wire[tagAt:], tag[:])
	return wire, nil
}

func parsePathControl(wire []byte) (pathControlMessage, error) {
	if len(wire) != pathRequestSize && len(wire) != pathChallengeSize {
		return pathControlMessage{}, ErrInvalidPathControl
	}
	if subtle.ConstantTimeCompare(wire[:4], pathControlMagic[:]) != 1 {
		return pathControlMessage{}, ErrInvalidPathControl
	}
	msg := pathControlMessage{msgType: pathControlType(wire[4])}
	if msg.msgType != pathControlRequest && msg.msgType != pathControlChallenge && msg.msgType != pathControlResponse {
		return pathControlMessage{}, ErrInvalidPathControl
	}
	if msg.msgType == pathControlRequest && len(wire) != pathRequestSize {
		return pathControlMessage{}, ErrInvalidPathControl
	}
	if msg.msgType != pathControlRequest && len(wire) != pathChallengeSize {
		return pathControlMessage{}, ErrInvalidPathControl
	}
	copy(msg.sessionID[:], wire[5:21])
	copy(msg.clientNonce[:], wire[21:37])
	tagAt := 37
	if msg.msgType != pathControlRequest {
		copy(msg.serverNonce[:], wire[37:53])
		tagAt = 53
	}
	copy(msg.tag[:], wire[tagAt:])
	return msg, nil
}

func verifyPathControl(msg pathControlMessage, key [trafficKeySize]byte) bool {
	wire, err := marshalPathControl(msg.msgType, msg.sessionID, msg.clientNonce, msg.serverNonce, key)
	if err != nil {
		return false
	}
	tagAt := len(wire) - pathControlTagSize
	return subtle.ConstantTimeCompare(msg.tag[:], wire[tagAt:]) == 1
}

func pathControlTag(key [trafficKeySize]byte, body []byte) [pathControlTagSize]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(body)
	var tag [pathControlTagSize]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}
