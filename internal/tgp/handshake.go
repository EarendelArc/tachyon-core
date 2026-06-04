package tgp

import (
	"context"
	"errors"
	"fmt"
	"net"
)

const (
	handshakeBodySize = 4 + 1 + 16 + publicKeySize
	handshakeSequence = 0
)

var (
	handshakeMagic       = [4]byte{0x54, 0x47, 0x48, 0x01} // "TGH\x01"
	ErrInvalidHandshake  = errors.New("invalid tgp handshake")
	ErrUnexpectedMessage = errors.New("unexpected tgp handshake message")
)

type handshakeType uint8

const (
	handshakeHello handshakeType = iota + 1
	handshakeHelloAck
)

func DialSession(ctx context.Context, localAddr string, remoteAddr net.Addr, pacerPPS float64) (*DatagramSession, error) {
	if remoteAddr == nil {
		return nil, errors.New("remote address is required")
	}
	transport, err := ListenUDP(localAddr)
	if err != nil {
		return nil, err
	}

	keyPair, err := NewKeyPair()
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	sessionID, err := NewSessionID()
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	hello, err := marshalHandshake(handshakeHello, sessionID, keyPair.PublicKey())
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	if err := transport.WritePacket(ctx, hello, remoteAddr); err != nil {
		_ = transport.Close()
		return nil, err
	}

	for {
		wire, from, err := transport.ReadPacket(ctx)
		if err != nil {
			_ = transport.Close()
			return nil, err
		}
		msgType, gotSessionID, peerPublic, err := parseHandshake(wire)
		if err != nil {
			continue
		}
		if msgType != handshakeHelloAck || gotSessionID != sessionID {
			continue
		}
		keys, err := keyPair.DeriveTrafficKeys(peerPublic, sessionID, RoleClient)
		if err != nil {
			_ = transport.Close()
			return nil, err
		}
		return NewDatagramSession(SessionOptions{
			ID:         sessionID,
			Transport:  transport,
			RemoteAddr: from,
			SendKey:    keys.SendKey,
			RecvKey:    keys.RecvKey,
			Pacer:      NewTokenBucketPacer(pacerPPS),
		})
	}
}

func AcceptSession(ctx context.Context, transport Transport, pacerPPS float64) (*DatagramSession, error) {
	if transport == nil {
		return nil, errors.New("transport is required")
	}
	keyPair, err := NewKeyPair()
	if err != nil {
		return nil, err
	}

	for {
		wire, from, err := transport.ReadPacket(ctx)
		if err != nil {
			return nil, err
		}
		msgType, sessionID, peerPublic, err := parseHandshake(wire)
		if err != nil {
			continue
		}
		if msgType != handshakeHello {
			continue
		}

		keys, err := keyPair.DeriveTrafficKeys(peerPublic, sessionID, RoleServer)
		if err != nil {
			return nil, err
		}
		ack, err := marshalHandshake(handshakeHelloAck, sessionID, keyPair.PublicKey())
		if err != nil {
			return nil, err
		}
		if err := transport.WritePacket(ctx, ack, from); err != nil {
			return nil, err
		}
		return NewDatagramSession(SessionOptions{
			ID:         sessionID,
			Transport:  transport,
			RemoteAddr: from,
			SendKey:    keys.SendKey,
			RecvKey:    keys.RecvKey,
			Pacer:      NewTokenBucketPacer(pacerPPS),
		})
	}
}

func marshalHandshake(msgType handshakeType, sessionID SessionID, publicKey PublicKey) ([]byte, error) {
	body := make([]byte, handshakeBodySize)
	copy(body[0:4], handshakeMagic[:])
	body[4] = byte(msgType)
	copy(body[5:21], sessionID[:])
	copy(body[21:53], publicKey[:])

	outer, err := NewOuterHeader(handshakeSequence, len(body))
	if err != nil {
		return nil, err
	}
	wire := marshalOuterHeader(outer)
	wire = append(wire, body...)
	return wire, nil
}

func parseHandshake(wire []byte) (handshakeType, SessionID, PublicKey, error) {
	if len(wire) != outerHeaderSize+handshakeBodySize {
		return 0, SessionID{}, PublicKey{}, ErrInvalidHandshake
	}
	outer, err := parseOuterHeader(wire[:outerHeaderSize])
	if err != nil {
		return 0, SessionID{}, PublicKey{}, err
	}
	if outer.ContentType != 0x17 || outer.VersionMajor != 0xfe || outer.VersionMinor != 0xff || int(outer.Length) != handshakeBodySize {
		return 0, SessionID{}, PublicKey{}, ErrInvalidHandshake
	}

	body := wire[outerHeaderSize:]
	if string(body[0:4]) != string(handshakeMagic[:]) {
		return 0, SessionID{}, PublicKey{}, ErrInvalidHandshake
	}
	msgType := handshakeType(body[4])
	if msgType != handshakeHello && msgType != handshakeHelloAck {
		return 0, SessionID{}, PublicKey{}, fmt.Errorf("%w: %d", ErrUnexpectedMessage, msgType)
	}
	var sessionID SessionID
	var publicKey PublicKey
	copy(sessionID[:], body[5:21])
	copy(publicKey[:], body[21:53])
	return msgType, sessionID, publicKey, nil
}
