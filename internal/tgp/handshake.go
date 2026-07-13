package tgp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
)

const (
	handshakeBaseBodySize = 4 + 1 + 16 + publicKeySize
	handshakeAuthTagSize  = sha256.Size
	handshakeSequence     = 0
)

var (
	handshakeMagic       = [4]byte{0x54, 0x47, 0x48, 0x01} // "TGH\x01"
	ErrInvalidHandshake  = errors.New("invalid tgp handshake")
	ErrUnexpectedMessage = errors.New("unexpected tgp handshake message")
	ErrHandshakeTimeout  = errors.New("tgp handshake timeout")
)

type handshakeType uint8

const (
	handshakeHello handshakeType = iota + 1
	handshakeHelloAck
)

type SessionRuntimeOptions struct {
	PacerPPS         float64
	FEC              FECOptions
	MaxDatagramSize  int
	DisableMigration bool
	AuthKey          []byte
}

type handshakeMessage struct {
	msgType   handshakeType
	sessionID SessionID
	publicKey PublicKey
	authTag   []byte
}

func DialSession(ctx context.Context, localAddr string, remoteAddr net.Addr, pacerPPS float64) (*DatagramSession, error) {
	return DialSessionWithOptions(ctx, localAddr, remoteAddr, SessionRuntimeOptions{PacerPPS: pacerPPS})
}

func DialSessionWithOptions(ctx context.Context, localAddr string, remoteAddr net.Addr, opts SessionRuntimeOptions) (*DatagramSession, error) {
	if remoteAddr == nil {
		return nil, errors.New("remote address is required")
	}
	path, err := ListenUDP(localAddr)
	if err != nil {
		return nil, err
	}
	transport, err := NewMultipathTransport(path)
	if err != nil {
		_ = path.Close()
		return nil, err
	}
	return dialSessionWithTransport(ctx, transport, remoteAddr, opts)
}

func DialSessionMultipathWithOptions(ctx context.Context, localAddrs []string, remoteAddr net.Addr, opts SessionRuntimeOptions) (*DatagramSession, error) {
	if remoteAddr == nil {
		return nil, errors.New("remote address is required")
	}
	if len(localAddrs) == 0 {
		return DialSessionWithOptions(ctx, "0.0.0.0:0", remoteAddr, opts)
	}
	transports := make([]Transport, 0, len(localAddrs))
	for _, localAddr := range localAddrs {
		transport, err := ListenUDP(localAddr)
		if err != nil {
			for _, item := range transports {
				_ = item.Close()
			}
			return nil, err
		}
		transports = append(transports, transport)
	}
	transport, err := NewMultipathTransport(transports...)
	if err != nil {
		for _, item := range transports {
			_ = item.Close()
		}
		return nil, err
	}
	return dialSessionWithTransport(ctx, transport, remoteAddr, opts)
}

func dialSessionWithTransport(ctx context.Context, transport Transport, remoteAddr net.Addr, opts SessionRuntimeOptions) (*DatagramSession, error) {
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
	clientPublic := keyPair.PublicKey()
	hello, err := marshalHandshake(handshakeHello, sessionID, clientPublic, opts.AuthKey, PublicKey{})
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
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return nil, fmt.Errorf("%w: waiting for hello ack: %w", ErrHandshakeTimeout, err)
			}
			return nil, err
		}
		msg, err := parseHandshake(wire)
		if err != nil {
			continue
		}
		if msg.msgType != handshakeHelloAck || msg.sessionID != sessionID {
			continue
		}
		if err := verifyHandshakeAuth(msg, opts.AuthKey, clientPublic); err != nil {
			continue
		}
		keys, err := keyPair.DeriveTrafficKeysWithAuth(msg.publicKey, sessionID, RoleClient, opts.AuthKey)
		if err != nil {
			_ = transport.Close()
			return nil, err
		}
		if !opts.DisableMigration {
			if pathTransport, ok := transport.(interface {
				EnablePathAuthentication(SessionID, [trafficKeySize]byte, net.Addr) error
			}); ok {
				pathKey := derivePathAuthKey(keys.SendKey, sessionID)
				if err := pathTransport.EnablePathAuthentication(sessionID, pathKey, from); err != nil {
					_ = transport.Close()
					return nil, fmt.Errorf("enable tgp path authentication: %w", err)
				}
			}
		}
		return NewDatagramSession(SessionOptions{
			ID:               sessionID,
			Transport:        transport,
			RemoteAddr:       from,
			SendKey:          keys.SendKey,
			RecvKey:          keys.RecvKey,
			Pacer:            NewTokenBucketPacer(opts.PacerPPS),
			FEC:              opts.FEC,
			MaxDatagramSize:  opts.MaxDatagramSize,
			DisableMigration: opts.DisableMigration,
		})
	}
}

func AcceptSession(ctx context.Context, transport Transport, pacerPPS float64) (*DatagramSession, error) {
	return AcceptSessionWithOptions(ctx, transport, SessionRuntimeOptions{PacerPPS: pacerPPS})
}

func AcceptSessionWithOptions(ctx context.Context, transport Transport, opts SessionRuntimeOptions) (*DatagramSession, error) {
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
		msg, err := parseHandshake(wire)
		if err != nil {
			continue
		}
		if msg.msgType != handshakeHello {
			continue
		}
		if err := verifyHandshakeAuth(msg, opts.AuthKey, PublicKey{}); err != nil {
			continue
		}

		keys, err := keyPair.DeriveTrafficKeysWithAuth(msg.publicKey, msg.sessionID, RoleServer, opts.AuthKey)
		if err != nil {
			return nil, err
		}
		ack, err := marshalHandshake(handshakeHelloAck, msg.sessionID, keyPair.PublicKey(), opts.AuthKey, msg.publicKey)
		if err != nil {
			return nil, err
		}
		if err := transport.WritePacket(ctx, ack, from); err != nil {
			return nil, err
		}
		return NewDatagramSession(SessionOptions{
			ID:               msg.sessionID,
			Transport:        transport,
			RemoteAddr:       from,
			SendKey:          keys.SendKey,
			RecvKey:          keys.RecvKey,
			Pacer:            NewTokenBucketPacer(opts.PacerPPS),
			FEC:              opts.FEC,
			MaxDatagramSize:  opts.MaxDatagramSize,
			DisableMigration: opts.DisableMigration,
		})
	}
}

func marshalHandshake(msgType handshakeType, sessionID SessionID, publicKey PublicKey, authKey []byte, peerPublic PublicKey) ([]byte, error) {
	bodySize := handshakeBaseBodySize
	if len(authKey) > 0 {
		bodySize += handshakeAuthTagSize
	}
	body := make([]byte, bodySize)
	copy(body[0:4], handshakeMagic[:])
	body[4] = byte(msgType)
	copy(body[5:21], sessionID[:])
	copy(body[21:53], publicKey[:])
	if len(authKey) > 0 {
		tag := handshakeAuthTag(authKey, msgType, sessionID, publicKey, peerPublic)
		copy(body[handshakeBaseBodySize:], tag)
	}

	outer, err := NewOuterHeader(handshakeSequence, len(body))
	if err != nil {
		return nil, err
	}
	wire := marshalOuterHeader(outer)
	wire = append(wire, body...)
	return wire, nil
}

func parseHandshake(wire []byte) (handshakeMessage, error) {
	if len(wire) != outerHeaderSize+handshakeBaseBodySize && len(wire) != outerHeaderSize+handshakeBaseBodySize+handshakeAuthTagSize {
		return handshakeMessage{}, ErrInvalidHandshake
	}
	outer, err := parseOuterHeader(wire[:outerHeaderSize])
	if err != nil {
		return handshakeMessage{}, err
	}
	if outer.ContentType != 0x17 || outer.VersionMajor != 0xfe || outer.VersionMinor != 0xff || int(outer.Length) != len(wire)-outerHeaderSize {
		return handshakeMessage{}, ErrInvalidHandshake
	}

	body := wire[outerHeaderSize:]
	if string(body[0:4]) != string(handshakeMagic[:]) {
		return handshakeMessage{}, ErrInvalidHandshake
	}
	msgType := handshakeType(body[4])
	if msgType != handshakeHello && msgType != handshakeHelloAck {
		return handshakeMessage{}, fmt.Errorf("%w: %d", ErrUnexpectedMessage, msgType)
	}
	var sessionID SessionID
	var publicKey PublicKey
	copy(sessionID[:], body[5:21])
	copy(publicKey[:], body[21:53])
	msg := handshakeMessage{
		msgType:   msgType,
		sessionID: sessionID,
		publicKey: publicKey,
	}
	if len(body) == handshakeBaseBodySize+handshakeAuthTagSize {
		msg.authTag = append([]byte(nil), body[handshakeBaseBodySize:]...)
	}
	return msg, nil
}

func verifyHandshakeAuth(msg handshakeMessage, authKey []byte, peerPublic PublicKey) error {
	if len(authKey) == 0 {
		if len(msg.authTag) != 0 {
			return ErrInvalidHandshake
		}
		return nil
	}
	if len(msg.authTag) != handshakeAuthTagSize {
		return ErrInvalidHandshake
	}
	want := handshakeAuthTag(authKey, msg.msgType, msg.sessionID, msg.publicKey, peerPublic)
	if !hmac.Equal(msg.authTag, want) {
		return ErrInvalidHandshake
	}
	return nil
}

func handshakeAuthTag(authKey []byte, msgType handshakeType, sessionID SessionID, publicKey PublicKey, peerPublic PublicKey) []byte {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write(handshakeMagic[:])
	_, _ = mac.Write([]byte{byte(msgType)})
	_, _ = mac.Write(sessionID[:])
	_, _ = mac.Write(publicKey[:])
	_, _ = mac.Write(peerPublic[:])
	return mac.Sum(nil)
}
