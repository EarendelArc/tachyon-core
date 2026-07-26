package tgp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	handshakeNonceSize    = 16
	handshakeBaseBodySize = 4 + 1 + 16 + publicKeySize + 2 + 8 + handshakeNonceSize
	handshakeAuthTagSize  = sha256.Size
	handshakeSequence     = 0
	handshakeInitialRetry = 100 * time.Millisecond
	handshakeMaxRetry     = 800 * time.Millisecond
	MaxHandshakeAttempts  = 4
	handshakeReplayLimit  = MaxHandshakeAttempts - 1
	MaxHandshakeTimeout   = 30 * time.Second
)

var (
	handshakeMagic       = [4]byte{0x54, 0x47, 0x48, 0x04} // "TGH\x04"
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
	ValidateRemote   func(net.Addr) error
}

type handshakeMessage struct {
	msgType         handshakeType
	sessionID       SessionID
	publicKey       PublicKey
	maxDatagramSize int
	unixMilli       int64
	nonce           [handshakeNonceSize]byte
	authTag         []byte
}

type handshakeClock struct {
	now       func() time.Time
	waitUntil func(context.Context, time.Time) error
}

var systemHandshakeClock = handshakeClock{
	now: time.Now,
	waitUntil: func(ctx context.Context, deadline time.Time) error {
		delay := time.Until(deadline)
		if delay <= 0 {
			return nil
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	},
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
	return dialSessionWithTransportClock(ctx, transport, remoteAddr, opts, systemHandshakeClock)
}

func dialSessionWithTransportClock(ctx context.Context, transport Transport, remoteAddr net.Addr, opts SessionRuntimeOptions, clock handshakeClock) (*DatagramSession, error) {
	if clock.now == nil || clock.waitUntil == nil {
		_ = transport.Close()
		return nil, errors.New("tgp handshake clock is required")
	}
	handshakeCtx, cancelHandshake := handshakeDeadlineContext(ctx, clock.now())
	defer cancelHandshake()
	handshakeDeadline, _ := handshakeCtx.Deadline()
	localMaxDatagramSize, err := normalizeMaxDatagramSize(opts.MaxDatagramSize)
	if err != nil {
		_ = transport.Close()
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
	clientPublic := keyPair.PublicKey()
	var nonce [handshakeNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("generate tgp handshake nonce: %w", err)
	}
	hello, err := marshalHandshake(handshakeHello, sessionID, clientPublic, localMaxDatagramSize, handshakeDeadline.UnixMilli(), nonce, opts.AuthKey, PublicKey{})
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	retryDelay := handshakeInitialRetry
	for attempt := 1; attempt <= MaxHandshakeAttempts; attempt++ {
		if err := handshakeDeadlineError(handshakeCtx, handshakeDeadline, clock.now()); err != nil {
			_ = transport.Close()
			return nil, fmt.Errorf("%w: waiting for hello ack: %w", ErrHandshakeTimeout, err)
		}
		helloSentAt := clock.now()
		if err := transport.WritePacket(handshakeCtx, hello, remoteAddr); err != nil {
			_ = transport.Close()
			if deadlineErr := handshakeDeadlineError(handshakeCtx, handshakeDeadline, clock.now()); deadlineErr != nil {
				return nil, fmt.Errorf("%w: sending hello: %w", ErrHandshakeTimeout, deadlineErr)
			}
			return nil, err
		}

		attemptDeadline := helloSentAt.Add(retryDelay)
		if attemptDeadline.After(handshakeDeadline) {
			attemptDeadline = handshakeDeadline
		}
		attemptCtx, cancel := context.WithDeadline(handshakeCtx, attemptDeadline)
		for {
			now := clock.now()
			if deadlineErr := handshakeDeadlineError(handshakeCtx, handshakeDeadline, now); deadlineErr != nil {
				cancel()
				_ = transport.Close()
				return nil, fmt.Errorf("%w: waiting for hello ack: %w", ErrHandshakeTimeout, deadlineErr)
			}
			if !now.Before(attemptDeadline) {
				cancel()
				break
			}
			wire, from, err := transport.ReadPacket(attemptCtx)
			ackReceivedAt := clock.now()
			if err != nil {
				cancel()
				if deadlineErr := handshakeDeadlineError(handshakeCtx, handshakeDeadline, ackReceivedAt); deadlineErr != nil {
					_ = transport.Close()
					return nil, fmt.Errorf("%w: waiting for hello ack: %w", ErrHandshakeTimeout, deadlineErr)
				}
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					if waitErr := clock.waitUntil(handshakeCtx, attemptDeadline); waitErr != nil {
						_ = transport.Close()
						if deadlineErr := handshakeDeadlineError(handshakeCtx, handshakeDeadline, clock.now()); deadlineErr != nil {
							return nil, fmt.Errorf("%w: waiting for hello ack: %w", ErrHandshakeTimeout, deadlineErr)
						}
						return nil, fmt.Errorf("%w: waiting for hello ack: %w", ErrHandshakeTimeout, waitErr)
					}
					if deadlineErr := handshakeDeadlineError(handshakeCtx, handshakeDeadline, clock.now()); deadlineErr != nil {
						_ = transport.Close()
						return nil, fmt.Errorf("%w: waiting for hello ack: %w", ErrHandshakeTimeout, deadlineErr)
					}
					break
				}
				_ = transport.Close()
				return nil, err
			}
			if !sameAddr(from, remoteAddr) {
				continue
			}
			msg, err := parseHandshake(wire)
			if err != nil || msg.msgType != handshakeHelloAck || msg.sessionID != sessionID {
				continue
			}
			if msg.nonce != nonce {
				continue
			}
			if err := verifyHandshakeAuth(msg, opts.AuthKey, clientPublic); err != nil {
				continue
			}
			if msg.maxDatagramSize < MinTGPDatagramSize || msg.maxDatagramSize > localMaxDatagramSize {
				continue
			}
			clockOffset, err := estimateRelayClockOffset(helloSentAt, ackReceivedAt, msg.unixMilli)
			if err != nil {
				continue
			}
			keys, err := keyPair.DeriveTrafficKeysWithAuth(msg.publicKey, sessionID, RoleClient, opts.AuthKey)
			if err != nil {
				cancel()
				_ = transport.Close()
				return nil, err
			}
			if !opts.DisableMigration {
				if pathTransport, ok := transport.(interface {
					EnablePathAuthentication(SessionID, [trafficKeySize]byte, net.Addr, time.Duration) error
				}); ok {
					pathKey := derivePathAuthKey(keys.SendKey, sessionID)
					if err := pathTransport.EnablePathAuthentication(sessionID, pathKey, from, clockOffset); err != nil {
						cancel()
						_ = transport.Close()
						return nil, fmt.Errorf("enable tgp path authentication: %w", err)
					}
				}
			}
			cancel()
			return NewDatagramSession(SessionOptions{
				ID:               sessionID,
				Transport:        transport,
				RemoteAddr:       from,
				SendKey:          keys.SendKey,
				RecvKey:          keys.RecvKey,
				Pacer:            NewTokenBucketPacer(opts.PacerPPS),
				FEC:              opts.FEC,
				MaxDatagramSize:  msg.maxDatagramSize,
				DisableMigration: opts.DisableMigration,
				ValidateRemote:   opts.ValidateRemote,
			})
		}
		retryDelay = min(retryDelay*2, handshakeMaxRetry)
	}
	_ = transport.Close()
	return nil, fmt.Errorf("%w: maximum of %d hello attempts exhausted", ErrHandshakeTimeout, MaxHandshakeAttempts)
}

func AcceptSession(ctx context.Context, transport Transport, pacerPPS float64) (*DatagramSession, error) {
	return AcceptSessionWithOptions(ctx, transport, SessionRuntimeOptions{PacerPPS: pacerPPS})
}

func AcceptSessionWithOptions(ctx context.Context, transport Transport, opts SessionRuntimeOptions) (*DatagramSession, error) {
	if transport == nil {
		return nil, errors.New("transport is required")
	}
	localMaxDatagramSize, err := normalizeMaxDatagramSize(opts.MaxDatagramSize)
	if err != nil {
		return nil, err
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
		if msg.msgType != handshakeHello || validateHandshakeHelloFreshness(msg, time.Now()) != nil {
			continue
		}
		if err := verifyHandshakeAuth(msg, opts.AuthKey, PublicKey{}); err != nil {
			continue
		}
		if msg.maxDatagramSize < MinTGPDatagramSize || msg.maxDatagramSize > MaxTGPDatagramSize {
			continue
		}
		effectiveMaxDatagramSize := min(localMaxDatagramSize, msg.maxDatagramSize)

		keys, err := keyPair.DeriveTrafficKeysWithAuth(msg.publicKey, msg.sessionID, RoleServer, opts.AuthKey)
		if err != nil {
			return nil, err
		}
		ack, err := marshalHandshake(handshakeHelloAck, msg.sessionID, keyPair.PublicKey(), effectiveMaxDatagramSize, time.Now().UnixMilli(), msg.nonce, opts.AuthKey, msg.publicKey)
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
			MaxDatagramSize:  effectiveMaxDatagramSize,
			DisableMigration: opts.DisableMigration,
			handshakeReplay: &handshakeReplayState{
				hello:     append([]byte(nil), wire...),
				ack:       append([]byte(nil), ack...),
				peer:      from,
				expiresAt: time.UnixMilli(msg.unixMilli),
				remaining: handshakeReplayLimit,
			},
		})
	}
}

func marshalHandshake(msgType handshakeType, sessionID SessionID, publicKey PublicKey, maxDatagramSize int, unixMilli int64, nonce [handshakeNonceSize]byte, authKey []byte, peerPublic PublicKey) ([]byte, error) {
	maxDatagramSize, err := normalizeMaxDatagramSize(maxDatagramSize)
	if err != nil {
		return nil, err
	}
	if unixMilli <= 0 || nonce == ([handshakeNonceSize]byte{}) {
		return nil, ErrInvalidHandshake
	}
	bodySize := handshakeBaseBodySize
	if len(authKey) > 0 {
		bodySize += handshakeAuthTagSize
	}
	body := make([]byte, bodySize)
	copy(body[0:4], handshakeMagic[:])
	body[4] = byte(msgType)
	copy(body[5:21], sessionID[:])
	copy(body[21:53], publicKey[:])
	binary.BigEndian.PutUint16(body[53:55], uint16(maxDatagramSize))
	binary.BigEndian.PutUint64(body[55:63], uint64(unixMilli))
	copy(body[63:63+handshakeNonceSize], nonce[:])
	if len(authKey) > 0 {
		tag := handshakeAuthTag(authKey, msgType, sessionID, publicKey, maxDatagramSize, unixMilli, nonce, peerPublic)
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
	maxDatagramSize := int(binary.BigEndian.Uint16(body[53:55]))
	unixMilli := int64(binary.BigEndian.Uint64(body[55:63]))
	var nonce [handshakeNonceSize]byte
	copy(nonce[:], body[63:63+handshakeNonceSize])
	msg := handshakeMessage{
		msgType:         msgType,
		sessionID:       sessionID,
		publicKey:       publicKey,
		maxDatagramSize: maxDatagramSize,
		unixMilli:       unixMilli,
		nonce:           nonce,
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
	want := handshakeAuthTag(authKey, msg.msgType, msg.sessionID, msg.publicKey, msg.maxDatagramSize, msg.unixMilli, msg.nonce, peerPublic)
	if !hmac.Equal(msg.authTag, want) {
		return ErrInvalidHandshake
	}
	return nil
}

func handshakeAuthTag(authKey []byte, msgType handshakeType, sessionID SessionID, publicKey PublicKey, maxDatagramSize int, unixMilli int64, nonce [handshakeNonceSize]byte, peerPublic PublicKey) []byte {
	mac := hmac.New(sha256.New, authKey)
	_, _ = mac.Write(handshakeMagic[:])
	_, _ = mac.Write([]byte{byte(msgType)})
	_, _ = mac.Write(sessionID[:])
	_, _ = mac.Write(publicKey[:])
	var encodedMax [2]byte
	binary.BigEndian.PutUint16(encodedMax[:], uint16(maxDatagramSize))
	_, _ = mac.Write(encodedMax[:])
	var encodedRelayTime [8]byte
	binary.BigEndian.PutUint64(encodedRelayTime[:], uint64(unixMilli))
	_, _ = mac.Write(encodedRelayTime[:])
	_, _ = mac.Write(nonce[:])
	_, _ = mac.Write(peerPublic[:])
	return mac.Sum(nil)
}

func estimateRelayClockOffset(helloSentAt, ackReceivedAt time.Time, relayUnixMilli int64) (time.Duration, error) {
	if relayUnixMilli <= 0 || ackReceivedAt.Before(helloSentAt) {
		return 0, ErrInvalidHandshake
	}
	// Bias the estimate into the past by the ACK's downstream latency. This
	// avoids creating future-dated requests on asymmetric paths.
	return time.UnixMilli(relayUnixMilli).Sub(ackReceivedAt), nil
}

func handshakeDeadlineContext(ctx context.Context, now time.Time) (context.Context, context.CancelFunc) {
	maxDeadline := now.Add(MaxHandshakeTimeout)
	if deadline, ok := ctx.Deadline(); ok && !deadline.After(maxDeadline) {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, maxDeadline)
}

func handshakeDeadlineError(ctx context.Context, deadline, now time.Time) error {
	if !now.Before(deadline) {
		return context.DeadlineExceeded
	}
	return ctx.Err()
}

func validateHandshakeHelloFreshness(msg handshakeMessage, now time.Time) error {
	if msg.msgType != handshakeHello || msg.nonce == ([handshakeNonceSize]byte{}) || msg.unixMilli <= 0 {
		return ErrInvalidHandshake
	}
	expiresAt := time.UnixMilli(msg.unixMilli)
	if !expiresAt.After(now) || expiresAt.After(now.Add(MaxHandshakeTimeout)) {
		return ErrInvalidHandshake
	}
	return nil
}
