package tgp

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	publicKeySize  = 32
	trafficKeySize = 32
)

type Role uint8

const (
	RoleClient Role = iota + 1
	RoleServer
)

var (
	ErrInvalidRole      = errors.New("invalid tgp role")
	ErrInvalidPublicKey = errors.New("invalid tgp public key")
)

type KeyPair struct {
	private *ecdh.PrivateKey
}

type PublicKey [publicKeySize]byte

type TrafficKeys struct {
	SendKey [trafficKeySize]byte
	RecvKey [trafficKeySize]byte
}

func NewSessionID() (SessionID, error) {
	var id SessionID
	if _, err := rand.Read(id[:]); err != nil {
		return SessionID{}, fmt.Errorf("generate session id: %w", err)
	}
	return id, nil
}

func NewKeyPair() (*KeyPair, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 keypair: %w", err)
	}
	return &KeyPair{private: private}, nil
}

func (k *KeyPair) PublicKey() PublicKey {
	var out PublicKey
	if k == nil || k.private == nil {
		return out
	}
	copy(out[:], k.private.PublicKey().Bytes())
	return out
}

func (k *KeyPair) DeriveTrafficKeys(peer PublicKey, sessionID SessionID, role Role) (TrafficKeys, error) {
	if k == nil || k.private == nil {
		return TrafficKeys{}, errors.New("nil tgp keypair")
	}
	peerKey, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return TrafficKeys{}, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	shared, err := k.private.ECDH(peerKey)
	if err != nil {
		return TrafficKeys{}, fmt.Errorf("x25519 ecdh: %w", err)
	}

	okm, err := hkdf.Key(sha256.New, shared, sessionID[:], "tachyon-tgp-v1 traffic keys", trafficKeySize*2)
	if err != nil {
		return TrafficKeys{}, fmt.Errorf("derive traffic keys: %w", err)
	}

	var clientToServer [trafficKeySize]byte
	var serverToClient [trafficKeySize]byte
	copy(clientToServer[:], okm[:trafficKeySize])
	copy(serverToClient[:], okm[trafficKeySize:])

	switch role {
	case RoleClient:
		return TrafficKeys{SendKey: clientToServer, RecvKey: serverToClient}, nil
	case RoleServer:
		return TrafficKeys{SendKey: serverToClient, RecvKey: clientToServer}, nil
	default:
		return TrafficKeys{}, ErrInvalidRole
	}
}
