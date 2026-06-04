package tgp

import (
	"bytes"
	"testing"
)

func TestDeriveTrafficKeysMatchAcrossRoles(t *testing.T) {
	client, err := NewKeyPair()
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	server, err := NewKeyPair()
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	sessionID, err := NewSessionID()
	if err != nil {
		t.Fatalf("session id: %v", err)
	}

	clientKeys, err := client.DeriveTrafficKeys(server.PublicKey(), sessionID, RoleClient)
	if err != nil {
		t.Fatalf("client derive: %v", err)
	}
	serverKeys, err := server.DeriveTrafficKeys(client.PublicKey(), sessionID, RoleServer)
	if err != nil {
		t.Fatalf("server derive: %v", err)
	}

	if !bytes.Equal(clientKeys.SendKey[:], serverKeys.RecvKey[:]) {
		t.Fatal("client send key must equal server recv key")
	}
	if !bytes.Equal(clientKeys.RecvKey[:], serverKeys.SendKey[:]) {
		t.Fatal("client recv key must equal server send key")
	}
	if bytes.Equal(clientKeys.SendKey[:], clientKeys.RecvKey[:]) {
		t.Fatal("send and recv keys must be distinct")
	}
}
