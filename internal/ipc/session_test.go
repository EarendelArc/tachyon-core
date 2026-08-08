package ipc

import (
	"bufio"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestNewSessionTokenIsUniqueAnd256Bits(t *testing.T) {
	first, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("session tokens must be unique")
	}
	for _, token := range []string{first, second} {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(raw) != sessionTokenBytes {
			t.Fatalf("invalid generated token: length=%d err=%v", len(raw), err)
		}
	}
}

func TestHandoffSessionTokenUsesInheritedPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	t.Setenv(SessionTokenHandleEnv, strconv.FormatUint(uint64(writer.Fd()), 10))
	token, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := HandoffSessionToken(token); err != nil {
		t.Fatalf("handoff token: %v", err)
	}
	line, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil {
		t.Fatalf("read handoff: %v", err)
	}
	if strings.TrimSpace(line) != token {
		t.Fatal("handoff did not preserve token")
	}
	if os.Getenv(SessionTokenHandleEnv) != "" {
		t.Fatal("handoff handle environment variable was not cleared")
	}
}

func TestHandoffSessionTokenFailsClosedWithoutPipe(t *testing.T) {
	t.Setenv(SessionTokenHandleEnv, "")
	token, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := HandoffSessionToken(token); !errors.Is(err, ErrSessionTokenHandoffUnavailable) {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}

func TestHandoffSessionTokenRejectsRegularFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "handoff")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(SessionTokenHandleEnv, strconv.FormatUint(uint64(file.Fd()), 10))
	token, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := HandoffSessionToken(token); !errors.Is(err, ErrSessionTokenHandoffUnavailable) {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}
