package ipc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	// SessionTokenHandleEnv contains an inherited anonymous-pipe handle. The
	// value identifies the handle; it is not the session secret.
	SessionTokenHandleEnv = "TACHYON_IPC_TOKEN_HANDLE"
	sessionTokenBytes     = 32
)

var ErrSessionTokenHandoffUnavailable = errors.New("secure IPC token handoff is unavailable")

// SessionTokenHandoffConfigured reports whether the parent supplied an
// inherited anonymous pipe for the one-time session-token handoff.
func SessionTokenHandoffConfigured() bool {
	return strings.TrimSpace(os.Getenv(SessionTokenHandleEnv)) != ""
}

// NewSessionToken returns a 256-bit URL-safe bearer token.
func NewSessionToken() (string, error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate IPC session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ValidateSessionToken rejects malformed or low-entropy bearer tokens.
func ValidateSessionToken(token string) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != sessionTokenBytes {
		return errors.New("IPC session token must be a 256-bit base64url value")
	}
	return nil
}

// HandoffSessionToken writes the token once to an inherited anonymous pipe
// and closes the local handle. Prism must create the pipe, mark only the child
// write handle inheritable, and read the token from the parent end. No command
// line, environment variable, log record, or HTTP endpoint carries the secret.
func HandoffSessionToken(token string) error {
	if err := ValidateSessionToken(token); err != nil {
		return err
	}
	rawHandle := strings.TrimSpace(os.Getenv(SessionTokenHandleEnv))
	_ = os.Unsetenv(SessionTokenHandleEnv)
	if rawHandle == "" {
		return ErrSessionTokenHandoffUnavailable
	}
	handle, err := strconv.ParseUint(rawHandle, 10, 64)
	if err != nil || handle <= 2 {
		return fmt.Errorf("%w: invalid inherited handle", ErrSessionTokenHandoffUnavailable)
	}
	pipe := os.NewFile(uintptr(handle), "tachyon-ipc-token-handoff")
	if pipe == nil {
		return fmt.Errorf("%w: inherited handle is unavailable", ErrSessionTokenHandoffUnavailable)
	}
	defer pipe.Close()
	info, err := pipe.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return fmt.Errorf("%w: inherited handle is not an anonymous pipe", ErrSessionTokenHandoffUnavailable)
	}
	if _, err := io.WriteString(pipe, token+"\n"); err != nil {
		return fmt.Errorf("%w: token write failed", ErrSessionTokenHandoffUnavailable)
	}
	return nil
}
