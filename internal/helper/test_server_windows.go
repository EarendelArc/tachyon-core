//go:build windows

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tachyon-space/tachyon-core/internal/capturedudp"
	"github.com/tachyon-space/tachyon-core/internal/tgp"
)

// RunTestServer is a test-only Core Named Pipe v2 endpoint. It has no TUN,
// WFP, proxy, route, or game data path and must never be used in production.
func RunTestServer(ctx context.Context, config Config) error {
	registry, err := capturedudp.NewRegistry(capturedudp.Limits{})
	if err != nil {
		return err
	}
	defer registry.Close()
	server, err := capturedudp.NewNamedPipeServer(registry, capturedudp.NamedPipeConfig{
		Name: config.PipeName, AllowedSIDs: config.AllowedSIDs,
		MinimumIntegrityRID: config.MinimumServerIntegrityRID,
		OperationTimeout:    config.OperationTimeout,
	}, testServerSender{})
	if err != nil {
		return err
	}
	defer server.Close()
	if err := writeTestServerReady(config.TestReadyFile, config.PipeName); err != nil {
		return err
	}
	return server.Run(ctx)
}

type testServerReady struct {
	Stage string `json:"stage"`
	PID   int    `json:"pid"`
	Pipe  string `json:"pipe"`
}

func writeTestServerReady(path, pipeName string) error {
	if path == "" {
		return errors.New("test server ready file is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil || !isHarnessArtifactPath(absolute, "core-ready.json") {
		return errors.New("test server ready file must be a managed Harness/<GUID>/core-ready.json path")
	}
	if err := rejectDiagnosticReparsePoints(absolute); err != nil {
		return fmt.Errorf("validate test server ready path: %w", err)
	}
	if _, err := os.Lstat(absolute); err == nil {
		return errors.New("test server ready file already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect test server ready file: %w", err)
	}
	encoded, err := json.Marshal(testServerReady{Stage: "listening", PID: os.Getpid(), Pipe: pipeName})
	if err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(absolute), "core-ready.tmp")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create test server ready file: %w", err)
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write test server ready file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("flush test server ready file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close test server ready file: %w", err)
	}
	if err := os.Rename(temporary, absolute); err != nil {
		return fmt.Errorf("publish test server ready file: %w", err)
	}
	removeTemporary = false
	return nil
}

type testServerSender struct{}

func (testServerSender) SendDatagram(context.Context, tgp.TunnelDatagram) error { return nil }
