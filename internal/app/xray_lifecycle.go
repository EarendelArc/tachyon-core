package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/tachyon-space/tachyon-core/internal/xray/configgen"
	xrayrunner "github.com/tachyon-space/tachyon-core/internal/xray/runner"
)

func (a *App) startClientXray(ctx context.Context) (xrayrunner.ProxyRunner, error) {
	binaryPath := xrayBinaryPath(a.cfg.Xray.InstallDir)
	if !fileExists(binaryPath) {
		a.logger.Warn("xray binary not found; xray-routed traffic is not active", "path", binaryPath)
		return nil, nil
	}

	configPath := a.cfg.Xray.ConfigFile
	if configPath == "" {
		configPath = defaultXrayConfigPath("client")
		data, err := configgen.BuildClientConfig(configgen.ClientOptions{
			SOCKSAddr:  configgen.DefaultClientSOCKSAddr,
			ServerAddr: a.cfg.Client.Proxy.ServerAddr,
			VLESSUID:   a.cfg.Client.Proxy.VLESSUID,
			SNI:        a.cfg.Client.Proxy.SNI,
		})
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(configPath, data, 0o600); err != nil {
			return nil, fmt.Errorf("write xray client config: %w", err)
		}
	}

	return startXrayRunner(ctx, binaryPath, configPath, a.logger)
}

func (a *App) startServerXray(ctx context.Context) (xrayrunner.ProxyRunner, error) {
	binaryPath := xrayBinaryPath(a.cfg.Xray.InstallDir)
	if !fileExists(binaryPath) {
		a.logger.Warn("xray binary not found; TLS/Xray backend is not active", "path", binaryPath)
		return nil, nil
	}
	if a.cfg.Xray.ConfigFile == "" {
		a.logger.Warn("xray server config_file is empty; TLS/Xray backend is not active")
		return nil, nil
	}
	return startXrayRunner(ctx, binaryPath, a.cfg.Xray.ConfigFile, a.logger)
}

func startXrayRunner(ctx context.Context, binaryPath string, configPath string, logger *slog.Logger) (xrayrunner.ProxyRunner, error) {
	runner := xrayrunner.NewSubProcessRunner()
	if err := runner.Start(ctx, xrayrunner.XrayRunConfig{
		BinaryPath: binaryPath,
		ConfigPath: configPath,
		WorkDir:    filepath.Dir(configPath),
	}); err != nil {
		return nil, err
	}
	if logger != nil {
		status, _ := runner.Status(ctx)
		logger.Info("xray subprocess started", "pid", status.PID, "config", configPath)
	}
	return runner, nil
}

func xrayBinaryPath(installDir string) string {
	if installDir == "" {
		installDir = defaultXrayInstallDir()
	}
	name := "xray"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(installDir, name)
}

func defaultXrayInstallDir() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "tachyon", "xray")
	}
	return filepath.Join(".", "xray")
}

func defaultXrayConfigPath(mode string) string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "tachyon", "xray", mode+".json")
	}
	return filepath.Join(".", "xray", mode+".json")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tachyon-xray-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
		return os.Rename(tmpPath, path)
	}
	return nil
}

func stopXray(ctx context.Context, runner xrayrunner.ProxyRunner, logger *slog.Logger) {
	if runner == nil {
		return
	}
	if err := runner.Stop(ctx); err != nil && logger != nil {
		logger.Warn("stop xray subprocess", "error", err)
	}
}
