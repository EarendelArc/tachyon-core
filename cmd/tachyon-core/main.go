// tachyon-core: cross-platform network daemon for the Tachyon system.
//
// Usage:
//
//	tachyon-core run --config /etc/tachyon/config.json
//	tachyon-core version
//	tachyon-core validate --config config.json
//	tachyon-core generate-config --mode client > config.json
//	tachyon-core generate-config --mode server > config.json
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tachyon-space/tachyon-core/internal/app"
	"github.com/tachyon-space/tachyon-core/internal/cli"
	"github.com/tachyon-space/tachyon-core/internal/config"
)

// Version is injected at build time via -ldflags.
var (
	Version   = "dev"
	GoVersion = "unknown"
	BuildTime = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, cli.Usage())
		return nil
	}

	switch args[0] {
	case "version", "-v", "--version":
		fmt.Printf("tachyon-core %s (built %s with %s)\n", Version, BuildTime, GoVersion)
		return nil

	case "generate-config":
		return cmdGenerateConfig(args[1:])

	case "validate":
		return cmdValidateConfig(args[1:])

	case "run":
		return cmdRun(args[1:])

	default:
		fmt.Fprint(os.Stderr, cli.Usage())
		return fmt.Errorf("unknown command: %q", args[0])
	}
}

func cmdRun(args []string) error {
	configPath := "config.json"
	for i, a := range args {
		if (a == "--config" || a == "-c") && i+1 < len(args) {
			configPath = args[i+1]
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := cli.BuildLogger(cfg.Observability.LogLevel, cfg.Observability.LogFile)
	slog.SetDefault(logger)

	slog.Info("tachyon-core starting",
		"version", Version,
		"mode", cfg.Mode,
		"config", configPath,
	)

	application, err := app.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("initialise application: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := application.Run(ctx); err != nil {
		return fmt.Errorf("application error: %w", err)
	}

	slog.Info("tachyon-core stopped cleanly")
	return nil
}

func cmdValidateConfig(args []string) error {
	configPath := "config.json"
	for i, a := range args {
		if (a == "--config" || a == "-c") && i+1 < len(args) {
			configPath = args[i+1]
		}
	}
	mode, err := cli.ValidateConfig(configPath)
	if err != nil {
		return err
	}
	fmt.Printf("config %q is valid (mode: %s)\n", configPath, mode)
	return nil
}

func cmdGenerateConfig(args []string) error {
	mode := config.ModeClient
	for i, a := range args {
		if (a == "--mode" || a == "-m") && i+1 < len(args) {
			mode = config.Mode(args[i+1])
		}
	}

	tmpl, err := cli.GenerateConfig(mode)
	if err != nil {
		return err
	}
	fmt.Print(tmpl)
	return nil
}