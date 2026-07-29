// tachyon-core: cross-platform network daemon for the Tachyon system.
//
// Usage:
//
//	tachyon-core run --config /etc/tachyon/config.json
//	tachyon-core version
//	tachyon-core validate --config config.json
//	tachyon-core doctor --config config.json --json
//	tachyon-core generate-config --mode client > config.json
//	tachyon-core generate-config --mode server > config.json
//	tachyon-core helper --console --pipe \\\\.\\pipe\\Tachyon\\captured-udp-v2
//	tachyon-core helper --service --pipe \\\\.\\pipe\\Tachyon\\captured-udp-v2
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/app"
	"github.com/tachyon-space/tachyon-core/internal/cli"
	"github.com/tachyon-space/tachyon-core/internal/config"
	"github.com/tachyon-space/tachyon-core/internal/doctor"
	"github.com/tachyon-space/tachyon-core/internal/helper"
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
	case "help", "-h", "--help":
		fmt.Fprint(os.Stderr, cli.Usage())
		return nil

	case "version", "-v", "--version":
		fmt.Printf("tachyon-core %s (built %s with %s)\n", Version, BuildTime, GoVersion)
		return nil

	case "generate-config":
		return cmdGenerateConfig(args[1:])

	case "validate":
		return cmdValidateConfig(args[1:])

	case "doctor", "preflight":
		return cmdDoctor(args[1:])

	case "run":
		return cmdRun(args[1:])

	case "helper":
		return cmdHelper(args[1:])

	default:
		fmt.Fprint(os.Stderr, cli.Usage())
		return fmt.Errorf("unknown command: %q", args[0])
	}
}

func cmdHelper(args []string) error {
	if cli.HasHelp(args) {
		fmt.Fprint(os.Stderr, cli.Usage())
		return nil
	}
	serviceName := cli.FlagValue(args, "--service-name", "", "TachyonHelper")
	config := helper.Config{
		PipeName:            cli.FlagValue(args, "--pipe", "-p", `\\.\pipe\Tachyon\captured-udp-v2`),
		ServerSIDs:          []string{cli.FlagValue(args, "--server-sid", "", "")},
		TrustedServerBinary: cli.FlagValue(args, "--core-binary", "", ""),
		TrustedServerSHA256: cli.FlagValue(args, "--core-sha256", "", ""),
		ServiceName:         serviceName,
		DiagnosticFile:      cli.FlagValue(args, "--diagnostic-file", "", ""),
		DiagnosticOverride:  cli.FlagPresent(args, "--diagnostic-test-override"),
		OperationTimeout:    10 * time.Second,
		ReconnectMin:        100 * time.Millisecond,
		ReconnectMax:        5 * time.Second,
	}
	if cli.FlagPresent(args, "--service") {
		return helper.RunService(serviceName, config)
	}
	if cli.FlagPresent(args, "--test-server") {
		config.AllowedSIDs = []string{cli.FlagValue(args, "--allow-sid", "", "")}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return helper.RunTestServer(ctx, config)
	}
	runtime, err := helper.NewRuntime(config)
	if err != nil {
		return fmt.Errorf("initialise helper: %w", err)
	}
	defer runtime.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runtime.Run(ctx); err != nil {
		return fmt.Errorf("helper error: %w", err)
	}
	return nil
}

func cmdRun(args []string) error {
	if cli.HasHelp(args) {
		fmt.Fprint(os.Stderr, cli.Usage())
		return nil
	}
	configPath := cli.FlagValue(args, "--config", "-c", "config.json")

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
	if cli.HasHelp(args) {
		fmt.Fprint(os.Stderr, cli.Usage())
		return nil
	}
	configPath := cli.FlagValue(args, "--config", "-c", "config.json")
	mode, err := cli.ValidateConfig(configPath)
	if err != nil {
		return err
	}
	fmt.Printf("config %q is valid (mode: %s)\n", configPath, mode)
	return nil
}

func cmdDoctor(args []string) error {
	if cli.HasHelp(args) {
		fmt.Fprint(os.Stderr, cli.Usage())
		return nil
	}
	configPath := cli.FlagValue(args, "--config", "-c", "config.json")
	report := doctor.Run(configPath)
	data, err := report.JSON()
	if err != nil {
		return fmt.Errorf("render doctor report: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func cmdGenerateConfig(args []string) error {
	if cli.HasHelp(args) {
		fmt.Fprint(os.Stderr, cli.Usage())
		return nil
	}
	mode := config.Mode(cli.FlagValue(args, "--mode", "-m", "client"))

	tmpl, err := cli.GenerateConfig(mode)
	if err != nil {
		return err
	}
	fmt.Print(tmpl)
	return nil
}
