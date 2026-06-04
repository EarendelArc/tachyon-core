package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tachyon-space/tachyon-core/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	daemon := app.New(app.Config{
		Name:          "tachyon-core",
		Version:       "0.1.0-dev",
		IPCListenAddr: "127.0.0.1:55123",
		ConfigPath:    "tachyon-core.config.json",
	})

	if err := daemon.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "tachyon-core failed: %v\n", err)
		os.Exit(1)
	}
}
