package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/tachyon-space/tachyon-core/internal/ipc"
	"github.com/tachyon-space/tachyon-core/internal/routing"
)

type Config struct {
	Name          string
	Version       string
	IPCListenAddr string
	ConfigPath    string
}

type App struct {
	cfg Config
}

func New(cfg Config) *App {
	return &App{cfg: cfg}
}

func (a *App) Run(ctx context.Context) error {
	configPath := a.cfg.ConfigPath
	if configPath == "" {
		configPath = "tachyon-core.config.json"
	}
	if envPath := os.Getenv("TACHYON_CORE_CONFIG"); envPath != "" {
		configPath = envPath
	}

	routingService := routing.NewService(routing.NewFileStore(configPath))
	ipcServer := ipc.NewHTTPServer(routingService)
	httpServer := &http.Server{
		Addr:              a.cfg.IPCListenAddr,
		Handler:           ipcServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("%s %s listening on http://%s\n", a.cfg.Name, a.cfg.Version, a.cfg.IPCListenAddr)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return ctx.Err()
		}
		return err
	}
}
