package app

import (
	"context"
	"fmt"
)

type Config struct {
	Name          string
	Version       string
	IPCListenAddr string
}

type App struct {
	cfg Config
}

func New(cfg Config) *App {
	return &App{cfg: cfg}
}

func (a *App) Run(ctx context.Context) error {
	fmt.Printf("%s %s listening on %s\n", a.cfg.Name, a.cfg.Version, a.cfg.IPCListenAddr)
	<-ctx.Done()
	return ctx.Err()
}
