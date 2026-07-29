//go:build windows

package helper

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/windows/svc"
)

// RunService is the SCM entry point for the same tachyon-core binary. The
// service has no capture implementation by itself; it remains NotReady until
// a separately verified provider is injected.
func RunService(serviceName string, config Config) error {
	if serviceName == "" {
		serviceName = "TachyonHelper"
	}
	return svc.Run(serviceName, &serviceProgram{config: config})
}

type serviceProgram struct{ config Config }

func (program *serviceProgram) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime, err := NewRuntime(program.config)
	if err != nil {
		changes <- svc.Status{State: svc.StopPending}
		return true, 1
	}
	runResult := make(chan error, 1)
	go func() { runResult <- runtime.Run(ctx) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-runResult:
			_ = runtime.Shutdown(context.Background())
			changes <- svc.Status{State: svc.StopPending}
			if err != nil && !errors.Is(err, context.Canceled) {
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
				stopErr := runtime.Shutdown(stopContext)
				stopCancel()
				if stopErr != nil {
					return true, 1
				}
				return false, 0
			}
		}
	}
}
