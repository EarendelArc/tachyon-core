package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
	"time"
)

type State string

const (
	StateStopped State = "stopped"
	StateRunning State = "running"
	StateFailed  State = "failed"
)

type XrayRunConfig struct {
	BinaryPath string
	ConfigPath string
	WorkDir    string
	Args       []string
	Env        map[string]string
}

type Status struct {
	State   State
	PID     int
	Version string
	Since   time.Time
	LastErr string
}

type ProxyRunner interface {
	Start(ctx context.Context, cfg XrayRunConfig) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context, cfg XrayRunConfig) error
	Status(ctx context.Context) (Status, error)
	Stdout() io.Reader
	Stderr() io.Reader
}

type SubProcessRunner struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
	status Status
}

func NewSubProcessRunner() *SubProcessRunner {
	return &SubProcessRunner{
		status: Status{State: StateStopped},
	}
}

func (r *SubProcessRunner) Start(ctx context.Context, cfg XrayRunConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cmd != nil && r.status.State == StateRunning {
		return errors.New("xray runner already started")
	}
	if cfg.BinaryPath == "" {
		return errors.New("xray binary path is required")
	}

	args := cfg.Args
	if len(args) == 0 && cfg.ConfigPath != "" {
		args = []string{"run", "-config", cfg.ConfigPath}
	}

	cmd := exec.CommandContext(ctx, cfg.BinaryPath, args...)
	cmd.Dir = cfg.WorkDir
	for key, value := range cfg.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	cmd.Stdout = &r.stdout
	cmd.Stderr = &r.stderr

	if err := cmd.Start(); err != nil {
		r.status = Status{State: StateFailed, Since: time.Now(), LastErr: err.Error()}
		return err
	}

	r.cmd = cmd
	r.status = Status{State: StateRunning, PID: cmd.Process.Pid, Since: time.Now()}

	go r.wait(cmd)
	return nil
}

func (r *SubProcessRunner) Stop(ctx context.Context) error {
	r.mu.Lock()
	cmd := r.cmd
	r.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Process.Kill()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (r *SubProcessRunner) Restart(ctx context.Context, cfg XrayRunConfig) error {
	if err := r.Stop(ctx); err != nil {
		return err
	}
	return r.Start(ctx, cfg)
}

func (r *SubProcessRunner) Status(context.Context) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status, nil
}

func (r *SubProcessRunner) Stdout() io.Reader {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.NewReader(r.stdout.Bytes())
}

func (r *SubProcessRunner) Stderr() io.Reader {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.NewReader(r.stderr.Bytes())
}

func (r *SubProcessRunner) wait(cmd *exec.Cmd) {
	err := cmd.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cmd != cmd {
		return
	}

	if err != nil {
		r.status.State = StateFailed
		r.status.LastErr = err.Error()
	} else {
		r.status.State = StateStopped
		r.status.LastErr = ""
	}
	r.status.PID = 0
	r.cmd = nil
}
