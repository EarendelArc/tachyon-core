package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tachyon-space/tachyon-core/internal/cli"
)

// Version is injected at build time via -ldflags.
var (
	Version   = "dev"
	GoVersion = "unknown"
	BuildTime = "unknown"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, cli.CtlUsage())
		return
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(os.Stderr, cli.CtlUsage())

	case "version", "-v", "--version":
		fmt.Printf("tachyonctl %s (built %s with %s)\n", Version, BuildTime, GoVersion)

	case "health":
		cmdHealth(args[1:])

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", args[0])
		fmt.Fprint(os.Stderr, cli.CtlUsage())
		os.Exit(1)
	}
}

func cmdHealth(args []string) {
	if cli.HasHelp(args) {
		fmt.Fprint(os.Stderr, cli.CtlUsage())
		return
	}
	addr := cli.FlagValue(args, "--addr", "-a", "127.0.0.1:55123")
	if !hasFlag(args, "--token-stdin") {
		fmt.Fprintln(os.Stderr, "health requires --token-stdin; bearer tokens are never accepted in argv or environment")
		os.Exit(1)
	}
	token, err := bufio.NewReader(io.LimitReader(os.Stdin, 4096)).ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintln(os.Stderr, "read IPC token from stdin")
		os.Exit(1)
	}
	token = strings.TrimSpace(token)

	resp, err := cli.HealthCheck(addr, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if raw, ok := resp.Body["raw"]; ok {
		fmt.Printf("%d %s\n", resp.StatusCode, raw)
		return
	}
	pretty, _ := json.MarshalIndent(resp.Body, "", "  ")
	fmt.Printf("%d\n%s\n", resp.StatusCode, string(pretty))
}

func hasFlag(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}
