package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Version is injected at build time via -ldflags.
var (
	Version   = "dev"
	GoVersion = "unknown"
	BuildTime = "unknown"
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "tachyonctl - Tachyon Core control CLI\n\nUSAGE:\n  tachyonctl <command> [options]\n\nCOMMANDS:\n  health           Query the Core health endpoint\n    --addr/-a      Core HTTP address (default: 127.0.0.1:55123)\n\n  version          Print version information\n")
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		return
	}

	switch args[0] {
	case "version", "-v", "--version":
		fmt.Printf("tachyonctl %s (built %s with %s)\n", Version, BuildTime, GoVersion)
	case "health":
		cmdHealth(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", args[0])
		flag.Usage()
		os.Exit(1)
	}
}

func cmdHealth(args []string) {
	addr := "127.0.0.1:55123"
	for i, a := range args {
		if (a == "--addr" || a == "-a") && i+1 < len(args) {
			addr = args[i+1]
		}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/v1/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "health check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		fmt.Printf("%d %s\n", resp.StatusCode, string(body))
		return
	}
	pretty, _ := json.MarshalIndent(parsed, "", "  ")
	fmt.Printf("%d\n%s\n", resp.StatusCode, string(pretty))
}
