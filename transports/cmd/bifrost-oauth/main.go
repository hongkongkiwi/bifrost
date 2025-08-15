package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/pkg/browser"
)

func main() {
	server := flag.String("server", defaultString(os.Getenv("BIFROST_SERVER"), "http://localhost:8080"), "Bifrost server URL")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  bifrost-oauth gui [--server URL]\n")
		fmt.Fprintf(os.Stderr, "  bifrost-oauth anthropic --client-id ID [--mode max|console] [--server URL]\n")
		fmt.Fprintf(os.Stderr, "  bifrost-oauth qwen [--server URL]\n\n")
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	sub := flag.Arg(0)
	switch sub {
	case "gui":
		openURL(join(*server, "/oauth"))
	case "anthropic":
		anthropicCmd(*server, flag.Args()[1:])
	case "qwen":
		qwenCmd(*server)
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func anthropicCmd(server string, args []string) {
	fs := flag.NewFlagSet("anthropic", flag.ExitOnError)
	clientID := fs.String("client-id", "", "Anthropic OAuth client id")
	mode := fs.String("mode", "max", "Login mode: max or console")
	_ = fs.Parse(args)
	if strings.TrimSpace(*clientID) == "" {
		fmt.Fprintln(os.Stderr, "--client-id is required")
		os.Exit(2)
	}
	u := join(server, "/oauth/anthropic/start")
	parsed, _ := url.Parse(u)
	q := parsed.Query()
	q.Set("client_id", *clientID)
	q.Set("mode", *mode)
	parsed.RawQuery = q.Encode()
	openURL(parsed.String())
}

func qwenCmd(server string) {
	fmt.Println("Enter your DashScope API key (input hidden not supported; paste carefully):")
	fmt.Print("> ")
	in := bufio.NewReader(os.Stdin)
	key, _ := in.ReadString('\n')
	key = strings.TrimSpace(key)
	if key == "" {
		fmt.Fprintln(os.Stderr, "Empty key")
		os.Exit(2)
	}
	endpoint := join(server, "/oauth/qwen/save-key")
	resp, err := http.PostForm(endpoint, url.Values{"api_key": {key}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "Server error: %s\n", resp.Status)
		os.Exit(1)
	}
	fmt.Println("Saved. Qwen is ready via DashScope.")
}

func openURL(u string) {
	fmt.Println("Opening:", u)
	_ = browser.OpenURL(u)
}

func join(base, p string) string {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}

func defaultString(v, d string) string { if strings.TrimSpace(v) == "" { return d }; return v }
