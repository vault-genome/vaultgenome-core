// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// vgconsole is the console: the application a person opens to see that the
// model is safe and to act on it, without a terminal (ADR 0039). It runs on
// the person's own computer and serves one page to their own browser on
// loopback. Everything the page shows was verified here: the chip's answer to
// a challenge made here, the journal's signatures, the stop list signed with a
// key that was made here and has never left.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/buildinfo"
)

var (
	version = "dev"
	commit  = "unknown"
)

// drillMain is `vgconsole drill`, in the kit's build only (the drill build tag):
// a person's application carries no test of itself.
var drillMain func([]string) int

func main() {
	version, commit = buildinfo.Resolve(version, commit)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("vgconsole %s (%s)\n", version, commit)
			return
		case "drill":
			if drillMain != nil {
				os.Exit(drillMain(os.Args[2:]))
			}
		case "check":
			os.Exit(checkCmd(os.Args[2:]))
		}
	}
	if err := runConsole(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vgconsole:", err)
		os.Exit(1)
	}
}

func runConsole(args []string) error {
	fs := flag.NewFlagSet("vgconsole", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "Where this person's key and servers are kept (default: the user's configuration directory)")
	port := fs.Int("port", 0, "Local port (default: any free one)")
	noOpen := fs.Bool("no-open", false, "Do not open the browser")
	tokenFlag := fs.String("token", "", "The page's access token (default: a fresh random one)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *dataDir
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(base, "VaultGenome")
	}
	app, err := newApp(dir)
	if err != nil {
		return err
	}
	for _, path := range fs.Args() {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if _, err := app.Join(raw); err != nil {
			fmt.Fprintf(os.Stderr, "vgconsole: %s: %v\n", path, err)
		}
	}
	// One console per person: opened again, it shows the page already running.
	runningPath := filepath.Join(dir, "running.url")
	if url, ok := alreadyRunning(runningPath); ok {
		if !*noOpen {
			openBrowser(url)
		}
		fmt.Fprintln(os.Stderr, "vgconsole: already running:", url)
		return nil
	}
	token := *tokenFlag
	if token == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		token = hex.EncodeToString(buf)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	url := "http://" + addr + "/#t=" + token
	if err := os.WriteFile(runningPath, []byte(url), 0o600); err != nil {
		return err
	}
	defer func() { _ = os.Remove(runningPath) }()
	fmt.Fprintln(os.Stderr, "vgconsole: open", url)
	w := newWeb(app, token, addr)
	srv := &http.Server{Handler: w.handler(), ReadHeaderTimeout: 5 * time.Second}
	if !*noOpen {
		openBrowser(url)
	}
	// With no page open for a while there is no one to serve: the process goes,
	// and the next opening starts a fresh one.
	go func() {
		for range time.Tick(time.Minute) {
			if w.idleFor() > idleLimit {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = srv.Shutdown(ctx)
				cancel()
				return
			}
		}
	}()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// idleLimit is how long the process stays with no page asking anything. A page
// that is open asks every minute.
const idleLimit = 20 * time.Minute

// alreadyRunning reads the address a console left and asks whether it answers.
func alreadyRunning(path string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	url := strings.TrimSpace(string(raw))
	base, token, ok := strings.Cut(url, "/#t=")
	if !ok || !loopbackURLRE.MatchString(base) {
		return "", false
	}
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/api/ping", nil)
	if err != nil {
		return "", false
	}
	req.Header.Set(tokenHeader, token)
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	_ = resp.Body.Close()
	return url, resp.StatusCode == http.StatusOK
}

// loopbackURLRE is the only place a console's own address can be.
var loopbackURLRE = regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]{1,5}$`)

// checkCmd asks every server this person holds a pass for, now, and prints
// what the page would show: for a script, and for a kit proving a server
// after a restart. It exits 0 only when every server proved itself.
func checkCmd(args []string) int {
	fs := flag.NewFlagSet("vgconsole check", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "This person's directory (default: the user's configuration directory)")
	lang := fs.String("lang", "en", "ru or en")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir := *dataDir
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "vgconsole check:", err)
			return 1
		}
		dir = filepath.Join(base, "VaultGenome")
	}
	app, err := newApp(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vgconsole check:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rc := 0
	for _, s := range app.Servers() {
		if _, err := s.check(ctx); err != nil {
			rc = 1
		} else if err := s.refreshJournal(ctx); err != nil {
			rc = 1
		}
		raw, _ := json.MarshalIndent(app.overview(s, *lang), "", "  ")
		fmt.Println(string(raw))
	}
	return rc
}

// openBrowser hands the page to the person's own browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(context.Background(), "open", url)
	case "windows":
		cmd = exec.CommandContext(context.Background(), "rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.CommandContext(context.Background(), "xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "vgconsole: open this in a browser:", url)
		return
	}
	go func() { _ = cmd.Wait() }()
}
