// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command parent runs on the Nitro enclave's parent instance for the
// cross-cloud key release (ADR 0036, part four). An enclave has no
// network; the parent is its only way in and out, and is not trusted. It
// forwards bytes and reads none of them: the source's TLS from a TCP port
// to acp-bootstrap's vsock port, the enclave's TLS to KMS's endpoint, the
// enclave's HTTP to the instance metadata service. It hands the enclave
// its key files — sealed to the image, so ciphertext — and keeps the log
// the enclave sends, since a production-mode enclave has no console. It
// listens and dials with internal/shared/vsock, the package acp-bootstrap
// serves on.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/vsock"
)

func main() {
	region := flag.String("region", "us-east-2", "KMS's Region")
	listen := flag.String("listen", "0.0.0.0:8443", "the TCP address the source reaches the enclave's API on")
	enclaveCID := flag.Uint("enclave-cid", 16, "the enclave's CID")
	apiPort := flag.Uint("api-port", 5000, "the enclave's vsock port acp-bootstrap listens on (http.listen_vsock_port)")
	kmsPort := flag.Uint("kms-port", 8000, "vsock port forwarded to kms.<region>.amazonaws.com:443 (tee.aws_kms.kms_vsock_port)")
	imdsPort := flag.Uint("imds-port", 8002, "vsock port forwarded to the instance metadata service (tee.aws_kms.imds_vsock_port)")
	// Not 9000: nitro-cli listens there for the enclave's boot heartbeat
	// (init.c of aws-nitro-enclaves-sdk-bootstrap: CID 3, port 9000).
	filesPort := flag.Uint("files-port", 7000, "vsock port that hands the enclave its key files (tee.secret_files_vsock_port)")
	logPort := flag.Uint("log-port", 7001, "vsock port the enclave's log comes in on (log.vsock_port)")
	filesPath := flag.String("files", "", "the key files as the enclave reads them, JSON; read again for every enclave that asks")
	outDir := flag.String("out", ".", "where the enclave's logs are kept")
	flag.Parse()
	if *filesPath == "" {
		log.Fatal("parent: -files is required")
	}
	kmsTarget := net.JoinHostPort("kms."+*region+".amazonaws.com", "443")
	cid, api := uint32(*enclaveCID), uint32(*apiPort)
	closers := []io.Closer{
		listenVsock(uint32(*kmsPort), "kms", func(c net.Conn) {
			forward(c, "kms", func(ctx context.Context) (net.Conn, error) { return dialTCP(ctx, kmsTarget) })
		}),
		listenVsock(uint32(*imdsPort), "imds", func(c net.Conn) {
			forward(c, "imds", func(ctx context.Context) (net.Conn, error) { return dialTCP(ctx, "169.254.169.254:80") })
		}),
		listenVsock(uint32(*filesPort), "files", func(c net.Conn) { handFiles(c, *filesPath) }),
		listenVsock(uint32(*logPort), "log", func(c net.Conn) { keepLog(c, *outDir) }),
		listenTCP(*listen, "api", func(c net.Conn) {
			forward(c, "api", func(ctx context.Context) (net.Conn, error) { return vsock.Dial(ctx, cid, api) })
		}),
	}
	log.Printf("parent: %s to the enclave's vsock %d:%d; vsock %d to %s, %d to the metadata service; key files on %d, the log on %d",
		*listen, cid, api, *kmsPort, kmsTarget, *imdsPort, *filesPort, *logPort)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	for _, c := range closers {
		_ = c.Close()
	}
	log.Print("parent: stopped")
}

func dialTCP(ctx context.Context, target string) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, "tcp", target)
}

func listenVsock(port uint32, what string, serve func(net.Conn)) net.Listener {
	l, err := vsock.Listen(port)
	if err != nil {
		log.Fatalf("parent: listen vsock %d (%s): %v", port, what, err)
	}
	go accept(l, what, serve)
	return l
}

func listenTCP(addr, what string, serve func(net.Conn)) net.Listener {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("parent: listen %s (%s): %v", addr, what, err)
	}
	go accept(l, what, serve)
	return l
}

func accept(l net.Listener, what string, serve func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("parent: %s: accept: %v", what, err)
			continue
		}
		log.Printf("parent: %s: connection from %s", what, c.RemoteAddr())
		go serve(c)
	}
}

// forward copies bytes both ways between c and a connection dial makes;
// it reads none of them.
func forward(c net.Conn, what string, dial func(context.Context) (net.Conn, error)) {
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t, err := dial(ctx)
	cancel()
	if err != nil {
		log.Printf("parent: %s: dial: %v", what, err)
		return
	}
	defer func() { _ = t.Close() }()
	var up, down int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		up, _ = io.Copy(t, c)
		closeWrite(t)
	}()
	go func() {
		defer wg.Done()
		down, _ = io.Copy(c, t)
		closeWrite(c)
	}()
	wg.Wait()
	log.Printf("parent: %s: %d bytes one way, %d the other", what, up, down)
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// handFiles writes the key files and waits for the enclave to close: it
// reads one JSON value and closes first, so the answer is never cut short
// (ENOTCONN on the enclave's kernel, part four's first stage).
func handFiles(c net.Conn, path string) {
	defer func() { _ = c.Close() }()
	files, err := os.ReadFile(path)
	if err != nil {
		log.Printf("parent: files: %v", err)
		return
	}
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	n, err := c.Write(files)
	log.Printf("parent: files: %d bytes handed over (%v)", n, err)
	rest, err := io.Copy(io.Discard, c)
	log.Printf("parent: files: the enclave closed (%d bytes back, %v)", rest, err)
}

var logs atomic.Int32

// keepLog appends the enclave's log lines to a file per connection.
func keepLog(c net.Conn, dir string) {
	defer func() { _ = c.Close() }()
	n := logs.Add(1)
	path := filepath.Join(dir, fmt.Sprintf("enclave-log-%d.jsonl", n))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("parent: log: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(io.LimitReader(c, 64<<20))
	lines := 0
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			_, _ = f.Write(line)
			lines++
		}
		if err != nil {
			break
		}
	}
	log.Printf("parent: log: %d lines kept in %s", lines, path)
}
