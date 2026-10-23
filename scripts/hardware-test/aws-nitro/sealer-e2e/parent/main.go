// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command parent runs on the Nitro enclave's parent instance for the
// sealer's hardware run (ADR 0036, part four, stage one). An enclave has no
// network; the parent is its only way out, and is not trusted. It
// forwards bytes — the enclave's TLS to KMS's endpoint, the enclave's
// HTTP to the instance metadata service — hands the enclave the sealed
// files, and keeps the report the enclave sends back. It listens with
// internal/shared/vsock, the package acp-bootstrap serves on.
package main

import (
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

const maxReport = 1 << 20

func main() {
	region := flag.String("region", "us-east-2", "KMS's Region")
	kmsPort := flag.Uint("kms-port", 8000, "vsock port forwarded to kms.<region>.amazonaws.com:443")
	imdsPort := flag.Uint("imds-port", 8002, "vsock port forwarded to the instance metadata service")
	// Not 9000: nitro-cli listens there for the enclave's boot heartbeat
	// (init.c of aws-nitro-enclaves-sdk-bootstrap: CID 3, port 9000).
	filesPort := flag.Uint("files-port", 7000, "vsock port that hands the enclave the sealed files")
	reportPort := flag.Uint("report-port", 7001, "vsock port the enclave sends its report to")
	bundlePath := flag.String("bundle", "", "the sealed files, as the enclave reads them (JSON)")
	outDir := flag.String("out", ".", "where the reports are written")
	flag.Parse()
	if *bundlePath == "" {
		log.Fatal("parent: -bundle is required")
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		log.Fatal(err)
	}
	kmsTarget := net.JoinHostPort("kms."+*region+".amazonaws.com", "443")
	listeners := []net.Listener{
		listen(uint32(*kmsPort), "kms", func(c net.Conn) { forward(c, kmsTarget) }),
		listen(uint32(*imdsPort), "imds", func(c net.Conn) { forward(c, "169.254.169.254:80") }),
		listen(uint32(*filesPort), "files", func(c net.Conn) { handFiles(c, bundle) }),
		listen(uint32(*reportPort), "report", func(c net.Conn) { keepReport(c, *outDir) }),
	}
	log.Printf("parent: forwarding vsock %d to %s, %d to the metadata service; files on %d, reports on %d", *kmsPort, kmsTarget, *imdsPort, *filesPort, *reportPort)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	for _, l := range listeners {
		_ = l.Close()
	}
	log.Print("parent: stopped")
}

func listen(port uint32, what string, serve func(net.Conn)) net.Listener {
	l, err := vsock.Listen(port)
	if err != nil {
		log.Fatalf("parent: listen vsock %d (%s): %v", port, what, err)
	}
	go func() {
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
	}()
	return l
}

// forward copies bytes both ways between the enclave's connection and a
// TCP connection to target; it reads none of them.
func forward(c net.Conn, target string) {
	defer func() { _ = c.Close() }()
	t, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		log.Printf("parent: dial %s: %v", target, err)
		return
	}
	defer func() { _ = t.Close() }()
	var up, down int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		up, _ = io.Copy(t, c)
		if tc, ok := t.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		down, _ = io.Copy(c, t)
		_ = c.Close()
	}()
	wg.Wait()
	log.Printf("parent: %s: %d bytes up, %d down", target, up, down)
}

// handFiles writes the sealed files and then waits for the enclave to
// close: the enclave reads one JSON value and closes. The parent does not
// close first — on the enclave's kernel a peer's shutdown that arrives
// before the reader has read can leave the reader's socket disconnected
// with ENOTCONN instead of the data (the third run, 2026-10-23T13:01Z).
func handFiles(c net.Conn, bundle []byte) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	n, err := c.Write(bundle)
	log.Printf("parent: files: %d bytes handed over (%v)", n, err)
	rest, err := io.Copy(io.Discard, c)
	log.Printf("parent: files: the enclave closed (%d bytes back, %v)", rest, err)
}

var reports atomic.Int32

func keepReport(c net.Conn, dir string) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	raw, err := io.ReadAll(io.LimitReader(c, maxReport+1))
	if err != nil || len(raw) > maxReport {
		log.Printf("parent: report: %d bytes, %v", len(raw), err)
		return
	}
	n := reports.Add(1)
	path := filepath.Join(dir, fmt.Sprintf("enclave-report-%d.json", n))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		log.Printf("parent: report: %v", err)
		return
	}
	log.Printf("parent: report: %d bytes kept in %s", len(raw), path)
}
