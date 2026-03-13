package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/anacrolix/utp"
	"github.com/evg/btt-transport/bt"
	bttdht "github.com/evg/btt-transport/dht"
	"github.com/evg/btt-transport/mse"
	"github.com/evg/btt-transport/piece"
	"github.com/evg/btt-transport/proxy"
)

func main() {
	serverAddr := flag.String("server", "", "server address (skip DHT lookup)")
	psk := flag.String("psk", "test-psk-2026", "pre-shared key")
	mode := flag.String("mode", "echo", "mode: echo, bench, udp-proxy")
	transport := flag.String("transport", "utp", "transport: tcp, utp")
	listenUDP := flag.String("listen-udp", "0.0.0.0:51821", "local UDP listen for WG client")
	enableDHT := flag.Bool("dht", false, "discover server via BitTorrent DHT")
	camouflage := flag.Bool("camouflage", false, "enable BT handshake + 16KB padding")
	flag.Parse()

	target := resolveTarget(*serverAddr, *enableDHT, *psk)

	switch *mode {
	case "echo":
		// One-shot modes: connect once, run, exit
		pw, pr, closer := connect(target, *transport, *psk, *camouflage)
		defer closer()
		echoTest(pw, pr)
	case "bench":
		pw, pr, closer := connect(target, *transport, *psk, *camouflage)
		defer closer()
		benchTest(pw, pr)
	case "udp-proxy":
		runProxyLoop(target, *transport, *psk, *camouflage, *listenUDP)
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}

// resolveTarget finds the server address via DHT or uses the provided one.
func resolveTarget(serverAddr string, enableDHT bool, psk string) string {
	target := serverAddr

	if enableDHT && target == "" {
		log.Printf("discovering server via DHT...")

		disc, err := bttdht.New(0, []byte(psk), 0)
		if err != nil {
			log.Fatalf("dht init: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		if err := disc.Bootstrap(ctx); err != nil {
			log.Printf("dht bootstrap warning: %v", err)
		}

		peers, err := disc.FindPeers(ctx)
		cancel()
		disc.Close()

		if err != nil {
			log.Fatalf("dht discovery: %v", err)
		}
		target = peers[0].Addr()
		log.Printf("DHT discovered server: %s", target)
	}

	if target == "" {
		target = "127.0.0.1:6881"
	}
	return target
}

// connect establishes a full BTT session: uTP/TCP → MSE → BT handshake → piece framing.
// Returns piece writer, reader, and a cleanup function.
func connect(target, transport, psk string, camouflage bool) (*piece.Writer, *piece.Reader, func()) {
	log.Printf("connecting to %s [%s]", target, transport)

	var conn net.Conn
	var err error

	switch transport {
	case "utp":
		conn, err = utp.Dial(target)
	case "tcp":
		conn, err = net.DialTimeout("tcp", target, 5*time.Second)
	default:
		log.Fatalf("unknown transport: %s", transport)
	}
	if err != nil {
		log.Fatalf("dial: %v", err)
	}

	session, err := mse.Handshake(conn, []byte(psk))
	if err != nil {
		conn.Close()
		log.Fatalf("handshake: %v", err)
	}

	if camouflage {
		date := time.Now().UTC().Format("2006-01-02")
		remotePeerID, err := bt.Handshake(session, []byte(psk), date)
		if err != nil {
			session.Close()
			log.Fatalf("bt handshake: %v", err)
		}
		log.Printf("BT handshake OK (peer: %.8s)", remotePeerID)
	}

	log.Printf("session established with %s", target)

	var pw *piece.Writer
	var pr *piece.Reader
	if camouflage {
		pw = piece.NewPaddedWriter(session)
		pr = piece.NewPaddedReader(session)
	} else {
		pw = piece.NewWriter(session)
		pr = piece.NewReader(session)
	}

	closer := func() {
		pw.StopKeepalive()
		session.Close()
		conn.Close()
	}
	return pw, pr, closer
}

// tryConnect is like connect but returns an error instead of calling log.Fatalf.
func tryConnect(target, transport, psk string, camouflage bool) (*piece.Writer, *piece.Reader, func(), error) {
	log.Printf("connecting to %s [%s]", target, transport)

	var conn net.Conn
	var err error

	switch transport {
	case "utp":
		conn, err = utp.Dial(target)
	case "tcp":
		conn, err = net.DialTimeout("tcp", target, 5*time.Second)
	default:
		return nil, nil, nil, fmt.Errorf("unknown transport: %s", transport)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial: %w", err)
	}

	session, err := mse.Handshake(conn, []byte(psk))
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("mse handshake: %w", err)
	}

	if camouflage {
		date := time.Now().UTC().Format("2006-01-02")
		remotePeerID, err := bt.Handshake(session, []byte(psk), date)
		if err != nil {
			session.Close()
			return nil, nil, nil, fmt.Errorf("bt handshake: %w", err)
		}
		log.Printf("BT handshake OK (peer: %.8s)", remotePeerID)
	}

	log.Printf("session established with %s", target)

	var pw *piece.Writer
	var pr *piece.Reader
	if camouflage {
		pw = piece.NewPaddedWriter(session)
		pr = piece.NewPaddedReader(session)
	} else {
		pw = piece.NewWriter(session)
		pr = piece.NewReader(session)
	}

	closer := func() {
		pw.StopKeepalive()
		session.Close()
		conn.Close()
	}
	return pw, pr, closer, nil
}

const keepaliveInterval = 30 * time.Second

// runProxyLoop runs the UDP proxy with auto-reconnect.
// The UDP listener persists across reconnections so WireGuard doesn't lose its endpoint.
func runProxyLoop(target, transport, psk string, camouflage bool, listenAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("resolve udp: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	log.Printf("UDP proxy listening on %s (persistent)", listenAddr)

	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		pw, pr, closer, err := tryConnect(target, transport, psk, camouflage)
		if err != nil {
			log.Printf("connection failed: %v (retry in %v)", err, backoff)
			time.Sleep(backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		// Reset backoff on successful connection
		backoff = time.Second

		// Start keepalive
		pw.StartKeepalive(keepaliveInterval)

		// Run proxy until it breaks
		err = proxySession(udpConn, pr, pw)
		closer()

		if err != nil {
			log.Printf("session lost: %v (reconnecting...)", err)
		} else {
			log.Printf("session ended (reconnecting...)")
		}

		// Brief pause before reconnect
		time.Sleep(time.Second)
	}
}

// proxySession runs bidirectional proxying for one BTT session.
// Returns when the session breaks.
func proxySession(udpConn *net.UDPConn, streamR io.Reader, streamW io.Writer) error {
	var clientAddr net.UDPAddr
	done := make(chan struct{})
	errCh := make(chan error, 2)

	// UDP → Stream (WG client → tunnel)
	go func() {
		proxy.UDPToStream(udpConn, streamW, &clientAddr, done)
		errCh <- fmt.Errorf("udp→stream ended")
	}()

	// Stream → UDP (tunnel → WG client)
	go func() {
		proxy.StreamToUDP(streamR, udpConn, func() *net.UDPAddr {
			if clientAddr.Port == 0 {
				return nil
			}
			a := clientAddr
			return &a
		}, done)
		errCh <- fmt.Errorf("stream→udp ended")
	}()

	// Wait for either direction to fail
	err := <-errCh
	close(done)
	return err
}

func echoTest(pw *piece.Writer, pr *piece.Reader) {
	msg := []byte("Hello from BTT client over uTP!")
	log.Printf("sending: %s", msg)

	if _, err := pw.Write(msg); err != nil {
		log.Fatalf("write: %v", err)
	}

	buf := make([]byte, 16384)
	n, err := pr.Read(buf)
	if err != nil {
		log.Fatalf("read: %v", err)
	}

	log.Printf("received: %s", buf[:n])

	if string(buf[:n]) == string(msg) {
		log.Printf("echo test PASSED (uTP + MSE + piece framing)")
	} else {
		log.Fatalf("echo test FAILED: expected %q, got %q", msg, buf[:n])
	}
}

func benchTest(pw *piece.Writer, pr *piece.Reader) {
	payload := make([]byte, 16000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	const totalBytes = 100 * 1024 * 1024
	iterations := totalBytes / len(payload)

	done := make(chan int64)
	go func() {
		buf := make([]byte, 16384)
		var total int64
		for i := 0; i < iterations; i++ {
			n, err := pr.Read(buf)
			if err != nil {
				log.Printf("bench read error at iteration %d: %v", i, err)
				break
			}
			total += int64(n)
		}
		done <- total
	}()

	start := time.Now()

	for i := 0; i < iterations; i++ {
		if _, err := pw.Write(payload); err != nil {
			log.Fatalf("bench write: %v", err)
		}
	}

	received := <-done
	elapsed := time.Since(start)

	sent := int64(iterations) * int64(len(payload))
	mbps := float64(sent) * 8 / elapsed.Seconds() / 1_000_000

	fmt.Println("=== BTT Benchmark (uTP + MSE + Piece Framing) ===")
	fmt.Printf("Sent:       %d MB\n", sent/1024/1024)
	fmt.Printf("Received:   %d MB\n", received/1024/1024)
	fmt.Printf("Time:       %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Throughput: %.1f Mbps\n", mbps)
	fmt.Printf("Stack:      uTP → MSE (ChaCha20) → BT piece framing\n")
}
