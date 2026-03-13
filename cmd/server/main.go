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
	listenAddr := flag.String("listen", "0.0.0.0:6881", "listen address")
	psk := flag.String("psk", "test-psk-2026", "pre-shared key")
	forwardUDP := flag.String("forward-udp", "", "forward UDP to address (e.g. 10.0.0.1:51820 for WG)")
	transport := flag.String("transport", "utp", "transport: tcp, utp")
	enableDHT := flag.Bool("dht", false, "announce in BitTorrent DHT")
	camouflage := flag.Bool("camouflage", false, "enable BT handshake + 16KB padding")
	flag.Parse()

	_, portStr, _ := net.SplitHostPort(*listenAddr)
	var listenPort int
	fmt.Sscanf(portStr, "%d", &listenPort)

	var ln net.Listener
	var err error

	switch *transport {
	case "utp":
		// Create raw UDP socket
		udpConn, err := net.ListenPacket("udp", *listenAddr)
		if err != nil {
			log.Fatalf("listen udp: %v", err)
		}
		// Wrap in uTP — uTP packets handled internally, non-uTP (DHT) via ReadFrom
		utpSock, err := utp.NewSocketFromPacketConn(udpConn)
		if err != nil {
			log.Fatalf("utp socket: %v", err)
		}
		ln = utpSock // utp.Socket implements net.Listener

		if *enableDHT {
			// DHT shares the same UDP socket — reads non-uTP packets
			disc, err := bttdht.NewFromConn(utpSock, []byte(*psk), listenPort)
			if err != nil {
				log.Fatalf("dht init: %v", err)
			}
			defer disc.Close()

			ctx := context.Background()
			if err := disc.Bootstrap(ctx); err != nil {
				log.Printf("dht bootstrap warning: %v", err)
			}
			disc.Announce(ctx)
			log.Printf("DHT+uTP sharing port %d", listenPort)
		}

	case "tcp":
		ln, err = net.Listen("tcp", *listenAddr)
		if err != nil {
			log.Fatalf("listen: %v", err)
		}

		if *enableDHT {
			// TCP mode: DHT needs its own UDP socket
			disc, err := bttdht.New(listenPort, []byte(*psk), listenPort)
			if err != nil {
				log.Fatalf("dht init: %v", err)
			}
			defer disc.Close()

			ctx := context.Background()
			if err := disc.Bootstrap(ctx); err != nil {
				log.Printf("dht bootstrap warning: %v", err)
			}
			disc.Announce(ctx)
			log.Printf("DHT on UDP :%d, tunnel on TCP :%d", listenPort, listenPort)
		}

	default:
		log.Fatalf("unknown transport: %s", *transport)
	}
	defer ln.Close()

	log.Printf("BTT server listening on %s [%s] (PSK: %s...)", *listenAddr, *transport, (*psk)[:8])

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, []byte(*psk), *forwardUDP, *camouflage)
	}
}

func handleConn(conn net.Conn, psk []byte, forwardUDP string, camouflage bool) {
	defer conn.Close()

	log.Printf("new connection from %s", conn.RemoteAddr())

	session, err := mse.Accept(conn, psk)
	if err != nil {
		log.Printf("handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer session.Close()

	// BT protocol handshake inside encrypted session
	if camouflage {
		date := time.Now().UTC().Format("2006-01-02")
		remotePeerID, err := bt.Handshake(session, psk, date)
		if err != nil {
			log.Printf("bt handshake failed from %s: %v", conn.RemoteAddr(), err)
			return
		}
		log.Printf("BT handshake with %s (peer: %.8s)", conn.RemoteAddr(), remotePeerID)
	}

	log.Printf("session established with %s", conn.RemoteAddr())

	var pw *piece.Writer
	var pr *piece.Reader
	if camouflage {
		pw = piece.NewPaddedWriter(session)
		pr = piece.NewPaddedReader(session)
	} else {
		pw = piece.NewWriter(session)
		pr = piece.NewReader(session)
	}

	if forwardUDP != "" {
		if err := proxy.ServerProxy(forwardUDP, pr, pw); err != nil {
			log.Printf("udp proxy: %v", err)
		}
	} else {
		buf := make([]byte, 16384)
		for {
			n, err := pr.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("read: %v", err)
				}
				return
			}
			if n > 0 {
				log.Printf("received %d bytes, echoing back", n)
				if _, err := pw.Write(buf[:n]); err != nil {
					log.Printf("write: %v", err)
					return
				}
			}
		}
	}
}
