// BTT relay — transparent byte-level forwarder between client and server.
//
// The relay does NOT decrypt traffic. MSE handshake passes through end-to-end.
// Relay needs PSK only for DHT (to compute info_hash for announce/lookup).
//
// Works behind NAT: uses UPnP to open a port, then accepts incoming client
// connections and relays them to the server. DHT announces with ImpliedPort
// so peers learn the external (post-NAT) port.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/anacrolix/utp"
	bttdht "github.com/evg/btt-transport/dht"
	"github.com/evg/btt-transport/upnp"
)

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:6881", "listen address")
	psk := flag.String("psk", "test-psk-2026", "pre-shared key")
	serverAddr := flag.String("server", "", "server address (direct, skip DHT)")
	enableDHT := flag.Bool("dht", false, "enable DHT (announce as relay + discover server)")
	enableUPnP := flag.Bool("upnp", false, "auto-open port via UPnP")
	flag.Parse()

	_, portStr, _ := net.SplitHostPort(*listenAddr)
	var listenPort int
	fmt.Sscanf(portStr, "%d", &listenPort)

	target := *serverAddr

	// UPnP port mapping
	var upnpMapping *upnp.Mapping
	if *enableUPnP {
		localIP, err := upnp.LocalIP()
		if err != nil {
			log.Printf("UPnP: can't determine local IP: %v", err)
		} else {
			m, err := upnp.Add(localIP, listenPort, "UDP")
			if err != nil {
				log.Printf("UPnP: %v (continuing without)", err)
			} else {
				upnpMapping = m
			}
		}
	}

	// Clean up UPnP on exit
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("shutting down...")
		upnpMapping.Remove()
		os.Exit(0)
	}()

	// Create UDP socket for uTP
	udpConn, err := net.ListenPacket("udp", *listenAddr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}

	utpSock, err := utp.NewSocketFromPacketConn(udpConn)
	if err != nil {
		log.Fatalf("utp socket: %v", err)
	}
	defer utpSock.Close()

	if *enableDHT {
		disc, err := bttdht.NewFromConn(utpSock, []byte(*psk), listenPort)
		if err != nil {
			log.Fatalf("dht init: %v", err)
		}
		defer disc.Close()

		ctx := context.Background()
		if err := disc.Bootstrap(ctx); err != nil {
			log.Printf("dht bootstrap warning: %v", err)
		}

		// ImpliedPort=true when behind NAT — DHT peers record our external port
		disc.AnnounceRelayImplied(ctx, *enableUPnP)
		log.Printf("DHT relay announce started (impliedPort=%v)", *enableUPnP)

		if target == "" {
			log.Printf("discovering server via DHT...")
			peers, err := disc.FindPeers(ctx)
			if err != nil {
				log.Fatalf("dht server discovery: %v", err)
			}
			target = peers[0].Addr()
			log.Printf("DHT discovered server: %s", target)
		}
	}

	if target == "" {
		log.Fatalf("no server address: use -server or -dht")
	}

	log.Printf("BTT relay listening on %s, forwarding to %s", *listenAddr, target)

	for {
		conn, err := utpSock.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleRelay(utpSock, conn, target)
	}
}

func handleRelay(sock *utp.Socket, clientConn net.Conn, serverAddr string) {
	defer clientConn.Close()

	log.Printf("relay: new connection from %s", clientConn.RemoteAddr())

	// Dial server through the SAME socket — reuses NAT mapping
	serverConn, err := sock.Dial(serverAddr)
	if err != nil {
		log.Printf("relay: dial server %s: %v", serverAddr, err)
		return
	}
	defer serverConn.Close()

	log.Printf("relay: connected to server %s, bridging", serverAddr)

	// Bidirectional byte copy — MSE handshake passes through transparently
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(serverConn, clientConn)
		log.Printf("relay: client→server: %d bytes", n)
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, serverConn)
		log.Printf("relay: server→client: %d bytes", n)
	}()

	wg.Wait()
	log.Printf("relay: connection from %s closed", clientConn.RemoteAddr())
}
