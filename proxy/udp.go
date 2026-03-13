// Package proxy handles UDP <-> stream proxying for WireGuard packets.
// Each UDP datagram is sent as a separate piece message, preserving boundaries.
package proxy

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// UDPToStream reads UDP datagrams and writes them to a stream writer.
// Each datagram is prefixed with 2-byte length to preserve boundaries.
func UDPToStream(udpConn *net.UDPConn, w io.Writer, clientAddr *net.UDPAddr, done chan struct{}) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-done:
			return
		default:
		}
		udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("udp read: %v", err)
			return
		}

		// Remember client address for return path
		if clientAddr != nil {
			*clientAddr = *addr
		}

		// Write length-prefixed datagram to stream
		frame := make([]byte, 2+n)
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], buf[:n])

		if _, err := w.Write(frame); err != nil {
			log.Printf("stream write: %v", err)
			return
		}
	}
}

// StreamToUDP reads length-prefixed datagrams from a stream and sends them as UDP.
func StreamToUDP(r io.Reader, udpConn *net.UDPConn, getAddr func() *net.UDPAddr, done chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
		}

		// Read 2-byte length prefix
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			if err != io.EOF {
				log.Printf("stream read len: %v", err)
			}
			return
		}
		pktLen := binary.BigEndian.Uint16(lenBuf)

		// Read the datagram
		pkt := make([]byte, pktLen)
		if _, err := io.ReadFull(r, pkt); err != nil {
			log.Printf("stream read pkt: %v", err)
			return
		}

		addr := getAddr()
		if addr == nil {
			continue
		}

		if _, err := udpConn.WriteToUDP(pkt, addr); err != nil {
			log.Printf("udp write: %v", err)
			return
		}
	}
}

// ClientProxy runs the client-side UDP proxy.
// WireGuard client connects to listenAddr (UDP), packets go through the stream tunnel.
func ClientProxy(listenAddr string, streamR io.Reader, streamW io.Writer) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	log.Printf("UDP proxy listening on %s (for WireGuard client)", listenAddr)

	var clientAddr net.UDPAddr
	var mu sync.Mutex
	done := make(chan struct{})

	// UDP → Stream (WG client → tunnel)
	go UDPToStream(udpConn, streamW, &clientAddr, done)

	// Stream → UDP (tunnel → WG client)
	StreamToUDP(streamR, udpConn, func() *net.UDPAddr {
		mu.Lock()
		defer mu.Unlock()
		if clientAddr.Port == 0 {
			return nil
		}
		a := clientAddr
		return &a
	}, done)

	close(done)
	return nil
}

// ServerProxy runs the server-side UDP proxy.
// Forwards decrypted packets to a WireGuard server via UDP.
func ServerProxy(targetAddr string, streamR io.Reader, streamW io.Writer) error {
	remoteAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return err
	}

	// Connect to WG server
	udpConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	log.Printf("UDP proxy forwarding to %s (WireGuard server)", targetAddr)

	done := make(chan struct{})

	// Stream → UDP (tunnel → WG server)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}

			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(streamR, lenBuf); err != nil {
				if err != io.EOF {
					log.Printf("stream read: %v", err)
				}
				return
			}
			pktLen := binary.BigEndian.Uint16(lenBuf)

			pkt := make([]byte, pktLen)
			if _, err := io.ReadFull(streamR, pkt); err != nil {
				log.Printf("stream read pkt: %v", err)
				return
			}

			if _, err := udpConn.Write(pkt); err != nil {
				log.Printf("udp write: %v", err)
				return
			}
		}
	}()

	// UDP → Stream (WG server → tunnel)
	buf := make([]byte, 65535)
	for {
		select {
		case <-done:
			return nil
		default:
		}
		udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := udpConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("udp read: %v", err)
			close(done)
			return err
		}

		frame := make([]byte, 2+n)
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], buf[:n])

		if _, err := streamW.Write(frame); err != nil {
			log.Printf("stream write: %v", err)
			close(done)
			return err
		}
	}
}
