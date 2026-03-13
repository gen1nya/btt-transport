// Package dht provides peer discovery via the real BitTorrent DHT network.
//
// Server announces itself under info_hash = SHA1(PSK + "btt-transport" + date).
// Client looks up the same info_hash to find the server's IP:port.
// info_hash rotates daily — yesterday's hash is also announced/queried for
// smooth transition around midnight.
package dht

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/anacrolix/dht/v2"
	"github.com/evg/btt-transport/mse"
)

// Discovery wraps a DHT node for announce/lookup operations.
type Discovery struct {
	server *dht.Server
	psk    []byte
	port   int

	mu     sync.Mutex
	cancel context.CancelFunc
}

// New creates a DHT node on the given UDP port (0 = random) with its own socket.
func New(listenPort int, psk []byte, announcePort int) (*Discovery, error) {
	addr := fmt.Sprintf(":%d", listenPort)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dht listen: %w", err)
	}

	return newFromConn(conn, psk, announcePort)
}

// NewFromConn creates a DHT node sharing an existing PacketConn (e.g. utp.Socket).
// The PacketConn must demux non-uTP packets to ReadFrom (utp.Socket does this).
func NewFromConn(conn net.PacketConn, psk []byte, announcePort int) (*Discovery, error) {
	return newFromConn(conn, psk, announcePort)
}

func newFromConn(conn net.PacketConn, psk []byte, announcePort int) (*Discovery, error) {
	cfg := dht.NewDefaultServerConfig()
	cfg.Conn = conn
	cfg.NoSecurity = true // we're behind NAT usually

	s, err := dht.NewServer(cfg)
	if err != nil {
		return nil, fmt.Errorf("dht server: %w", err)
	}

	log.Printf("DHT node %x on %s", s.ID(), s.Addr())

	return &Discovery{
		server: s,
		psk:    psk,
		port:   announcePort,
	}, nil
}

// infoHashes returns today's and yesterday's info_hash for smooth daily rotation.
func (d *Discovery) infoHashes() [][20]byte {
	return hashesForSalt(d.psk, "btt-transport")
}

// relayInfoHashes returns relay-specific info_hashes (different salt).
func (d *Discovery) relayInfoHashes() [][20]byte {
	return hashesForSalt(d.psk, "btt-relay")
}

func hashesForSalt(psk []byte, salt string) [][20]byte {
	now := time.Now().UTC()
	today := now.Format("2006-01-02")
	yesterday := now.Add(-24 * time.Hour).Format("2006-01-02")

	return [][20]byte{
		mse.ComputeInfoHash(psk, salt+today),
		mse.ComputeInfoHash(psk, salt+yesterday),
	}
}

// Bootstrap connects to well-known DHT nodes and populates the routing table.
func (d *Discovery) Bootstrap(ctx context.Context) error {
	stats, err := d.server.BootstrapContext(ctx)
	if err != nil {
		return err
	}
	log.Printf("DHT bootstrap: contacted %d nodes, %d responsive",
		stats.NumAddrsTried, stats.NumResponses)
	return nil
}

// Announce starts announcing this node as a peer for the PSK-derived info_hash.
// Re-announces every 14 minutes (DHT announcements expire after ~15-30 min).
// Call Stop() to cancel.
func (d *Discovery) Announce(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	d.mu.Lock()
	d.cancel = cancel
	d.mu.Unlock()

	go d.announceLoop(ctx)
}

func (d *Discovery) announceLoop(ctx context.Context) {
	ticker := time.NewTicker(14 * time.Minute)
	defer ticker.Stop()

	// Announce immediately, then every 14 minutes
	d.doAnnounce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.doAnnounce(ctx)
		}
	}
}

func (d *Discovery) doAnnounce(ctx context.Context) {
	d.doAnnounceHashes(d.infoHashes())
}

// Peer represents a discovered BTT server.
type Peer struct {
	IP   net.IP
	Port int
}

func (p Peer) Addr() string {
	return fmt.Sprintf("%s:%d", p.IP, p.Port)
}

// FindPeers searches the DHT for servers announced under the PSK-derived info_hash.
func (d *Discovery) FindPeers(ctx context.Context) ([]Peer, error) {
	return d.findByHashes(ctx, d.infoHashes())
}

// AnnounceRelay starts announcing this node as a relay (different info_hash than server).
func (d *Discovery) AnnounceRelay(ctx context.Context) {
	d.AnnounceRelayImplied(ctx, false)
}

// AnnounceRelayImplied starts announcing as relay. If impliedPort is true,
// DHT peers will record the external (post-NAT) port instead of the announced one.
func (d *Discovery) AnnounceRelayImplied(ctx context.Context, impliedPort bool) {
	ctx, cancel := context.WithCancel(ctx)
	d.mu.Lock()
	d.cancel = cancel
	d.mu.Unlock()

	go func() {
		ticker := time.NewTicker(14 * time.Minute)
		defer ticker.Stop()

		d.doAnnounceHashesImplied(d.relayInfoHashes(), impliedPort)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.doAnnounceHashesImplied(d.relayInfoHashes(), impliedPort)
			}
		}
	}()
}

func (d *Discovery) doAnnounceHashes(hashes [][20]byte) {
	d.doAnnounceHashesImplied(hashes, false)
}

func (d *Discovery) doAnnounceHashesImplied(hashes [][20]byte, impliedPort bool) {
	for _, ih := range hashes {
		a, err := d.server.AnnounceTraversal(ih,
			dht.AnnouncePeer(dht.AnnouncePeerOpts{
				Port:        d.port,
				ImpliedPort: impliedPort,
			}),
		)
		if err != nil {
			log.Printf("DHT announce error for %x: %v", ih[:4], err)
			continue
		}
		go func(a *dht.Announce, ih [20]byte) {
			for range a.Peers {
			}
			log.Printf("DHT announced %x..., contacted %d nodes",
				ih[:4], a.NumContacted())
			a.Close()
		}(a, ih)
	}
}

// FindRelays searches the DHT for relay nodes.
func (d *Discovery) FindRelays(ctx context.Context) ([]Peer, error) {
	return d.findByHashes(ctx, d.relayInfoHashes())
}

func (d *Discovery) findByHashes(ctx context.Context, hashes [][20]byte) ([]Peer, error) {
	seen := make(map[string]bool)
	var peers []Peer

	for _, ih := range hashes {
		log.Printf("DHT lookup %x...", ih[:4])

		a, err := d.server.AnnounceTraversal(ih)
		if err != nil {
			log.Printf("DHT lookup error: %v", err)
			continue
		}

		timeout := time.After(15 * time.Second)
	drain:
		for {
			select {
			case pv, ok := <-a.Peers:
				if !ok {
					break drain
				}
				for _, p := range pv.Peers {
					key := fmt.Sprintf("%s:%d", p.IP, p.Port)
					if !seen[key] {
						seen[key] = true
						peers = append(peers, Peer{IP: p.IP, Port: p.Port})
						log.Printf("DHT found peer: %s", key)
					}
				}
			case <-timeout:
				break drain
			case <-ctx.Done():
				a.Close()
				return peers, ctx.Err()
			}
		}
		a.Close()

		if len(peers) > 0 {
			break
		}
	}

	if len(peers) == 0 {
		return nil, fmt.Errorf("no peers found in DHT")
	}
	return peers, nil
}

// Stop cancels ongoing announcements.
func (d *Discovery) Stop() {
	d.mu.Lock()
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()
}

// Close shuts down the DHT node.
func (d *Discovery) Close() {
	d.Stop()
	d.server.Close()
}
