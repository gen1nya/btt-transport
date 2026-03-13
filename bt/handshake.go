// Package bt implements the BitTorrent peer wire protocol handshake.
//
// After MSE encryption is established, peers exchange BT handshakes:
//
//	[1 byte]  pstrlen = 19
//	[19 bytes] pstr = "BitTorrent protocol"
//	[8 bytes]  reserved (extension flags)
//	[20 bytes] info_hash
//	[20 bytes] peer_id
//
// Total: 68 bytes. This makes the encrypted stream look like
// a standard BT connection from the inside out.
package bt

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/evg/btt-transport/mse"
)

const (
	pstr       = "BitTorrent protocol"
	pstrLen    = 19
	handshakeLen = 1 + pstrLen + 8 + 20 + 20 // 68 bytes
)

// Handshake performs the BT protocol handshake over an encrypted session.
// Both sides must use the same PSK to derive the info_hash.
// Returns the remote peer_id.
func Handshake(rw io.ReadWriter, psk []byte, date string) ([20]byte, error) {
	infoHash := mse.ComputeInfoHash(psk, date)
	peerID := generatePeerID()

	// Send handshake
	msg := make([]byte, handshakeLen)
	msg[0] = pstrLen
	copy(msg[1:20], pstr)
	// reserved[5] = 0x10 — Extension Protocol (BEP 10), looks realistic
	msg[25] = 0x10
	copy(msg[28:48], infoHash[:])
	copy(msg[48:68], peerID[:])

	if _, err := rw.Write(msg); err != nil {
		return [20]byte{}, fmt.Errorf("bt handshake write: %w", err)
	}

	// Read remote handshake
	remote := make([]byte, handshakeLen)
	if _, err := io.ReadFull(rw, remote); err != nil {
		return [20]byte{}, fmt.Errorf("bt handshake read: %w", err)
	}

	// Verify protocol string
	if remote[0] != pstrLen {
		return [20]byte{}, fmt.Errorf("bt handshake: bad pstrlen %d", remote[0])
	}
	if string(remote[1:20]) != pstr {
		return [20]byte{}, fmt.Errorf("bt handshake: bad protocol string")
	}

	// Verify info_hash matches
	var remoteHash [20]byte
	copy(remoteHash[:], remote[28:48])
	if remoteHash != infoHash {
		return [20]byte{}, fmt.Errorf("bt handshake: info_hash mismatch")
	}

	var remotePeerID [20]byte
	copy(remotePeerID[:], remote[48:68])
	return remotePeerID, nil
}

// generatePeerID creates a realistic-looking BT peer ID.
// Format: "-qB4620-" + 12 random chars (mimics qBittorrent 4.6.2)
func generatePeerID() [20]byte {
	var id [20]byte
	copy(id[:8], "-qB4620-")
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var buf [12]byte
	rand.Read(buf[:])
	for i := range buf {
		id[8+i] = charset[buf[i]%byte(len(charset))]
	}
	return id
}
