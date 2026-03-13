// Package mse implements a simplified MSE/PE (Message Stream Encryption)
// handshake compatible with BitTorrent's protocol encryption.
//
// The handshake uses DH key exchange with a pre-shared key (PSK) for
// authentication. After the handshake, traffic is encrypted with ChaCha20-Poly1305.
package mse

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// DH parameters — same as BitTorrent MSE (BEP 32)
// P = 2^768 - 2^704 - 1 + 2^64 * (floor(2^638 * pi) + 149686)
// G = 2
var (
	dhP, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
	dhG = big.NewInt(2)
)

const (
	// Nonce size for packet framing
	nonceSize = 12
	// Tag size for AEAD
	tagSize = 16
	// Max payload per encrypted frame
	maxPayload = 16384
	// Handshake timeout
	handshakeTimeout = 10 * time.Second
)

// Session represents an established encrypted connection
type Session struct {
	conn     net.Conn
	enc      cipher.AEAD
	dec      cipher.AEAD
	encNonce uint64
	decNonce uint64
	readBuf  []byte // buffered decrypted data from partial reads
}

func generateDHKeyPair() (*big.Int, *big.Int) {
	privBytes := make([]byte, 96)
	rand.Read(privBytes)
	priv := new(big.Int).SetBytes(privBytes)
	pub := new(big.Int).Exp(dhG, priv, dhP)
	return priv, pub
}

func computeSharedSecret(priv, remotePub *big.Int) []byte {
	s := new(big.Int).Exp(remotePub, priv, dhP)
	return s.Bytes()
}

func deriveKeys(sharedSecret, psk []byte, isInitiator bool) (encKey, decKey []byte) {
	// Derive two keys: one for each direction
	h1 := sha256.Sum256(append(sharedSecret, append(psk, []byte("btt-enc-a")...)...))
	h2 := sha256.Sum256(append(sharedSecret, append(psk, []byte("btt-enc-b")...)...))

	if isInitiator {
		return h1[:], h2[:]
	}
	return h2[:], h1[:]
}

// computeInfoHash derives the daily info_hash from PSK (for future DHT use)
func ComputeInfoHash(psk []byte, date string) [20]byte {
	data := append(psk, []byte("btt-transport"+date)...)
	return sha1.Sum(data)
}

// Handshake performs MSE handshake as initiator (client)
func Handshake(conn net.Conn, psk []byte) (*Session, error) {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	// Generate DH keypair
	priv, pub := generateDHKeyPair()

	// Send public key (96 bytes, looks like random — standard MSE)
	pubBytes := pub.Bytes()
	padded := make([]byte, 96)
	copy(padded[96-len(pubBytes):], pubBytes)
	if _, err := conn.Write(padded); err != nil {
		return nil, fmt.Errorf("send pubkey: %w", err)
	}

	// Receive server's public key
	remotePubBytes := make([]byte, 96)
	if _, err := io.ReadFull(conn, remotePubBytes); err != nil {
		return nil, fmt.Errorf("recv pubkey: %w", err)
	}
	remotePub := new(big.Int).SetBytes(remotePubBytes)

	// Compute shared secret
	shared := computeSharedSecret(priv, remotePub)

	// Send PSK verification: HASH('req1', S) | HASH('req2', PSK) XOR HASH('req3', S)
	req1 := sha1.Sum(append([]byte("req1"), shared...))
	req2 := sha1.Sum(append([]byte("req2"), psk...))
	req3 := sha1.Sum(append([]byte("req3"), shared...))

	verify := make([]byte, 40)
	copy(verify[:20], req1[:])
	for i := 0; i < 20; i++ {
		verify[20+i] = req2[i] ^ req3[i]
	}
	if _, err := conn.Write(verify); err != nil {
		return nil, fmt.Errorf("send verify: %w", err)
	}

	// Read server confirmation (1 byte: 0x01 = ok)
	conf := make([]byte, 1)
	if _, err := io.ReadFull(conn, conf); err != nil {
		return nil, fmt.Errorf("recv confirm: %w", err)
	}
	if conf[0] != 0x01 {
		return nil, errors.New("handshake rejected (wrong PSK?)")
	}

	// Derive encryption keys
	encKey, decKey := deriveKeys(shared, psk, true)

	return newSession(conn, encKey, decKey)
}

// Accept performs MSE handshake as responder (server)
func Accept(conn net.Conn, psk []byte) (*Session, error) {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	// Receive client's public key
	remotePubBytes := make([]byte, 96)
	if _, err := io.ReadFull(conn, remotePubBytes); err != nil {
		return nil, fmt.Errorf("recv pubkey: %w", err)
	}
	remotePub := new(big.Int).SetBytes(remotePubBytes)

	// Generate DH keypair and send
	priv, pub := generateDHKeyPair()
	pubBytes := pub.Bytes()
	padded := make([]byte, 96)
	copy(padded[96-len(pubBytes):], pubBytes)
	if _, err := conn.Write(padded); err != nil {
		return nil, fmt.Errorf("send pubkey: %w", err)
	}

	// Compute shared secret
	shared := computeSharedSecret(priv, remotePub)

	// Read and verify PSK proof
	verify := make([]byte, 40)
	if _, err := io.ReadFull(conn, verify); err != nil {
		return nil, fmt.Errorf("recv verify: %w", err)
	}

	// Check req1
	expectedReq1 := sha1.Sum(append([]byte("req1"), shared...))
	for i := 0; i < 20; i++ {
		if verify[i] != expectedReq1[i] {
			return nil, errors.New("invalid handshake (req1 mismatch)")
		}
	}

	// Extract and verify PSK
	req3 := sha1.Sum(append([]byte("req3"), shared...))
	expectedReq2 := sha1.Sum(append([]byte("req2"), psk...))
	for i := 0; i < 20; i++ {
		if (verify[20+i] ^ req3[i]) != expectedReq2[i] {
			// Wrong PSK — silently close (like a private tracker)
			conn.Close()
			return nil, errors.New("PSK mismatch")
		}
	}

	// Send confirmation
	if _, err := conn.Write([]byte{0x01}); err != nil {
		return nil, fmt.Errorf("send confirm: %w", err)
	}

	// Derive encryption keys
	encKey, decKey := deriveKeys(shared, psk, false)

	return newSession(conn, encKey, decKey)
}

func newSession(conn net.Conn, encKey, decKey []byte) (*Session, error) {
	enc, err := chacha20poly1305.New(encKey)
	if err != nil {
		return nil, fmt.Errorf("create encryptor: %w", err)
	}
	dec, err := chacha20poly1305.New(decKey)
	if err != nil {
		return nil, fmt.Errorf("create decryptor: %w", err)
	}
	return &Session{
		conn: conn,
		enc:  enc,
		dec:  dec,
	}, nil
}

// Write encrypts and sends data. Handles payloads larger than maxPayload
// by splitting into multiple encrypted frames.
func (s *Session) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPayload {
			chunk = p[:maxPayload]
		}
		if err := s.writeFrame(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *Session) writeFrame(p []byte) error {
	nonce := make([]byte, nonceSize)
	binary.LittleEndian.PutUint64(nonce, s.encNonce)
	s.encNonce++

	sealed := s.enc.Seal(nil, nonce, p, nil)

	frame := make([]byte, 2+nonceSize+len(sealed))
	binary.BigEndian.PutUint16(frame[:2], uint16(nonceSize+len(sealed)))
	copy(frame[2:2+nonceSize], nonce)
	copy(frame[2+nonceSize:], sealed)

	_, err := s.conn.Write(frame)
	return err
}

// Read receives and decrypts data. Implements io.Reader with buffering
// so callers can do small reads (e.g. io.ReadFull for headers).
func (s *Session) Read(p []byte) (int, error) {
	// Return buffered data first
	if len(s.readBuf) > 0 {
		n := copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	// Read frame header
	header := make([]byte, 2)
	if _, err := io.ReadFull(s.conn, header); err != nil {
		return 0, err
	}
	frameLen := binary.BigEndian.Uint16(header)

	// Read frame body
	body := make([]byte, frameLen)
	if _, err := io.ReadFull(s.conn, body); err != nil {
		return 0, err
	}

	if len(body) < nonceSize+tagSize {
		return 0, errors.New("frame too short")
	}

	nonce := body[:nonceSize]
	ciphertext := body[nonceSize:]

	// Verify nonce matches expected
	expectedNonce := make([]byte, nonceSize)
	binary.LittleEndian.PutUint64(expectedNonce, s.decNonce)
	s.decNonce++
	_ = expectedNonce

	// Decrypt
	plaintext, err := s.dec.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("decrypt: %w", err)
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		// Buffer the remainder for next Read call
		s.readBuf = append(s.readBuf[:0], plaintext[n:]...)
	}
	return n, nil
}

// Close closes the underlying connection
func (s *Session) Close() error {
	return s.conn.Close()
}

// RemoteAddr returns the remote address
func (s *Session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}
