// Package piece implements BitTorrent piece message framing.
// VPN payload is wrapped to look like BT piece data (message type 0x07).
//
// Wire format (standard BT peer wire protocol):
//
//	[4 bytes] length prefix (big-endian, includes everything after)
//	[1 byte]  message type (0x07 = piece)
//	[4 bytes] piece index
//	[4 bytes] block offset
//	[N bytes] block data (always BlockSize except last block in piece)
//
// Inside the block data, real payload is length-prefixed:
//
//	[2 bytes] payload length
//	[N bytes] payload (VPN data)
//	[padding] random bytes to fill BlockSize
//
// Standard BT block size is 16KB (16384 bytes).
package piece

import (
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MsgPiece     = 0x07
	MsgRequest   = 0x06
	MsgKeepAlive = 0xFF // internal: keepalive (4 zero bytes on wire)

	BlockSize   = 16384 // standard BT block size
	HeaderSize  = 13    // 4 (length) + 1 (type) + 4 (index) + 4 (offset)
	PieceBlocks = 16    // blocks per piece (256KB pieces, typical)

	// payloadPrefix is the 2-byte length prefix inside the block data
	payloadPrefix = 2
	// maxPayloadPerBlock is the max payload that fits in one block
	maxPayloadPerBlock = BlockSize - payloadPrefix
	// flushDelay is the max time to buffer before sending a padded block
	flushDelay = time.Millisecond
)

// Writer wraps data in BT piece message framing with optional padding to BlockSize.
// In padded mode, small writes are buffered up to 1ms before flushing as a full
// 16KB block. This aggregates multiple small packets (e.g. WG keepalives) into
// one block, reducing overhead from ~128x to ~10x on typical traffic.
type Writer struct {
	w        io.Writer
	pieceIdx atomic.Uint32
	blockOff uint32
	padded   bool

	mu       sync.Mutex
	buf      []byte
	timer    *time.Timer
	writeErr error

	lastWrite atomic.Int64 // unix nano of last write
	kaStop    chan struct{} // stop keepalive goroutine
}

// NewWriter creates a piece framer (no padding, backward compat)
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// NewPaddedWriter creates a piece framer that pads blocks to 16KB
func NewPaddedWriter(w io.Writer) *Writer {
	return &Writer{w: w, padded: true}
}

// Write wraps payload in a BT piece message.
// In padded mode: buffers data and sends 16KB blocks after 1ms delay.
// In non-padded mode: sends immediately (backward compat).
func (pw *Writer) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	pw.lastWrite.Store(time.Now().UnixNano())

	if !pw.padded {
		return pw.writeImmediate(payload)
	}

	return pw.writeBuffered(payload)
}

// writeImmediate sends without padding (original behavior)
func (pw *Writer) writeImmediate(payload []byte) (int, error) {
	msgLen := 1 + 4 + 4 + len(payload)
	frame := make([]byte, 4+msgLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(msgLen))
	frame[4] = MsgPiece
	binary.BigEndian.PutUint32(frame[5:9], pw.pieceIdx.Load())
	binary.BigEndian.PutUint32(frame[9:13], pw.blockOff)
	copy(frame[13:], payload)

	pw.blockOff += uint32(len(payload))
	if pw.blockOff >= BlockSize*PieceBlocks {
		pw.blockOff = 0
		pw.pieceIdx.Add(1)
	}

	_, err := pw.w.Write(frame)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

// writeBuffered accumulates data into a buffer and flushes as 16KB padded blocks.
// Full blocks are flushed immediately; partial blocks are flushed after flushDelay.
func (pw *Writer) writeBuffered(payload []byte) (int, error) {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	// Propagate error from timer-triggered flush
	if pw.writeErr != nil {
		err := pw.writeErr
		pw.writeErr = nil
		return 0, err
	}

	total := 0
	for len(payload) > 0 {
		space := maxPayloadPerBlock - len(pw.buf)
		if space <= 0 {
			if err := pw.flushLocked(); err != nil {
				return total, err
			}
			space = maxPayloadPerBlock
		}

		n := len(payload)
		if n > space {
			n = space
		}
		pw.buf = append(pw.buf, payload[:n]...)
		payload = payload[n:]
		total += n

		// Full block — flush immediately
		if len(pw.buf) >= maxPayloadPerBlock {
			if err := pw.flushLocked(); err != nil {
				return total, err
			}
		}
	}

	// Partial block — start timer
	if len(pw.buf) > 0 && pw.timer == nil {
		pw.timer = time.AfterFunc(flushDelay, pw.timerFlush)
	}

	return total, nil
}

// timerFlush is called by the timer goroutine to flush partial blocks.
func (pw *Writer) timerFlush() {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	pw.timer = nil
	if len(pw.buf) > 0 {
		if err := pw.flushLocked(); err != nil {
			pw.writeErr = err
		}
	}
}

// flushLocked sends any buffered data as a padded block. Must be called with mu held.
func (pw *Writer) flushLocked() error {
	if len(pw.buf) == 0 {
		return nil
	}
	data := make([]byte, len(pw.buf))
	copy(data, pw.buf)
	pw.buf = pw.buf[:0]
	if pw.timer != nil {
		pw.timer.Stop()
		pw.timer = nil
	}
	return pw.flushBlock(data)
}

// Flush sends any buffered data immediately.
func (pw *Writer) Flush() error {
	if !pw.padded {
		return nil
	}
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return pw.flushLocked()
}

// StartKeepalive sends BT keepalive messages (4 zero bytes) when no data
// has been written for the given interval. This prevents the uTP connection
// from timing out during idle periods.
func (pw *Writer) StartKeepalive(interval time.Duration) {
	pw.kaStop = make(chan struct{})
	pw.lastWrite.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-pw.kaStop:
				return
			case <-ticker.C:
				idle := time.Since(time.Unix(0, pw.lastWrite.Load()))
				if idle >= interval {
					// BT keepalive: 4 zero bytes (message length = 0)
					pw.mu.Lock()
					_, err := pw.w.Write([]byte{0, 0, 0, 0})
					pw.mu.Unlock()
					if err != nil {
						return
					}
				}
			}
		}
	}()
}

// StopKeepalive stops the keepalive goroutine.
func (pw *Writer) StopKeepalive() {
	if pw.kaStop != nil {
		close(pw.kaStop)
	}
}

// flushBlock sends one piece message with payload padded to BlockSize
func (pw *Writer) flushBlock(payload []byte) error {
	// Block data: [2 byte payload len] [payload] [random padding]
	blockData := make([]byte, BlockSize)
	binary.BigEndian.PutUint16(blockData[0:2], uint16(len(payload)))
	copy(blockData[2:], payload)
	// Fill rest with fast PRNG padding (not crypto — padding is discarded by reader)
	for i := 2 + len(payload); i+8 <= BlockSize; i += 8 {
		binary.LittleEndian.PutUint64(blockData[i:], rand.Uint64())
	}

	// BT piece message header
	msgLen := 1 + 4 + 4 + BlockSize
	frame := make([]byte, 4+msgLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(msgLen))
	frame[4] = MsgPiece
	binary.BigEndian.PutUint32(frame[5:9], pw.pieceIdx.Load())
	binary.BigEndian.PutUint32(frame[9:13], pw.blockOff)
	copy(frame[13:], blockData)

	// Advance position
	pw.blockOff += BlockSize
	if pw.blockOff >= BlockSize*PieceBlocks {
		pw.blockOff = 0
		pw.pieceIdx.Add(1)
	}

	_, err := pw.w.Write(frame)
	return err
}

// Reader strips BT piece framing and returns the payload.
// Supports both padded (2-byte length prefix inside block) and non-padded modes.
type Reader struct {
	r       io.Reader
	readBuf []byte
	padded  bool
}

// NewReader creates a piece deframer (non-padded, backward compat)
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r}
}

// NewPaddedReader creates a piece deframer that expects 16KB padded blocks
func NewPaddedReader(r io.Reader) *Reader {
	return &Reader{r: r, padded: true}
}

// Read reads one piece message and returns the payload.
func (pr *Reader) Read(buf []byte) (int, error) {
	// Return buffered data first
	if len(pr.readBuf) > 0 {
		n := copy(buf, pr.readBuf)
		pr.readBuf = pr.readBuf[n:]
		return n, nil
	}

	// Read length prefix
	header := make([]byte, 4)
	if _, err := io.ReadFull(pr.r, header); err != nil {
		return 0, err
	}
	msgLen := binary.BigEndian.Uint32(header)

	// Keep-alive: length == 0
	if msgLen == 0 {
		return 0, nil
	}

	if msgLen > BlockSize+9+1024 {
		return 0, errors.New("piece message too large")
	}

	// Read message body
	body := make([]byte, msgLen)
	if _, err := io.ReadFull(pr.r, body); err != nil {
		return 0, err
	}

	if body[0] != MsgPiece {
		return 0, errors.New("unexpected message type")
	}

	// Skip type (1) + index (4) + offset (4) = 9 bytes
	if len(body) <= 9 {
		return 0, nil
	}

	blockData := body[9:]

	var payload []byte
	if pr.padded {
		// Padded mode: first 2 bytes = payload length, rest is padding
		if len(blockData) < payloadPrefix {
			return 0, nil
		}
		pLen := binary.BigEndian.Uint16(blockData[:2])
		if int(pLen) > len(blockData)-payloadPrefix {
			return 0, errors.New("invalid payload length in padded block")
		}
		payload = blockData[2 : 2+pLen]
	} else {
		// Non-padded mode: entire block data is payload
		payload = blockData
	}

	n := copy(buf, payload)
	if n < len(payload) {
		pr.readBuf = append(pr.readBuf[:0], payload[n:]...)
	}
	return n, nil
}
