package piece

import (
	"bytes"
	"testing"
	"time"
)

func TestPaddedWriterBuffering(t *testing.T) {
	var buf bytes.Buffer
	pw := NewPaddedWriter(&buf)

	// Write a small packet — should NOT flush immediately
	pw.Write([]byte("hello"))
	if buf.Len() != 0 {
		t.Fatalf("expected no output yet, got %d bytes", buf.Len())
	}

	// Wait for timer flush
	time.Sleep(5 * time.Millisecond)
	if buf.Len() == 0 {
		t.Fatal("expected output after timer, got nothing")
	}

	// Should be exactly one 16KB padded block: 4 (len) + 1 (type) + 4 (idx) + 4 (off) + 16384 (block)
	expected := 4 + 1 + 4 + 4 + BlockSize
	if buf.Len() != expected {
		t.Fatalf("expected %d bytes, got %d", expected, buf.Len())
	}
}

func TestPaddedWriterAggregation(t *testing.T) {
	var buf bytes.Buffer
	pw := NewPaddedWriter(&buf)

	// Write two small packets rapidly — should aggregate into one block
	pw.Write([]byte("aaa"))
	pw.Write([]byte("bbb"))

	if buf.Len() != 0 {
		t.Fatalf("expected no output yet, got %d bytes", buf.Len())
	}

	time.Sleep(5 * time.Millisecond)

	expected := 4 + 1 + 4 + 4 + BlockSize
	if buf.Len() != expected {
		t.Fatalf("expected one block (%d bytes), got %d", expected, buf.Len())
	}

	// Verify aggregated payload
	pr := NewPaddedReader(&buf)
	out := make([]byte, 1024)
	n, err := pr.Read(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out[:n]) != "aaabbb" {
		t.Fatalf("expected 'aaabbb', got %q", out[:n])
	}
}

func TestPaddedWriterFullBlock(t *testing.T) {
	var buf bytes.Buffer
	pw := NewPaddedWriter(&buf)

	// Write exactly maxPayloadPerBlock — should flush immediately
	payload := make([]byte, maxPayloadPerBlock)
	for i := range payload {
		payload[i] = byte(i)
	}
	pw.Write(payload)

	expected := 4 + 1 + 4 + 4 + BlockSize
	if buf.Len() != expected {
		t.Fatalf("expected immediate flush (%d bytes), got %d", expected, buf.Len())
	}
}

func TestPaddedWriterFlush(t *testing.T) {
	var buf bytes.Buffer
	pw := NewPaddedWriter(&buf)

	pw.Write([]byte("flush me"))
	if buf.Len() != 0 {
		t.Fatalf("expected no output yet, got %d bytes", buf.Len())
	}

	pw.Flush()

	expected := 4 + 1 + 4 + 4 + BlockSize
	if buf.Len() != expected {
		t.Fatalf("expected flushed block (%d bytes), got %d", expected, buf.Len())
	}
}

func TestPaddedWriterLargePayload(t *testing.T) {
	var buf bytes.Buffer
	pw := NewPaddedWriter(&buf)

	// Write more than one block — should produce 2 blocks immediately
	payload := make([]byte, maxPayloadPerBlock+100)
	for i := range payload {
		payload[i] = byte(i)
	}
	pw.Write(payload)

	// First block flushed immediately (full), second pending
	oneBlock := 4 + 1 + 4 + 4 + BlockSize
	if buf.Len() != oneBlock {
		t.Fatalf("expected one immediate block (%d), got %d", oneBlock, buf.Len())
	}

	// Timer flushes the remaining 100 bytes
	time.Sleep(5 * time.Millisecond)
	if buf.Len() != 2*oneBlock {
		t.Fatalf("expected two blocks (%d), got %d", 2*oneBlock, buf.Len())
	}
}

func TestNonPaddedWriter(t *testing.T) {
	var buf bytes.Buffer
	pw := NewWriter(&buf)

	// Non-padded writes should be immediate (no buffering)
	pw.Write([]byte("hello"))
	if buf.Len() == 0 {
		t.Fatal("expected immediate output for non-padded writer")
	}
}
